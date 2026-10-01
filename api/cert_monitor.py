"""TLS certificate expiry monitoring (per org).

Orgs register hostnames; the beat worker calls :func:`run_cert_checks_once`
(which also runs inside the 60s ``check_schedules`` beat) and each enabled
domain is actually probed at most once per :data:`CHECK_INTERVAL_S`.

When a certificate expires within the domain's ``warn_days``, an alert fans
out to every channel the org configured (the domain's own webhook URL plus
the org's telegram chats, slack/teams webhooks and email recipients) and is
recorded in the notifications log as ``event='cert.expiry'``.

Anti-spam: the first 'expiring' alert fires immediately; while the domain
stays expiring we re-alert at most every :data:`REPEAT_ALERT_S`, and we
alert again at once when the state flips (ok -> expiring).

Outbound-connection safety: the resolved IP must be public — private,
loopback, link-local, reserved and multicast addresses are refused, so a
domain row cannot be used to probe the worker's internal network.
"""

import ipaddress
import logging
import re
import socket
import ssl
import time
from datetime import datetime, timezone

log = logging.getLogger("braimsec.certs")

CHECK_INTERVAL_S = 20 * 3600      # probe each domain at most ~daily
REPEAT_ALERT_S = 7 * 86400        # re-alert while still expiring, weekly
DEFAULT_WARN_DAYS = 14
CONNECT_TIMEOUT_S = 12

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}$")


# ---------------------------------------------------------------------------
# Validation / probing
# ---------------------------------------------------------------------------

def validate_hostname(hostname: str) -> str:
    """Normalize + validate a hostname. Raises ValueError."""
    host = (hostname or "").strip().lower()
    if host.startswith(("http://", "https://")):
        raise ValueError("hostname must not include a scheme")
    host = host.split("/")[0].split(":")[0].rstrip(".")
    if not _HOST_RE.match(host):
        raise ValueError(f"invalid hostname: {hostname!r}")
    return host


def _public_ip_or_raise(host: str) -> str:
    """Resolve ``host`` and return the IP; refuse non-public addresses."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {host!r}: {e}")
    if not infos:
        raise ValueError(f"no address found for {host!r}")
    ip_str = infos[0][4][0]
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        raise ValueError(f"unparseable address for {host!r}: {ip_str}")
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
        raise ValueError(f"refusing non-public address {ip} for {host!r}")
    return ip_str


def get_cert_expiry(host: str, port: int = 443,
                    timeout: float = CONNECT_TIMEOUT_S
                    ) -> tuple[datetime | None, str | None, str | None]:
    """Fetch the peer cert; return (expires_at_utc, issuer, error).

    ``issuer`` is best-effort (may be None). Never raises.
    """
    try:
        _public_ip_or_raise(host)
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        if not cert or "notAfter" not in cert:
            return None, None, "peer presented no certificate"
        expires = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc)
        issuer = None
        try:
            issuer = "".join(
                f"/{k}={v}" for part in cert.get("issuer", ())
                for k, v in part)
        except Exception:  # noqa: BLE001 - issuer is decorative
            issuer = None
        return expires, issuer, None
    except ValueError as e:
        return None, None, str(e)
    except Exception as e:  # noqa: BLE001 - probe must never raise
        return None, None, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def list_domains(db, org_id: str) -> list[dict]:
    return [dict(r) for r in db.execute(
        "SELECT id, org_id, hostname, port, warn_days, webhook_url, enabled,"
        " last_checked_at, last_expires_at, last_days_left, last_status,"
        " last_error, last_alerted_at, created_at"
        " FROM cert_domains WHERE org_id=? ORDER BY hostname, port",
        (org_id,)).fetchall()]


def add_domain(db, org_id: str, hostname: str, port: int = 443,
               warn_days: int = DEFAULT_WARN_DAYS,
               webhook_url: str = "") -> dict:
    host = validate_hostname(hostname)
    if not (1 <= port <= 65535):
        raise ValueError("port must be 1..65535")
    if not (1 <= warn_days <= 90):
        raise ValueError("warn_days must be 1..90")
    exists = db.execute(
        "SELECT id FROM cert_domains WHERE org_id=? AND hostname=? AND port=?",
        (org_id, host, port)).fetchone()
    if exists:
        raise ValueError("domain already monitored")
    cur = db.execute(
        "INSERT INTO cert_domains (org_id, hostname, port, warn_days,"
        " webhook_url, enabled, last_status, created_at)"
        " VALUES (?,?,?,?,?,1,'never',?)",
        (org_id, host, port, warn_days, webhook_url or "", _now_iso()))
    db.commit()
    row = db.execute("SELECT * FROM cert_domains WHERE id=?",
                     (cur.lastrowid,)).fetchone()
    return dict(row)


# ---------------------------------------------------------------------------
# Checking + alerting
# ---------------------------------------------------------------------------

def _severity_for(days_left: int) -> str:
    if days_left <= 3:
        return "critical"
    if days_left <= 7:
        return "high"
    return "warning"


def check_domain(db, domain: dict) -> dict:
    """Probe one domain, persist the outcome, maybe alert. Never raises."""
    try:
        expires, issuer, err = get_cert_expiry(domain["hostname"],
                                              domain["port"])
        now = _now_iso()
        if err:
            db.execute("UPDATE cert_domains SET last_checked_at=?,"
                       " last_status='error', last_error=? WHERE id=?",
                       (now, err[:500], domain["id"]))
            db.commit()
            return {"status": "error", "error": err}
        days_left = (expires - datetime.now(timezone.utc)).days
        status = "expiring" if days_left <= domain["warn_days"] else "ok"
        db.execute("UPDATE cert_domains SET last_checked_at=?,"
                   " last_expires_at=?, last_days_left=?, last_status='"
                   + status + "', last_error=NULL WHERE id=?",
                   (now, expires.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                    days_left, domain["id"]))
        db.commit()
        # NOTE: `domain` still carries the pre-check last_alerted_at, which
        # is exactly what the anti-spam check needs.
        if status == "expiring" and _alert_due(domain):
            _fan_out(db, domain, days_left, expires)
            db.execute("UPDATE cert_domains SET last_alerted_at=? WHERE id=?",
                       (now, domain["id"]))
            db.commit()
            from audit import log_event  # noqa: E402
            log_event(domain["org_id"], "system", "cert_domain.alerted",
                      detail={"domain_id": domain["id"],
                              "hostname": domain["hostname"],
                              "port": domain["port"],
                              "days_left": days_left},
                      db=db)
            db.commit()
        return {"status": status, "days_left": days_left,
                "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "issuer": issuer}
    except Exception as e:  # noqa: BLE001 - a probe must never kill the beat
        log.exception("cert check crashed for %s", domain.get("hostname"))
        return {"status": "error", "error": str(e)}


def _alert_due(domain: dict) -> bool:
    """Anti-spam: first 'expiring' alert fires at once; while the domain
    stays expiring we re-alert at most every REPEAT_ALERT_S."""
    if not domain.get("last_alerted_at"):
        return True
    try:
        last = datetime.fromisoformat(domain["last_alerted_at"])
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - last).total_seconds() \
        >= REPEAT_ALERT_S


def _texts(payload: dict) -> dict:
    """Human texts for a cert.expiry payload (also used by resend)."""
    hostport = f"{payload['hostname']}:{payload['port']}"
    days_left = payload["days_left"]
    exp = str(payload["expires_at"])[:10]
    return {
        "telegram": (f"🔒 BraimSec: شهادة TLS على وشك الانتهاء\n"
                     f"«{hostport}»\nتنتهي في {exp} — بقي {days_left} يوم ⏳"),
        "slack": (f":lock: *BraimSec: شهادة TLS على وشك الانتهاء*\n"
                  f"`{hostport}`\nتنتهي في {exp} — بقي {days_left} يوم"),
        "email_subject": (f"🔒 BraimSec: شهادة {payload['hostname']} تنتهي "
                          f"خلال {days_left} يوم"),
        "email_text": (f"BraimSec: شهادة TLS على وشك الانتهاء\n\n"
                       f"النطاق: {hostport}\nتنتهي في: {exp}\n"
                       f"المتبقي: {days_left} يوم\n\nجدد الشهادة قبل انتهائها."),
        "email_html": (f'<html dir="rtl" lang="ar"><body>'
                       f'<h2>🔒 شهادة TLS على وشك الانتهاء</h2>'
                       f'<p>النطاق: <b>{hostport}</b></p>'
                       f'<p>تنتهي في: <b>{exp}</b> (بقي {days_left} يوم)</p>'
                       f'</body></html>'),
        "teams_title": "🔒 BraimSec: شهادة TLS على وشك الانتهاء",
        "teams_facts": [("النطاق", hostport),
                        ("تنتهي في", exp),
                        ("المتبقي", f"{days_left} يوم")],
    }


from alert_fanout import register_text_builder as _register  # noqa: E402
_register("cert.expiry", _texts)


def _fan_out(db, domain: dict, days_left: int, expires: datetime):
    """Build the webhook payload and hand off to the shared fan-out."""
    from alert_fanout import fan_out  # noqa: E402
    payload = {"event": "cert.expiry", "hostname": domain["hostname"],
               "port": domain["port"], "days_left": days_left,
               "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%S+00:00")}
    fan_out(db, domain["org_id"], event="cert.expiry",
            scan_id=f"cert:{domain['id']}",
            severity=_severity_for(days_left), count=days_left,
            webhook_url=domain.get("webhook_url") or "", payload=payload)


def run_cert_checks_once(db=None) -> dict:
    """Probe every due domain. Best-effort: never raises."""
    from database import get_db  # noqa: E402
    own = db is None
    if own:
        db = get_db()
    try:
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%S+00:00",
                               time.gmtime(time.time() - CHECK_INTERVAL_S))
        rows = db.execute(
            "SELECT * FROM cert_domains WHERE enabled=1 AND"
            " (last_checked_at IS NULL OR last_checked_at < ?)",
            (cutoff,)).fetchall()
        out = {"checked": 0, "expiring": 0, "errors": 0}
        for r in rows:
            res = check_domain(db, dict(r))
            out["checked"] += 1
            if res.get("status") == "expiring":
                out["expiring"] += 1
            elif res.get("status") == "error":
                out["errors"] += 1
        return out
    except Exception:  # noqa: BLE001 - beat must survive
        log.exception("cert check sweep crashed")
        return {"checked": 0, "expiring": 0, "errors": 0}
    finally:
        if own:
            db.close()
