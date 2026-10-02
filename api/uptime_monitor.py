"""HTTP(S) uptime monitoring (per org).

Orgs register URL targets; the beat worker calls
:func:`run_uptime_checks_once` (inside the 60s ``check_schedules`` beat) and
each enabled target is actually probed at most every ``check_interval_s``
(default 300s).

A target is *down* when the probe errors, the HTTP status is >= 500, the
status differs from ``expected_status`` (when set), or ``keyword`` (when
set) is missing from the body. To avoid flapping, the ``uptime.down`` alert
fires only after :data:`FAILURES_BEFORE_ALERT` consecutive failures, and a
``uptime.recovered`` alert fires on the first success after a down alert.
While a target stays down we re-alert at most every :data:`REPEAT_ALERT_S`.

Both alerts fan out through the shared :mod:`alert_fanout` path (the five
channels) and are logged as ``event='uptime.down'`` / ``'uptime.recovered'``.

Outbound-connection safety: the resolved IP must be public — the same guard
as TLS monitoring, so a target row cannot probe the worker's internal
network. (A small DNS-TOCTOU window between the check and the HTTP dial is
accepted and documented.)
"""

import http.client
import logging
import time
from datetime import datetime, timezone

import cert_monitor
import status_page
import maintenance

log = logging.getLogger("braimsec.uptime")

PROBE_TIMEOUT_S = 10
FAILURES_BEFORE_ALERT = 2
REPEAT_ALERT_S = 6 * 3600
DEFAULT_INTERVAL_S = 300
MAX_BODY_BYTES = 256 * 1024


# ---------------------------------------------------------------------------
# Validation / probing
# ---------------------------------------------------------------------------

def _norm_path(path: str) -> str:
    p = (path or "/").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    return p[:500]


def validate_target(hostname: str, port: int, path: str,
                    check_interval_s: int, expected_status: int | None,
                    keyword: str) -> tuple[str, int, str, int]:
    host = cert_monitor.validate_hostname(hostname)
    if not (1 <= port <= 65535):
        raise ValueError("port must be 1..65535")
    if not (60 <= check_interval_s <= 3600):
        raise ValueError("check_interval_s must be 60..3600")
    if expected_status is not None and not (100 <= expected_status <= 599):
        raise ValueError("expected_status must be 100..599")
    if keyword and len(keyword) > 200:
        raise ValueError("keyword too long (max 200)")
    return host, port, _norm_path(path), check_interval_s


def probe(target: dict) -> dict:
    """HTTP GET the target. Returns a dict, never raises.

    Keys: ok(bool), http_status(int|None), latency_ms(int|None),
    error(str|None), keyword_ok(bool|None).
    """
    host, port = target["hostname"], target["port"]
    t0 = time.monotonic()
    try:
        cert_monitor._public_ip_or_raise(host)
        cls = (http.client.HTTPSConnection if target["use_https"]
               else http.client.HTTPConnection)
        conn = cls(host, port, timeout=PROBE_TIMEOUT_S)
        try:
            conn.request("GET", target["path"],
                         headers={"User-Agent": "BraimSec-Uptime/1.0",
                                  "Accept": "*/*"})
            resp = conn.getresponse()
            body = resp.read(MAX_BODY_BYTES)
        finally:
            conn.close()
        latency_ms = int((time.monotonic() - t0) * 1000)
        status = resp.status
        kw = target.get("keyword") or ""
        keyword_ok = (not kw) or (kw.lower() in
                                  body.decode("utf-8", "replace").lower())
        err = None
        if status >= 500:
            err = f"HTTP {status}"
        elif target.get("expected_status") and \
                status != target["expected_status"]:
            err = f"HTTP {status} (expected {target['expected_status']})"
        elif not keyword_ok:
            err = "keyword not found in response body"
        return {"ok": err is None, "http_status": status,
                "latency_ms": latency_ms, "error": err,
                "keyword_ok": keyword_ok}
    except ValueError as e:
        # DNS failure / non-public IP refusal: config error, not "down".
        return {"ok": False, "http_status": None, "latency_ms": None,
                "error": str(e), "keyword_ok": None, "config_error": True}
    except Exception as e:  # noqa: BLE001 - probe must never raise
        return {"ok": False, "http_status": None,
                "latency_ms": int((time.monotonic() - t0) * 1000),
                "error": f"{type(e).__name__}: {e}", "keyword_ok": None}


# ---------------------------------------------------------------------------
# Texts (payload-based so resend rebuilds faithful messages)
# ---------------------------------------------------------------------------

def _texts_down(payload: dict) -> dict:
    url = _url_of(payload)
    reason = payload.get("error") or f"HTTP {payload.get('http_status')}"
    return {
        "telegram": (f"🔴 BraimSec: الموقع متوقف\n«{url}»\n"
                     f"السبب: {reason}\nفشل متتالٍ: {payload['failures']} ⚠️"),
        "slack": (f":red_circle: *BraimSec: الموقع متوقف*\n`{url}`\n"
                  f"السبب: {reason}"),
        "email_subject": f"🔴 BraimSec: توقف {payload['hostname']}",
        "email_text": (f"BraimSec: الموقع متوقف\n\nالرابط: {url}\n"
                       f"السبب: {reason}\n"
                       f"مرات الفشل المتتالية: {payload['failures']}\n"),
        "email_html": (f'<html dir="rtl" lang="ar"><body>'
                       f'<h2>🔴 الموقع متوقف</h2>'
                       f'<p>الرابط: <b>{url}</b></p>'
                       f'<p>السبب: <b>{reason}</b></p></body></html>'),
        "teams_title": "🔴 BraimSec: الموقع متوقف",
        "teams_facts": [("الرابط", url), ("السبب", reason),
                        ("فشل متتالٍ", str(payload["failures"]))],
    }


def _texts_recovered(payload: dict) -> dict:
    url = _url_of(payload)
    return {
        "telegram": f"🟢 BraimSec: عاد الموقع للعمل\n«{url}» ✅",
        "slack": f":large_green_circle: *BraimSec: عاد الموقع للعمل*\n`{url}`",
        "email_subject": f"🟢 BraimSec: عودة {payload['hostname']} للعمل",
        "email_text": f"BraimSec: عاد الموقع للعمل\n\nالرابط: {url}\n",
        "email_html": (f'<html dir="rtl" lang="ar"><body>'
                       f'<h2>🟢 عاد الموقع للعمل</h2>'
                       f'<p>الرابط: <b>{url}</b></p></body></html>'),
        "teams_title": "🟢 BraimSec: عاد الموقع للعمل",
        "teams_facts": [("الرابط", url)],
    }


def _url_of(payload: dict) -> str:
    scheme = "https" if payload.get("use_https", True) else "http"
    default = 443 if scheme == "https" else 80
    host = payload["hostname"]
    port = f":{payload['port']}" if payload["port"] != default else ""
    return f"{scheme}://{host}{port}{payload.get('path', '/')}"


from alert_fanout import register_text_builder as _register  # noqa: E402
_register("uptime.down", _texts_down)
_register("uptime.recovered", _texts_recovered)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def list_targets(db, org_id: str) -> list[dict]:
    return [dict(r) for r in db.execute(
        "SELECT * FROM uptime_targets WHERE org_id=? ORDER BY hostname, path",
        (org_id,)).fetchall()]


def add_target(db, org_id: str, hostname: str, port: int = 443,
               path: str = "/", use_https: bool = True,
               expected_status: int | None = None, keyword: str = "",
               check_interval_s: int = DEFAULT_INTERVAL_S,
               webhook_url: str = "") -> dict:
    host, port, path, interval = validate_target(
        hostname, port, path, check_interval_s, expected_status,
        keyword or "")
    exists = db.execute(
        "SELECT id FROM uptime_targets WHERE org_id=? AND hostname=?"
        " AND port=? AND path=?",
        (org_id, host, port, path)).fetchone()
    if exists:
        raise ValueError("target already monitored")
    cur = db.execute(
        "INSERT INTO uptime_targets (org_id, hostname, port, path, use_https,"
        " expected_status, keyword, check_interval_s, webhook_url, enabled,"
        " last_status, consecutive_failures, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?, 'never', 0, ?)",
        (org_id, host, port, path, 1 if use_https else 0, expected_status,
         keyword or "", interval, webhook_url or "", 1, _now_iso()))
    db.commit()
    return dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                           (cur.lastrowid,)).fetchone())


# ---------------------------------------------------------------------------
# Checking + alerting
# ---------------------------------------------------------------------------

def _down_alert_due(target: dict) -> bool:
    if target.get("last_alert_event") != "uptime.down":
        return True
    if not target.get("last_alerted_at"):
        return True
    try:
        last = datetime.fromisoformat(target["last_alerted_at"])
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - last).total_seconds() \
        >= REPEAT_ALERT_S


def _alert(db, target: dict, event: str, severity: str, payload: dict,
           audit_action: str):
    from audit import log_event  # noqa: E402
    scan_id = f"uptime:{target['id']}"
    # Maintenance suppression: while a window covers the target, a down
    # alert is logged (status='suppressed') but never sent and no incident
    # opens. The repeat window still advances so the log isn't spammed.
    if event == "uptime.down":
        window = maintenance.is_target_in_maintenance(
            db, target["org_id"], target["id"])
        if window is not None:
            from alert_fanout import record  # noqa: E402
            record(db, target["org_id"], event=event, scan_id=scan_id,
                   severity=severity, count=payload.get("failures", 0),
                   webhook_url=target.get("webhook_url") or "",
                   channel="maintenance",
                   recipient=window["title"][:120], status="suppressed",
                   attempts=0, error=None, payload=payload)
            db.commit()
            db.execute("UPDATE uptime_targets SET last_alerted_at=?,"
                       " last_alert_event=? WHERE id=?",
                       (_now_iso(), event, target["id"]))
            db.commit()
            log_event(target["org_id"], "system",
                      "maintenance.alert_suppressed",
                      detail={"target_id": target["id"],
                              "hostname": target["hostname"],
                              "window_id": window["id"],
                              "window_title": window["title"]},
                      db=db)
            db.commit()
            return
    # A recovery is announced only if the outage itself was announced:
    # a down alert that was suppressed by maintenance stays silent.
    if event == "uptime.recovered":
        last_down = db.execute(
            "SELECT status FROM notifications WHERE org_id=?"
            " AND scan_id=? AND event='uptime.down'"
            " ORDER BY created_at DESC, id DESC LIMIT 1",
            (target["org_id"], scan_id)).fetchone()
        if last_down is not None and last_down["status"] == "suppressed":
            db.execute("UPDATE uptime_targets SET last_alerted_at=?,"
                       " last_alert_event=? WHERE id=?",
                       (_now_iso(), event, target["id"]))
            db.commit()
            return
    from alert_fanout import fan_out  # noqa: E402
    fan_out(db, target["org_id"], event=event,
            scan_id=scan_id, severity=severity,
            count=payload.get("failures", 0),
            webhook_url=target.get("webhook_url") or "", payload=payload)
    db.execute("UPDATE uptime_targets SET last_alerted_at=?,"
               " last_alert_event=? WHERE id=?",
               (_now_iso(), event, target["id"]))
    db.commit()
    from audit import log_event  # noqa: E402
    log_event(target["org_id"], "system", audit_action,
              detail={"target_id": target["id"],
                      "hostname": target["hostname"],
                      "path": target["path"]},
              db=db)
    db.commit()
    # Automatic incident log: a down alert opens an incident for the
    # target (idempotent — one open incident per target); a recovery
    # auto-resolves them. Best-effort: never breaks alerting.
    try:
        if event == "uptime.down":
            status_page.open_incident_for_target(
                db, target, payload.get("error") or "")
        elif event == "uptime.recovered":
            status_page.resolve_incidents_for_target(db, target)
    except Exception:  # noqa: BLE001
        log.exception("auto-incident handling failed")


def check_target(db, target: dict) -> dict:
    """Probe one target, persist the outcome, maybe alert. Never raises."""
    try:
        res = probe(target)
        now = _now_iso()
        if res.get("config_error"):
            db.execute("UPDATE uptime_targets SET last_checked_at=?,"
                       " last_status='error', last_error=? WHERE id=?",
                       (now, res["error"][:500], target["id"]))
            db.commit()
            status_page.record_check(db, target["id"], "error", None)
            return {"status": "error", "error": res["error"]}
        if res["ok"]:
            was_down = target.get("last_status") == "down"
            db.execute("UPDATE uptime_targets SET last_checked_at=?,"
                       " last_status='up', last_http_code=?,"
                       " last_latency_ms=?, last_error=NULL,"
                       " consecutive_failures=0 WHERE id=?",
                       (now, res["http_status"], res["latency_ms"],
                        target["id"]))
            db.commit()
            status_page.record_check(db, target["id"], "up",
                                     res["latency_ms"])
            if was_down and target.get("last_alert_event") == "uptime.down":
                payload = _payload(target, res, "uptime.recovered")
                _alert(db, target, "uptime.recovered", "info", payload,
                       "uptime_target.recovered")
            return {"status": "up", "http_status": res["http_status"],
                    "latency_ms": res["latency_ms"]}
        # down
        failures = (target.get("consecutive_failures") or 0) + 1
        db.execute("UPDATE uptime_targets SET last_checked_at=?,"
                   " last_status='down', last_http_code=?,"
                   " last_latency_ms=?, last_error=?,"
                   " consecutive_failures=? WHERE id=?",
                   (now, res["http_status"], res["latency_ms"],
                    (res["error"] or "")[:500], failures, target["id"]))
        db.commit()
        status_page.record_check(db, target["id"], "down",
                                 res["latency_ms"])
        # NOTE: `target` still carries the pre-check alert state, which is
        # exactly what the anti-spam check needs.
        if failures >= FAILURES_BEFORE_ALERT and _down_alert_due(target):
            payload = _payload(target, res, "uptime.down")
            payload["failures"] = failures
            _alert(db, target, "uptime.down", "critical", payload,
                   "uptime_target.down")
        return {"status": "down", "error": res["error"],
                "failures": failures}
    except Exception as e:  # noqa: BLE001 - a probe must never kill the beat
        log.exception("uptime check crashed for %s", target.get("hostname"))
        return {"status": "error", "error": str(e)}


def _payload(target: dict, res: dict, event: str) -> dict:
    return {"event": event, "hostname": target["hostname"],
            "port": target["port"], "path": target["path"],
            "use_https": bool(target["use_https"]),
            "http_status": res.get("http_status"),
            "latency_ms": res.get("latency_ms"),
            "error": res.get("error"), "failures": 0}


def run_uptime_checks_once(db=None) -> dict:
    """Probe every due target. Best-effort: never raises."""
    from database import get_db  # noqa: E402
    own = db is None
    if own:
        db = get_db()
    try:
        now_ts = time.time()
        rows = db.execute(
            "SELECT * FROM uptime_targets WHERE enabled=1").fetchall()
        out = {"checked": 0, "down": 0, "errors": 0}
        for r in rows:
            t = dict(r)
            last = t.get("last_checked_at")
            if last:
                try:
                    age = now_ts - datetime.fromisoformat(last).timestamp()
                except ValueError:
                    age = float("inf")
                if age < (t.get("check_interval_s") or DEFAULT_INTERVAL_S):
                    continue
            res = check_target(db, t)
            out["checked"] += 1
            if res.get("status") == "down":
                out["down"] += 1
            elif res.get("status") == "error":
                out["errors"] += 1
        try:
            status_page.prune_daily(db)
        except Exception:  # noqa: BLE001 - pruning must not kill the beat
            log.exception("uptime_daily prune failed")
        return out
    except Exception:  # noqa: BLE001 - beat must survive
        log.exception("uptime check sweep crashed")
        return {"checked": 0, "down": 0, "errors": 0}
    finally:
        if own:
            db.close()
