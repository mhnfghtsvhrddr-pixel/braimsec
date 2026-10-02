"""Scheduled uptime digest emails.

A per-org digest configuration (weekly or monthly) makes the beat worker
email an uptime summary — per-target uptime %, average latency, incidents
in the period and certificates expiring soon — to the org's alert-email
recipients. A manual ``send`` endpoint covers "send it now".

Without SMTP configured (``BRAIMSEC_SMTP_*``) the digest is reported as
``skipped`` and nothing is sent, mirroring the alert-email semantics.
"""

import logging
import time
from datetime import datetime, timedelta, timezone

log = logging.getLogger("braimsec.digest")

FREQUENCIES = ("weekly", "monthly")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def _parse_day(value, field, lo, hi):
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an integer")
    if not (lo <= v <= hi):
        raise ValueError(f"{field} must be {lo}..{hi}")
    return v


def validate_config(frequency: str, day_of_week, day_of_month,
                    hour) -> dict:
    if frequency not in FREQUENCIES:
        raise ValueError(f"frequency must be one of {FREQUENCIES}")
    hour = _parse_day(hour, "hour", 0, 23)
    if frequency == "weekly":
        day_of_week = _parse_day(day_of_week, "day_of_week", 0, 6)
        day_of_month = 1
    else:
        day_of_month = _parse_day(day_of_month, "day_of_month", 1, 28)
        day_of_week = 0
    return {"frequency": frequency, "day_of_week": day_of_week,
            "day_of_month": day_of_month, "hour": hour}


def get_config(db, org_id: str) -> dict | None:
    r = db.execute("SELECT * FROM uptime_digests WHERE org_id=?",
                   (org_id,)).fetchone()
    return dict(r) if r else None


def upsert_config(db, org_id: str, enabled: bool, frequency: str,
                  day_of_week, day_of_month, hour) -> dict:
    cfg = validate_config(frequency, day_of_week, day_of_month, hour)
    now = _now_iso()
    if get_config(db, org_id) is None:
        db.execute(
            "INSERT INTO uptime_digests (org_id, enabled, frequency,"
            " day_of_week, day_of_month, hour, last_sent_at, created_at,"
            " updated_at) VALUES (?,?,?,?,?,?,NULL,?,?)",
            (org_id, 1 if enabled else 0, cfg["frequency"],
             cfg["day_of_week"], cfg["day_of_month"], cfg["hour"],
             now, now))
    else:
        db.execute(
            "UPDATE uptime_digests SET enabled=?, frequency=?,"
            " day_of_week=?, day_of_month=?, hour=?, updated_at=?"
            " WHERE org_id=?",
            (1 if enabled else 0, cfg["frequency"], cfg["day_of_week"],
             cfg["day_of_month"], cfg["hour"], now, org_id))
    db.commit()
    return get_config(db, org_id)


def digest_due(cfg: dict, now: datetime | None = None) -> bool:
    """True when the digest should be sent right now (UTC clock)."""
    if not cfg or not cfg["enabled"]:
        return False
    now = now or datetime.now(timezone.utc)
    if now.hour < cfg["hour"]:
        return False
    if cfg["frequency"] == "weekly":
        if now.weekday() != cfg["day_of_week"]:
            return False
        period_start = (now - timedelta(days=7))
    else:
        if now.day != cfg["day_of_month"]:
            return False
        period_start = now - timedelta(days=31)
    last = cfg.get("last_sent_at")
    if last:
        try:
            last_dt = datetime.fromisoformat(last)
        except ValueError:
            return True
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        # Already sent inside the current period: don't resend.
        if last_dt >= period_start:
            return False
    return True


def build_digest(db, org_id: str, days: int = 7) -> dict:
    """Aggregate uptime/incident/cert data for the last ``days`` days."""
    if not (1 <= days <= 90):
        raise ValueError("days must be 1..90")
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    targets = []
    for t in db.execute(
            "SELECT id, hostname, port, path, use_https FROM uptime_targets"
            " WHERE org_id=? AND enabled=1 ORDER BY hostname, path",
            (org_id,)).fetchall():
        t = dict(t)
        rows = db.execute(
            "SELECT checks_up, checks_down, checks_error, latency_sum_ms,"
            " latency_n FROM uptime_daily WHERE target_id=? AND day >= ?",
            (t["id"], start)).fetchall()
        up = sum(r["checks_up"] for r in rows)
        down = sum(r["checks_down"] for r in rows)
        err = sum(r["checks_error"] for r in rows)
        lat_sum = sum(r["latency_sum_ms"] for r in rows)
        lat_n = sum(r["latency_n"] for r in rows)
        total = up + down + err
        scheme = "https" if t["use_https"] else "http"
        targets.append({
            "hostname": t["hostname"], "path": t["path"],
            "url": f"{scheme}://{t['hostname']}:{t['port']}{t['path']}",
            "uptime_pct": round(100.0 * up / total, 2) if total else None,
            "avg_latency_ms": round(lat_sum / lat_n) if lat_n else None,
            "checks": total, "down_checks": down,
        })
    cutoff = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    incidents = [dict(r) for r in db.execute(
        "SELECT id, title, status, impact, started_at, resolved_at"
        " FROM incidents WHERE org_id=? AND started_at >= ?"
        " ORDER BY started_at DESC", (org_id, cutoff)).fetchall()]
    certs = [dict(r) for r in db.execute(
        "SELECT hostname, last_days_left, last_status FROM cert_domains"
        " WHERE org_id=? AND enabled=1 AND last_status='expiring'"
        " ORDER BY last_days_left", (org_id,)).fetchall()]
    return {"org_id": org_id, "days": days,
            "period_start": cutoff[:10],
            "period_end": now.strftime("%Y-%m-%d"),
            "targets": targets, "incidents": incidents,
            "certs_expiring": certs, "generated_at": _now_iso()}


def digest_texts(digest: dict, org_name: str) -> tuple[str, str, str]:
    """(subject, text, html) for the digest email."""
    days = digest["days"]
    subject = (f"📊 BraimSec: ملخص الجهوزية ({days} أيام) — {org_name}")
    lines = [f"BraimSec — ملخص الجهوزية (آخر {days} أيام)",
             f"المنظمة: {org_name}",
             f"الفترة: {digest['period_start']} → {digest['period_end']}",
             ""]
    for t in digest["targets"]:
        up = "لا بيانات" if t["uptime_pct"] is None else f"{t['uptime_pct']}%"
        lat = "—" if t["avg_latency_ms"] is None else f"{t['avg_latency_ms']}ms"
        lines.append(f"• {t['hostname']}{t['path']}: جهوزية {up}، "
                     f"متوسط الاستجابة {lat} ({t['checks']} فحصاً)")
    if digest["incidents"]:
        lines += ["", f"الحوادث ({len(digest['incidents'])}):"]
        lines += [f"• {i['title']} [{i['status']}]" for i in
                  digest["incidents"]]
    if digest["certs_expiring"]:
        lines += ["", "شهادات تنتهي قريباً:"]
        lines += [f"• {c['hostname']}: {c['last_days_left']} يوم"
                  for c in digest["certs_expiring"]]
    text = "\n".join(lines)
    rows = ""
    for t in digest["targets"]:
        up = "لا بيانات" if t["uptime_pct"] is None else f"{t['uptime_pct']}%"
        lat = "—" if t["avg_latency_ms"] is None else f"{t['avg_latency_ms']}ms"
        rows += (f"<tr><td dir='ltr'>{t['hostname']}{t['path']}</td>"
                 f"<td>{up}</td><td>{lat}</td><td>{t['checks']}</td></tr>")
    html = (
        '<html dir="rtl" lang="ar"><body style="font-family:sans-serif">'
        f"<h2>📊 ملخص الجهوزية — آخر {days} أيام</h2>"
        f"<p>{org_name} · {digest['period_start']} → {digest['period_end']}</p>"
        "<table border='1' cellpadding='6' cellspacing='0'>"
        "<tr><th>الرابط</th><th>الجهوزية</th><th>متوسط الاستجابة</th>"
        "<th>الفحوصات</th></tr>" + rows + "</table>"
        f"<p>الحوادث: {len(digest['incidents'])} · "
        f"شهادات تنتهي قريباً: {len(digest['certs_expiring'])}</p>"
        "</body></html>")
    return subject, text, html


def send_digest(db, org_id: str, days: int = 7,
                actor: str = "") -> dict:
    """Email the digest to the org's alert recipients.

    Returns {sent, total, skipped, error}. ``skipped`` is True when the
    org has no recipients or SMTP is not configured — nothing is sent.
    """
    from email_alerts import send_email  # noqa: E402
    org_row = db.execute("SELECT name FROM organizations WHERE id=?",
                         (org_id,)).fetchone()
    org_name = org_row["name"] if org_row else org_id
    digest = build_digest(db, org_id, days)
    subject, text, html = digest_texts(digest, org_name)
    recipients = [r["email"] for r in db.execute(
        "SELECT email FROM alert_emails WHERE org_id=? AND enabled=1",
        (org_id,)).fetchall()]
    if not recipients:
        return {"sent": 0, "total": 0, "skipped": True,
                "error": "no alert-email recipients configured"}
    sent, errors = 0, []
    for email in recipients:
        try:
            ok, _attempts, err = send_email(email, subject, text, html)
        except Exception as e:  # noqa: BLE001 - one bad recipient
            ok, err = False, f"{type(e).__name__}: {e}"
        if ok:
            sent += 1
        elif err:
            errors.append(err)
    from audit import log_event  # noqa: E402
    log_event(org_id, actor or "system", "uptime_digest.sent",
              detail={"days": days, "sent": sent, "total": len(recipients)},
              db=db)
    db.commit()
    skipped = sent == 0 and any("SMTP not configured" in e
                                for e in errors)
    return {"sent": sent, "total": len(recipients), "skipped": skipped,
            "error": "; ".join(errors[:3]) if errors else None}


def run_digests_once(db=None, now: datetime | None = None) -> dict:
    """Send every due digest. Best-effort: never raises."""
    from database import get_db  # noqa: E402
    own = db is None
    if own:
        db = get_db()
    try:
        now = now or datetime.now(timezone.utc)
        out = {"sent": 0, "skipped": 0}
        for r in db.execute("SELECT * FROM uptime_digests"
                            " WHERE enabled=1").fetchall():
            cfg = dict(r)
            try:
                if not digest_due(cfg, now):
                    continue
                res = send_digest(db, cfg["org_id"], days=7
                                  if cfg["frequency"] == "weekly" else 30)
            except Exception:  # noqa: BLE001 - one org must not kill beat
                log.exception("digest failed for org %s", cfg["org_id"])
                continue
            db.execute("UPDATE uptime_digests SET last_sent_at=?"
                       " WHERE org_id=?", (_now_iso(), cfg["org_id"]))
            db.commit()
            out["sent"] += 1
            if res.get("skipped"):
                out["skipped"] += 1
        return out
    except Exception:  # noqa: BLE001 - beat must survive
        log.exception("digest sweep crashed")
        return {"sent": 0, "skipped": 0}
    finally:
        if own:
            db.close()
