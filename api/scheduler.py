#!/usr/bin/env python3
"""BraimSec scheduled scans + new-findings alerts (webhooks).

A *schedule* belongs to one org and periodically re-scans a server-local
target (``target_path`` inside the scan sandbox). Each run reuses the
previous scheduled scan as ``baseline_scan_id`` so unchanged code costs no
engine work (see ``scanner/incremental.py``).

After a scheduled scan reaches a terminal state, the worker calls
:func:`evaluate_schedule_alerts`:

- the scan's findings are fingerprinted ``tool|rule_id|file|message``
  (line numbers are excluded: a finding that merely moved lines is not new)
- findings whose fingerprint was absent from the previous scheduled scan
  are *new*; if any new finding has severity >= the schedule's
  ``alert_severity`` threshold, a Slack-compatible webhook fires
- the first scheduled run only establishes the baseline: no alert
- a failed scheduled scan fires a ``schedule.failed`` alert (silent
  monitoring is worse than a noisy one)
- findings triaged as false_positive (``finding_suppressions`` table,
  team triage feature) are excluded from the new-findings set: a
  dismissed false positive never re-alerts

Alerts are delivered with :func:`send_alert` (SSRF-guarded, 3 attempts with
backoff) and every outcome is recorded in the ``notifications`` table.
Email is the twin channel: :func:`email_alerts.dispatch_email_alerts`
sends to the org's registered addresses on the *same* trigger (operator's
own SMTP via ``BRAIMSEC_SMTP_*`` env vars; unconfigured SMTP is recorded
as ``skipped``, never silent).

The periodic driver is :func:`run_scheduler_once`, invoked every minute by
Celery beat (``braimsec.check_schedules`` in ``tasks.py``). Due schedules
are claimed with a single conditional UPDATE so overlapping beat/worker
instances can never double-run a schedule.
"""

import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from database import get_db
from ssrf_guard import safe_webhook_post

log = logging.getLogger("braimsec.scheduler")


SEVERITY_ORDER = {"note": 0, "warning": 1, "error": 2}
VALID_FREQUENCIES = ("daily", "weekly")
VALID_SEVERITIES = ("note", "warning", "error")

ALERT_TIMEOUT_S = 10.0
ALERT_ATTEMPTS = 3
MAX_ALERT_FINDINGS = 10  # findings embedded in the webhook payload


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scheduling math (pure, heavily tested)
# ---------------------------------------------------------------------------

def compute_next_run(frequency: str, run_time: str, weekday: int | None,
                     tz_name: str, after: datetime | None = None) -> str:
    """Next run strictly after ``after`` (default: now), as ISO-8601.

    ``run_time`` is ``HH:MM`` in the schedule's IANA timezone. ``weekday``
    (0=Monday..6=Sunday) is required for weekly schedules.
    """
    if frequency not in VALID_FREQUENCIES:
        raise ValueError(f"frequency must be one of {VALID_FREQUENCIES}")
    try:
        hour, minute = (int(x) for x in run_time.split(":"))
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError()
    except ValueError:
        raise ValueError("run_time must be HH:MM (00:00-23:59)")
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"unknown timezone: {tz_name}")
    after = after or datetime.now(timezone.utc)
    if after.tzinfo is None:
        after = after.replace(tzinfo=timezone.utc)
    local = after.astimezone(tz)
    candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if frequency == "daily":
        if candidate <= local:
            candidate += timedelta(days=1)
    else:  # weekly
        if weekday is None or not (0 <= weekday <= 6):
            raise ValueError("weekday (0=Monday..6=Sunday) is required for weekly")
        days_ahead = (weekday - candidate.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate <= local:
            candidate += timedelta(weeks=1)
    return candidate.isoformat()


# ---------------------------------------------------------------------------
# Finding fingerprints + alert payload (pure)
# ---------------------------------------------------------------------------

def finding_fingerprint(tool: str, rule_id: str, file: str,
                       message: str | None) -> str:
    """Stable identity of a finding across rescans.

    Line/column are deliberately excluded: a finding that moved because code
    above it changed is the *same* finding, not a new one.
    """
    h = hashlib.sha256()
    h.update(f"{tool or ''}|{rule_id or ''}|{file or ''}|{message or ''}"
             .encode("utf-8"))
    return h.hexdigest()[:32]


def build_alert_payload(schedule: dict, scan: dict,
                        new_findings: list[dict]) -> dict:
    """Slack-compatible alert payload (also carries ``content`` for Discord)."""
    sev_rank = max(SEVERITY_ORDER.get(f["severity"], 0) for f in new_findings)
    top_sev = next(s for s, r in SEVERITY_ORDER.items() if r == sev_rank)
    sev_ar = {"error": "حرجة", "warning": "متوسطة", "note": "منخفضة"}
    text = (f"🛡️ BraimSec: {len(new_findings)} نتيجة جديدة "
            f"({sev_ar.get(top_sev, top_sev)}) في '{scan['target_name']}' "
            f"[جدولة: {schedule['name']}]")
    items = [{
        "severity": f["severity"],
        "tool": f["tool"],
        "rule_id": f["rule_id"],
        "file": f["file"],
        "line": f["line"],
        "message": (f["message"] or "")[:300],
    } for f in new_findings[:MAX_ALERT_FINDINGS]]
    return {
        "event": "schedule.alert",
        "text": text,
        "content": text,  # Discord webhooks read `content`
        "schedule_id": schedule["id"],
        "schedule_name": schedule["name"],
        "scan_id": scan["id"],
        "target_name": scan["target_name"],
        "new_findings": len(new_findings),
        "highest_severity": top_sev,
        "truncated": len(new_findings) > MAX_ALERT_FINDINGS,
        "findings": items,
    }


# ---------------------------------------------------------------------------
# Alert delivery (SSRF-guarded, retried, recorded)
# ---------------------------------------------------------------------------

def send_alert(webhook_url: str, payload: dict,
               org_id: str | None = None) -> tuple[bool, int, int | None,
                                                  str | None]:
    """POST the payload; returns (ok, attempts, http_code, error).

    When the org has a signing secret configured (``POST
    /api/webhook-signing/rotate``), the payload is HMAC-SHA256-signed and
    ``X-BraimSec-Signature`` / ``X-BraimSec-Timestamp`` headers are sent so
    receivers can verify authenticity and reject replays. Signing is
    best-effort: a corrupt secret row is logged and the alert goes out
    unsigned rather than being dropped.
    """
    body = json.dumps(payload, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json; charset=utf-8",
               "X-BraimSec-Event": payload.get("event", "schedule.alert")}
    if org_id:
        try:
            from webhook_signing import (get_org_signing_secret,
                                         signing_headers)
            db = get_db()
            try:
                secret = get_org_signing_secret(db, org_id)
            finally:
                db.close()
            if secret:
                headers.update(signing_headers(secret, body))
        except Exception as e:  # noqa: BLE001 - best effort by design
            log.warning("webhook signing unavailable for org %s: %s",
                        org_id, str(e)[:150])
    attempts = 0
    last_err = None
    for attempt in range(1, ALERT_ATTEMPTS + 1):
        attempts = attempt
        try:
            code = safe_webhook_post(webhook_url, body, headers,
                                     ALERT_TIMEOUT_S)
            if 200 <= code < 300:
                return True, attempts, code, None
            last_err = f"HTTP {code}"
            log.warning("schedule alert -> %s (attempt %d)", code, attempt)
        except Exception as e:  # noqa: BLE001 - best effort by design
            last_err = str(e)[:200]
            log.warning("schedule alert failed (attempt %d): %s", attempt,
                        last_err)
        time.sleep(2 ** attempt)
    return False, attempts, None, last_err


# ---------------------------------------------------------------------------
# Driver: claim due schedules and run their scans
# ---------------------------------------------------------------------------

def _create_scheduled_scan(db, sched: dict) -> str:
    """Create + enqueue one scan for a schedule. Returns the scan id.

    Reuses ``POST /api/scans`` internals (quota, sandbox validation, queue
    routing) so scheduled scans behave exactly like manual ones.
    """
    # Deferred import: main imports tasks which imports this module.
    from fastapi import HTTPException  # noqa: E402 - deferred, cheap
    from main import _new_scan, _resolve_scan_target  # noqa: E402

    target_dir = _resolve_scan_target(sched["target_path"])  # 403 outside sandbox
    baseline = sched.get("prev_scan_id") or sched.get("last_scan_id")
    if baseline:
        row = db.execute("SELECT status FROM scans WHERE id=?",
                         (baseline,)).fetchone()
        if not row or row["status"] != "done":
            baseline = None  # only incrementalize against a finished scan
    name = sched["target_path"].rstrip("/").split("/")[-1] or sched["target_path"]
    prev_last, prev_prev = sched["last_scan_id"], sched["prev_scan_id"]
    scan_id = uuid.uuid4().hex[:12]
    # Link the schedule to the new scan BEFORE enqueue: the worker's alert
    # hook resolves the schedule via last_scan_id, and in inline (dev)
    # mode that hook fires inside _new_scan — before a later UPDATE could
    # land. (Also closes a Celery race where the worker could start first.)
    db.execute(
        "UPDATE schedules SET prev_scan_id=last_scan_id, last_scan_id=?,"
        " last_run_at=?, last_error=NULL WHERE id=? AND org_id=?",
        (scan_id, _now_iso(), sched["id"], sched["org_id"]))
    db.commit()
    try:
        _new_scan(
            sched["org_id"], name, target_dir, None, None,
            webhook_url=None, webhook_secret=None,
            baseline_scan_id=baseline, project_id=None, scan_id=scan_id)
    except HTTPException as e:
        if e.status_code == 402:
            # Quota: no scan row was created — revert the link.
            db.execute(
                "UPDATE schedules SET last_scan_id=?, prev_scan_id=?,"
                " last_error=? WHERE id=?",
                (prev_last, prev_prev, e.detail, sched["id"]))
            db.commit()
        else:
            # 503: the scan row exists as failed but no worker hook ran —
            # evaluate now so the schedule.failed alert still fires.
            db.execute("UPDATE schedules SET last_error=? WHERE id=?",
                       (e.detail, sched["id"]))
            db.commit()
            evaluate_schedule_alerts(scan_id)
        raise
    return scan_id


def run_scheduler_once(now_iso: str | None = None) -> dict:
    """Run every schedule whose time has come. Returns a small summary.

    Each due schedule is claimed with one conditional UPDATE (sets the next
    run *before* the scan starts), so two beat instances can never run it
    twice. A schedule whose scan creation fails is logged and skipped; its
    next run is already advanced so one bad target cannot wedge the loop.
    """
    from fastapi import HTTPException  # noqa: E402 - deferred, cheap
    now_iso = now_iso or _now_iso()
    db = get_db()
    ran, skipped = [], []
    try:
        due = db.execute(
            "SELECT * FROM schedules WHERE enabled=1 AND next_run_at <= ?",
            (now_iso,)).fetchall()
        for row in due:
            sched = dict(row)
            try:
                nxt = compute_next_run(sched["frequency"], sched["run_time"],
                                       sched["weekday"], sched["timezone"],
                                       after=datetime.fromisoformat(now_iso))
            except ValueError as e:
                log.error("schedule %s has invalid spec: %s", sched["id"], e)
                skipped.append({"id": sched["id"], "reason": str(e)[:120]})
                continue
            # Atomic claim: only the winner's UPDATE matches.
            cur = db.execute(
                "UPDATE schedules SET next_run_at=?, last_run_at=? "
                "WHERE id=? AND next_run_at <= ?",
                (nxt, now_iso, sched["id"], now_iso))
            if cur.rowcount == 0:
                continue  # claimed by another beat instance
            db.commit()
            try:
                scan_id = _create_scheduled_scan(db, sched)
            except HTTPException as e:
                db.execute("UPDATE schedules SET last_error=? WHERE id=?",
                           (f"{e.status_code}: {e.detail}"[:300], sched["id"]))
                db.commit()
                skipped.append({"id": sched["id"],
                                "reason": f"{e.status_code}: {e.detail}"[:120]})
                continue
            except Exception as e:  # noqa: BLE001 - one bad schedule != dead loop
                log.exception("scheduled scan failed for %s", sched["id"])
                db.execute("UPDATE schedules SET last_error=? WHERE id=?",
                           (str(e)[:300], sched["id"]))
                db.commit()
                skipped.append({"id": sched["id"], "reason": str(e)[:120]})
                continue
            # NB: the schedule→scan link (last/prev_scan_id, last_run_at) is
            # already updated inside _create_scheduled_scan, BEFORE the
            # enqueue — the worker alert hook resolves the schedule through
            # it, so it must exist before the scan can finish.
            ran.append({"id": sched["id"], "scan_id": scan_id})
    finally:
        db.close()
    return {"ran": ran, "skipped": skipped, "at": now_iso}


def run_schedule_now(schedule_id: str) -> str:
    """Trigger one immediate run of an enabled schedule. Returns scan id."""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM schedules WHERE id=?",
                         (schedule_id,)).fetchone()
        if not row:
            raise KeyError(schedule_id)
        sched = dict(row)
        if not sched["enabled"]:
            raise ValueError("schedule is disabled")
        # _create_scheduled_scan links the schedule to the new scan itself
        # (last/prev_scan_id, last_run_at) before enqueue, so the worker
        # alert hook can resolve it. A manual run does not shift next_run_at.
        return _create_scheduled_scan(db, sched)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Post-scan: diff against the previous scheduled scan, alert on new findings
# ---------------------------------------------------------------------------

def _email_row(new_findings: list[dict]) -> list[dict]:
    """Slim finding dicts for the email body builder."""
    return [{"severity": f["severity"], "rule_id": f["rule_id"],
             "file": f["file"], "line": f["line"],
             "message": f["message"]} for f in new_findings]


def _send_email_alerts(db, *, org_id: str, schedule_id: str | None,
                       vcs_repo_id: str | None, scan_id: str, event: str,
                       severity: str, new_count: int, heading: str,
                       subheading: str, findings: list[dict]) -> dict:
    """Email twin of a webhook alert (deferred import keeps the worker's
    import graph light). Never raises: alerting must never break scans."""
    try:
        from email_alerts import dispatch_email_alerts  # noqa: E402
        return dispatch_email_alerts(
            db, org_id=org_id, schedule_id=schedule_id,
            vcs_repo_id=vcs_repo_id, scan_id=scan_id, event=event,
            severity=severity, new_count=new_count, heading=heading,
            subheading=subheading, findings=findings)
    except Exception:  # noqa: BLE001 - best-effort by design
        log.exception("email alert dispatch crashed for %s", scan_id)
        return {"emailed": False, "reason": "dispatch crashed"}


def _send_telegram_alerts(db, *, org_id: str, schedule_id: str | None,
                          vcs_repo_id: str | None, scan_id: str, event: str,
                          severity: str, new_count: int, heading: str,
                          subheading: str, findings: list[dict]) -> dict:
    """Telegram twin of a webhook alert (deferred import keeps the worker's
    import graph light). Never raises: alerting must never break scans."""
    try:
        from telegram_alerts import dispatch_telegram_alerts  # noqa: E402
        return dispatch_telegram_alerts(
            db, org_id=org_id, schedule_id=schedule_id,
            vcs_repo_id=vcs_repo_id, scan_id=scan_id, event=event,
            severity=severity, new_count=new_count, heading=heading,
            subheading=subheading, findings=findings)
    except Exception:  # noqa: BLE001 - best-effort by design
        log.exception("telegram alert dispatch crashed for %s", scan_id)
        return {"telegrammed": False, "reason": "dispatch crashed"}


def _send_slack_alerts(db, *, org_id: str, schedule_id: str | None,
                       vcs_repo_id: str | None, scan_id: str, event: str,
                       severity: str, new_count: int, heading: str,
                       subheading: str, findings: list[dict]) -> dict:
    """Slack twin of a webhook alert (deferred import keeps the worker's
    import graph light). Never raises: alerting must never break scans."""
    try:
        from slack_alerts import dispatch_slack_alerts  # noqa: E402
        return dispatch_slack_alerts(
            db, org_id=org_id, schedule_id=schedule_id,
            vcs_repo_id=vcs_repo_id, scan_id=scan_id, event=event,
            severity=severity, new_count=new_count, heading=heading,
            subheading=subheading, findings=findings)
    except Exception:  # noqa: BLE001 - best-effort by design
        log.exception("slack alert dispatch crashed for %s", scan_id)
        return {"slacked": False, "reason": "dispatch crashed"}


def _send_teams_alerts(db, *, org_id: str, schedule_id: str | None,
                       vcs_repo_id: str | None, scan_id: str, event: str,
                       severity: str, new_count: int, heading: str,
                       subheading: str, findings: list[dict]) -> dict:
    """Teams twin of a webhook alert (deferred import keeps the worker's
    import graph light). Never raises: alerting must never break scans."""
    try:
        from teams_alerts import dispatch_teams_alerts  # noqa: E402
        return dispatch_teams_alerts(
            db, org_id=org_id, schedule_id=schedule_id,
            vcs_repo_id=vcs_repo_id, scan_id=scan_id, event=event,
            severity=severity, new_count=new_count, heading=heading,
            subheading=subheading, findings=findings)
    except Exception:  # noqa: BLE001 - best-effort by design
        log.exception("teams alert dispatch crashed for %s", scan_id)
        return {"teamsed": False, "reason": "dispatch crashed"}


def _scan_findings(db, scan_id: str) -> list[dict]:
    return [dict(r) for r in db.execute(
        "SELECT tool, rule_id, severity, message, file, line "
        "FROM findings WHERE scan_id=?", (scan_id,)).fetchall()]


def _suppressed_fps(db, org_id: str) -> set:
    """Fingerprints the org triaged as false_positive.

    Tolerant of DBs that predate the finding_suppressions table (team
    triage feature): a missing table means no suppressions, and alerting
    behaves exactly as before.
    """
    try:
        rows = db.execute(
            "SELECT fingerprint FROM finding_suppressions WHERE org_id=?",
            (org_id,)).fetchall()
    except Exception:  # noqa: BLE001 - pre-triage DBs: no suppression yet
        return set()
    return {r[0] for r in rows}


def evaluate_schedule_alerts(scan_id: str) -> dict:
    """Diff a finished scheduled scan vs its predecessor; alert if needed.

    Called by the worker on every terminal scan state. Best-effort: any
    failure is swallowed by the caller so alerting can never break scans.
    Returns a small outcome dict for tests/logs.
    """
    db = get_db()
    try:
        sched_row = db.execute(
            "SELECT * FROM schedules WHERE last_scan_id=?", (scan_id,)).fetchone()
        if not sched_row:
            return {"alerted": False, "reason": "not a scheduled scan"}
        sched = dict(sched_row)
        scan = db.execute("SELECT * FROM scans WHERE id=?",
                          (scan_id,)).fetchone()
        if not scan:
            return {"alerted": False, "reason": "scan row missing"}
        scan = dict(scan)
        if scan["status"] == "failed":
            return _alert_failure(db, sched, scan)
        if scan["status"] != "done":
            return {"alerted": False, "reason": f"status={scan['status']}"}
        prev_id = sched.get("prev_scan_id")
        if not prev_id:
            return {"alerted": False, "reason": "first run: baseline set"}
        old_fps = {finding_fingerprint(f["tool"], f["rule_id"], f["file"],
                                       f["message"])
                   for f in _scan_findings(db, prev_id)}
        threshold = SEVERITY_ORDER.get(sched.get("alert_severity",
                                                 "warning"), 1)
        suppressed = _suppressed_fps(db, sched["org_id"])
        new_findings = [
            f for f in _scan_findings(db, scan_id)
            if finding_fingerprint(f["tool"], f["rule_id"], f["file"],
                                   f["message"]) not in old_fps
            and finding_fingerprint(f["tool"], f["rule_id"], f["file"],
                                    f["message"]) not in suppressed
            and SEVERITY_ORDER.get(f["severity"], 0) >= threshold
        ]
        if not new_findings:
            return {"alerted": False, "reason": "no new findings >= threshold"}
        payload = build_alert_payload(sched, scan, new_findings)
        webhook_url = sched["webhook_url"] or ""
        email_out = _send_email_alerts(
            db, org_id=sched["org_id"], schedule_id=sched["id"],
            vcs_repo_id=None, scan_id=scan_id, event="schedule.alert",
            severity=payload["highest_severity"],
            new_count=len(new_findings),
            heading=f"فحص مجدول: {sched['name']}",
            subheading=f"الهدف: {scan['target_name']}",
            findings=_email_row(new_findings))
        telegram_out = _send_telegram_alerts(
            db, org_id=sched["org_id"], schedule_id=sched["id"],
            vcs_repo_id=None, scan_id=scan_id, event="schedule.alert",
            severity=payload["highest_severity"],
            new_count=len(new_findings),
            heading=f"فحص مجدول: {sched['name']}",
            subheading=f"الهدف: {scan['target_name']}",
            findings=_email_row(new_findings))
        slack_out = _send_slack_alerts(
            db, org_id=sched["org_id"], schedule_id=sched["id"],
            vcs_repo_id=None, scan_id=scan_id, event="schedule.alert",
            severity=payload["highest_severity"],
            new_count=len(new_findings),
            heading=f"فحص مجدول: {sched['name']}",
            subheading=f"الهدف: {scan['target_name']}",
            findings=_email_row(new_findings))
        teams_out = _send_teams_alerts(
            db, org_id=sched["org_id"], schedule_id=sched["id"],
            vcs_repo_id=None, scan_id=scan_id, event="schedule.alert",
            severity=payload["highest_severity"],
            new_count=len(new_findings),
            heading=f"فحص مجدول: {sched['name']}",
            subheading=f"الهدف: {scan['target_name']}",
            findings=_email_row(new_findings))
        if webhook_url:
            ok, attempts, code, err = send_alert(webhook_url, payload, org_id=sched["org_id"])
            db.execute(
                "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
                " scan_id, event, severity, new_count, webhook_url, channel,"
                " status, attempts, response_code, error, payload, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sched["org_id"], sched["id"], None, scan_id, "schedule.alert",
                 payload["highest_severity"], len(new_findings),
                 webhook_url, "webhook", "sent" if ok else "failed", attempts,
                 code, err, json.dumps(payload, ensure_ascii=False),
                 _now_iso()))
            db.commit()
        else:
            # Email-only org: no webhook configured, nothing to send/record.
            ok, attempts, err = False, 0, None
        emailed = bool(email_out.get("emailed"))
        telegrammed = bool(telegram_out.get("telegrammed"))
        slacked = bool(slack_out.get("slacked"))
        teamsed = bool(teams_out.get("teamsed"))
        return {"alerted": bool(ok) or emailed or telegrammed or slacked
                or teamsed,
                "new_count": len(new_findings),
                "attempts": attempts, "error": err, "email": email_out,
                "telegram": telegram_out, "slack": slack_out,
                "teams": teams_out}
    finally:
        db.close()


def _alert_failure(db, sched: dict, scan: dict) -> dict:
    """A failed scheduled scan means blind monitoring: say so, loudly."""
    payload = {
        "event": "schedule.failed",
        "text": (f"⚠️ BraimSec: scheduled scan FAILED for "
                 f"'{scan['target_name']}' [جدولة: {sched['name']}] — "
                 f"{(scan['error'] or 'unknown error')[:200]}"),
        "schedule_id": sched["id"],
        "schedule_name": sched["name"],
        "scan_id": scan["id"],
        "target_name": scan["target_name"],
        "error": (scan["error"] or "")[:500],
    }
    payload["content"] = payload["text"]
    webhook_url = sched["webhook_url"] or ""
    email_out = _send_email_alerts(
        db, org_id=sched["org_id"], schedule_id=sched["id"],
        vcs_repo_id=None, scan_id=scan["id"], event="schedule.failed",
        severity="error", new_count=0,
        heading=f"فحص مجدول: {sched['name']}",
        subheading=(f"الهدف: {scan['target_name']} — "
                    f"{(scan['error'] or 'unknown error')[:200]}"),
        findings=[])
    telegram_out = _send_telegram_alerts(
        db, org_id=sched["org_id"], schedule_id=sched["id"],
        vcs_repo_id=None, scan_id=scan["id"], event="schedule.failed",
        severity="error", new_count=0,
        heading=f"فحص مجدول: {sched['name']}",
        subheading=(f"الهدف: {scan['target_name']} — "
                    f"{(scan['error'] or 'unknown error')[:200]}"),
        findings=[])
    slack_out = _send_slack_alerts(
        db, org_id=sched["org_id"], schedule_id=sched["id"],
        vcs_repo_id=None, scan_id=scan["id"], event="schedule.failed",
        severity="error", new_count=0,
        heading=f"فحص مجدول: {sched['name']}",
        subheading=(f"الهدف: {scan['target_name']} — "
                    f"{(scan['error'] or 'unknown error')[:200]}"),
        findings=[])
    teams_out = _send_teams_alerts(
        db, org_id=sched["org_id"], schedule_id=sched["id"],
        vcs_repo_id=None, scan_id=scan["id"], event="schedule.failed",
        severity="error", new_count=0,
        heading=f"فحص مجدول: {sched['name']}",
        subheading=(f"الهدف: {scan['target_name']} — "
                    f"{(scan['error'] or 'unknown error')[:200]}"),
        findings=[])
    if webhook_url:
        ok, attempts, code, err = send_alert(webhook_url, payload, org_id=sched["org_id"])
        db.execute(
            "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
            " scan_id, event, severity, new_count, webhook_url, channel,"
            " status, attempts, response_code, error, payload, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sched["org_id"], sched["id"], None, scan["id"], "schedule.failed",
             "error", 0, webhook_url, "webhook", "sent" if ok else "failed",
             attempts, code, err, json.dumps(payload, ensure_ascii=False),
             _now_iso()))
        db.commit()
    else:
        ok, err = False, None
    emailed = bool(email_out.get("emailed"))
    telegrammed = bool(telegram_out.get("telegrammed"))
    slacked = bool(slack_out.get("slacked"))
    teamsed = bool(teams_out.get("teamsed"))
    return {"alerted": bool(ok) or emailed or telegrammed or slacked
            or teamsed,
            "event": "schedule.failed",
            "error": err, "email": email_out, "telegram": telegram_out,
            "slack": slack_out, "teams": teams_out}
