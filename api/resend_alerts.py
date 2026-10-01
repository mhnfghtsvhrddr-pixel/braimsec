"""Resend a failed alert notification from the delivery log.

Replay semantics per channel:

- ``webhook``: the original JSON payload is stored on the row, so the resend
  is an exact replay through ``scheduler.send_alert`` (re-signed with the
  org's current HMAC secret, if any).
- ``telegram`` / ``email``: the recipient (chat id / address) is stored
  unmasked; the message body is rebuilt from the same scan's findings with
  the same builder functions the dispatchers use.
- ``slack`` / ``teams``: NOT supported — the recipient column only keeps a
  masked label, so the exact destination URL cannot be resolved
  deterministically. Re-run the schedule instead.

Only rows with ``status='failed'`` can be resent. The row is updated in
place (status/attempts/response_code/error) and the attempt is audit-logged.
"""

import json
import logging

log = logging.getLogger("braimsec.resend")

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_RESENDABLE = {"webhook", "telegram", "email"}


class ResendError(Exception):
    """Carries an HTTP status for the endpoint."""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def _top_findings(db, scan_id: str, limit: int = 10) -> list[dict]:
    rows = db.execute(
        "SELECT tool, rule_id, severity, message, file, line"
        " FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
    fs = [dict(r) for r in rows]
    fs.sort(key=lambda f: _SEV_ORDER.get(
        str(f.get("severity") or "").lower(), 9))
    return fs[:limit]


def _context(db, row: dict) -> tuple[str, str]:
    """(heading, subheading) for the rebuilt message."""
    scan_tag = f"فحص {(row['scan_id'] or '')[:8]}"
    if row.get("schedule_id"):
        s = db.execute("SELECT name FROM schedules WHERE id=?",
                       (row["schedule_id"],)).fetchone()
        return ((s["name"] if s and s["name"] else "جدولة محذوفة"), scan_tag)
    if row.get("vcs_repo_id"):
        r = db.execute("SELECT full_name FROM vcs_repos WHERE id=?",
                       (row["vcs_repo_id"],)).fetchone()
        return ((r["full_name"] if r and r["full_name"] else "مستودع محذوف"),
                scan_tag)
    return ("تنبيه BraimSec", scan_tag)


def _build_content(db, row: dict, channel: str):
    """Return the (send_args, send_fn) pair for a rebuilt message."""
    from email_alerts import build_email, send_email  # noqa: E402
    from telegram_alerts import (build_telegram_message,  # noqa: E402
                                 send_telegram)

    findings = _top_findings(db, row["scan_id"])
    heading, subheading = _context(db, row)
    if channel == "telegram":
        text = build_telegram_message(row["event"], heading, subheading,
                                      findings, row["severity"], "")
        return send_telegram, (row["recipient"], text)
    subject, text_body, html_body = build_email(
        row["event"], heading, subheading, findings, row["severity"], "")
    return send_email, (row["recipient"], subject, text_body, html_body)


def resend_notification(db, notif_id: int, org_id: str, actor: str) -> dict:
    """Resend one failed notification. Returns the updated row summary."""
    from scheduler import send_alert  # noqa: E402 - deferred, mirrors dispatch

    row = db.execute(
        "SELECT * FROM notifications WHERE id=? AND org_id=?",
        (notif_id, org_id)).fetchone()
    if row is None:
        raise ResendError(404, "notification not found")
    row = dict(row)

    if row["status"] == "sent":
        raise ResendError(409, "notification already sent")
    if row["status"] == "skipped":
        raise ResendError(409, "skipped rows cannot be resent — "
                              "configure the channel first")
    if row["status"] != "failed":
        raise ResendError(409, f"only failed rows can be resent "
                              f"(status={row['status']})")

    channel = row["channel"]
    code = None
    if channel == "webhook":
        if not row["webhook_url"]:
            raise ResendError(409, "no webhook URL stored on this row")
        try:
            payload = json.loads(row["payload"] or "{}")
        except (json.JSONDecodeError, TypeError):
            raise ResendError(409, "stored payload is not valid JSON")
        ok, attempts, code, err = send_alert(row["webhook_url"], payload,
                                             org_id=org_id)
    elif channel in ("telegram", "email"):
        if not row["recipient"]:
            raise ResendError(409, "no recipient stored on this row")
        send_fn, args = _build_content(db, row, channel)
        ok, attempts, err = send_fn(*args)
    else:
        raise ResendError(409, f"resend is not supported for channel "
                              f"'{channel}' (masked destination) — "
                              f"re-run the schedule instead")

    new_status = "sent" if ok else "failed"
    db.execute("UPDATE notifications SET status=?, attempts=attempts+1,"
               " response_code=?, error=? WHERE id=?",
               (new_status, code, err, notif_id))

    from audit import log_event  # noqa: E402
    log_event(org_id, actor, "notification.resent",
              detail={"notif_id": notif_id, "channel": channel,
                      "event": row["event"], "scan_id": row["scan_id"],
                      "status": new_status,
                      "attempts": row["attempts"] + 1},
              db=db)
    db.commit()  # row update + audit record land in one transaction
    return {"id": notif_id, "channel": channel, "status": new_status,
            "attempts": row["attempts"] + 1, "error": err}
