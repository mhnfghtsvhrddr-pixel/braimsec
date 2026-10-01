"""BraimSec Slack alerts (Incoming Webhooks).

The fourth alert channel, twin of webhooks/email/telegram: a Slack message
fires on the *same* trigger (new findings >= severity threshold, or a failed
scan), for the org's registered incoming-webhook URLs.

Each org registers its own webhook URL (created in Slack via
*Apps > Incoming Webhooks*); the URL is a bearer credential, so it is stored
**Fernet-encrypted at rest** (same scheme as VCS webhook secrets in
``vcs.py``, key derived from ``BRAIMSEC_API_KEY``) and never logged, never
returned by the API — the list endpoint only shows a masked tail.

``urlopen`` is imported as a module-level name (``from urllib.request import
urlopen``) so tests can monkeypatch ``slack_alerts.urlopen`` without
touching global urllib. ``time.sleep`` is module-level ``time`` for the
same reason.

Setup for an org owner (one-time):
  1. In Slack: create an app (or use an existing one) -> *Incoming Webhooks*
     -> *Add New Webhook to Workspace* -> pick the channel -> copy the URL
     (looks like https://hooks.slack.com/services/T.../B.../xxxx).
  2. POST /api/slack-webhooks {"webhook_url": "<url>", "label": "#security"}
     with a member+ API key. Alerts start flowing on the next trigger.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from urllib.request import Request, urlopen

from database import get_db

log = logging.getLogger("braimsec.slack_alerts")

SLACK_ATTEMPTS = 3
SLACK_TIMEOUT_S = 10.0
MAX_MESSAGE_CHARS = 3000
MAX_SL_FINDINGS = 5

SEV_AR = {"error": "حرجة", "warning": "متوسطة", "note": "منخفضة"}

# Incoming-webhook URLs live only on this host — anything else is rejected
# (also a guard against SSRF via the registration endpoint).
_WEBHOOK_RE = re.compile(
    r"^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{10,200}$")


# ---------------------------------------------------------------------------
# Validation + secret handling
# ---------------------------------------------------------------------------

def validate_webhook_url(value) -> str:
    """Validate a Slack incoming-webhook URL; returns it stripped.

    Raises ValueError on anything that is not a hooks.slack.com URL.
    """
    s = str(value or "").strip()
    if not _WEBHOOK_RE.match(s):
        raise ValueError(
            "invalid Slack webhook URL: must look like "
            "https://hooks.slack.com/services/T.../B.../xxx")
    return s


def mask_webhook_url(url: str) -> str:
    """Non-reversible masked display form for API responses."""
    tail = (url or "")[-6:]
    return f"https://hooks.slack.com/services/…{tail}"


def _encrypt(raw: str) -> str:
    from vcs import encrypt_secret  # noqa: E402  (deferred: light import graph)
    return encrypt_secret(raw)


def _decrypt(enc: str) -> str:
    from vcs import decrypt_secret  # noqa: E402
    return decrypt_secret(enc)


# ---------------------------------------------------------------------------
# Message building (short Arabic text; Slack renders it as mrkdwn/plain)
# ---------------------------------------------------------------------------

def _sev_ar(sev: str) -> str:
    return SEV_AR.get(sev, sev)


def build_slack_text(event: str, heading: str, subheading: str,
                     new_findings: list[dict], highest_severity: str,
                     link: str) -> str:
    """Build the short Arabic alert text (<= MAX_MESSAGE_CHARS)."""
    heading = re.sub(r"\s+", " ", heading or "").strip()
    subheading = re.sub(r"\s+", " ", subheading or "").strip()
    link = re.sub(r"\s+", " ", link or "").strip()
    if event.endswith(".failed"):
        text = (":warning: *BraimSec: فشل الفحص*\n"
                f"{heading}\n{subheading}\n\n"
                f"الفحص الآلي توقف بخطأ — راجع التفاصيل في اللوحة."
                + (f"\n<{link}|فتح اللوحة>" if link else ""))
        return text[:MAX_MESSAGE_CHARS]

    n = len(new_findings)
    sev = _sev_ar(highest_severity)
    lines = [f":shield: *BraimSec: {n} نتيجة جديدة ({sev})*",
             heading, subheading, ""]
    for f in new_findings[:MAX_SL_FINDINGS]:
        msg = re.sub(r"\s+", " ", str(f.get("message") or "")).strip()[:120]
        lines.append(f"• `[{f.get('severity')}]` {f.get('rule_id')} — "
                     f"`{f.get('file')}:{f.get('line')}`")
        if msg:
            lines.append(f"  {msg}")
    if n > MAX_SL_FINDINGS:
        lines.append(f"…و{n - MAX_SL_FINDINGS} أخرى")
    if link:
        lines += ["", f"<{link}|فتح اللوحة>"]
    return "\n".join(lines)[:MAX_MESSAGE_CHARS]


# ---------------------------------------------------------------------------
# Delivery (retried, recorded)
# ---------------------------------------------------------------------------

def send_slack(webhook_url: str, text: str) -> tuple[bool, int, str | None]:
    """POST one message to an incoming webhook.

    Returns (ok, attempts, error). Best-effort by design: exceptions are
    caught and retried, never raised. The webhook URL never appears in the
    returned error or any log line.
    """
    body = json.dumps({"text": text}).encode("utf-8")
    attempts = 0
    last_err = None
    for attempt in range(1, SLACK_ATTEMPTS + 1):
        attempts = attempt
        try:
            req = Request(webhook_url, data=body,
                          headers={"Content-Type": "application/json"},
                          method="POST")
            with urlopen(req, timeout=SLACK_TIMEOUT_S) as resp:
                code = resp.status
                payload = (resp.read() or b"").decode("utf-8", "replace")
            if 200 <= code < 300 and payload.strip() == "ok":
                return True, attempts, None
            last_err = f"slack http {code}: {payload[:120]}"
            log.warning("slack alert failed (attempt %d): %s", attempt,
                        last_err)
        except Exception as e:  # noqa: BLE001 - best effort by design
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
            log.warning("slack alert failed (attempt %d): %s", attempt,
                        last_err)
        time.sleep(2 ** attempt)
    return False, attempts, last_err


def _dashboard_link() -> str:
    return (os.environ.get("PUBLIC_BASE_URL") or "").rstrip("/")


def dispatch_slack_alerts(db, *, org_id: str, schedule_id: str | None,
                           vcs_repo_id: str | None, scan_id: str,
                           event: str, severity: str, new_count: int,
                           heading: str, subheading: str,
                           findings: list[dict]) -> dict:
    """Send a Slack alert to each registered webhook of the org.

    Same trigger as the webhook/email/telegram path: the caller has already
    decided this event deserves an alert. One ``notifications`` row per
    webhook with ``channel='slack'`` and the masked URL in ``recipient``.
    Returns a small outcome dict for tests/logs.
    """
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    rows = db.execute(
        "SELECT id, webhook_url_enc, label FROM slack_webhooks"
        " WHERE org_id=? ORDER BY id", (org_id,)).fetchall()
    if not rows:
        return {"slacked": False, "reason": "no webhooks"}

    def _record(label, masked, status, attempts, err):
        db.execute(
            "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
            " scan_id, event, severity, new_count, webhook_url, channel,"
            " recipient, status, attempts, response_code, error, payload,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (org_id, schedule_id, vcs_repo_id, scan_id, event, severity,
             new_count, "", "slack", f"{label} {masked}".strip(),
             status, attempts, None, err, "{}", now_iso))

    text = build_slack_text(event, heading, subheading, findings,
                            severity, _dashboard_link())
    sent, failed, skipped = 0, 0, 0
    for r in rows:
        label = r["label"] or ""
        try:
            url = _decrypt(r["webhook_url_enc"])
        except Exception as e:  # noqa: BLE001 - corrupt row must not kill scan
            log.warning("slack webhook %s undecryptable: %s", r["id"], e)
            _record(label, mask_webhook_url(""), "skipped", 0,
                    "stored webhook URL undecryptable")
            skipped += 1
            continue
        masked = mask_webhook_url(url)
        ok, attempts, err = send_slack(url, text)
        _record(label, masked, "sent" if ok else "failed", attempts, err)
        if ok:
            sent += 1
        else:
            failed += 1
    db.commit()
    return {"slacked": sent > 0, "sent": sent, "failed": failed,
            "skipped": skipped, "webhooks": len(rows)}


def get_org_webhooks(org_id: str) -> list[dict]:
    """Webhook rows for an org — masked URLs only, never the secret."""
    db = get_db()
    try:
        out = []
        for r in db.execute(
                "SELECT id, webhook_url_enc, label, created_at"
                " FROM slack_webhooks WHERE org_id=? ORDER BY id",
                (org_id,)).fetchall():
            try:
                masked = mask_webhook_url(_decrypt(r["webhook_url_enc"]))
            except Exception:  # noqa: BLE001 - corrupt row stays listed
                masked = "undecryptable"
            out.append({"id": r["id"], "label": r["label"],
                        "webhook_url_masked": masked,
                        "created_at": r["created_at"]})
        return out
    finally:
        db.close()
