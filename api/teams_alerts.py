"""BraimSec Microsoft Teams alerts (Incoming Webhooks).

The fifth alert channel, twin of webhooks/email/telegram/slack: a Teams
message fires on the *same* trigger (new findings >= severity threshold, or
a failed scan), for the org's registered incoming-webhook URLs.

Each org registers its own webhook URL (Teams channel -> *Connectors* ->
*Incoming Webhook*, or a Power Automate *When a Teams webhook request is
received* flow); the URL is a bearer credential, so it is stored
**Fernet-encrypted at rest** (same scheme as VCS webhook secrets in
``vcs.py``, key derived from ``BRAIMSEC_API_KEY``) and never logged, never
returned by the API — the list endpoint only shows a masked form.

The message is a MessageCard (themeColor reflects severity), so it renders
natively in Teams. Only Microsoft webhook hosts are accepted at
registration (guard against SSRF): ``*.office.com`` (classic connectors)
and ``*.logic.azure.com`` (Power Automate workflows).

``urlopen`` is module-level so tests can monkeypatch
``teams_alerts.urlopen``; ``time.sleep`` is module-level ``time``.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from urllib.request import Request, urlopen

from database import get_db

log = logging.getLogger("braimsec.teams_alerts")

TEAMS_ATTEMPTS = 3
TEAMS_TIMEOUT_S = 10.0
MAX_MESSAGE_CHARS = 3000
MAX_TEAMS_FINDINGS = 5

SEV_AR = {"error": "حرجة", "warning": "متوسطة", "note": "منخفضة"}
SEV_COLOR = {"error": "FF0000", "warning": "FF8C00", "note": "FFC000"}

# Only Microsoft webhook hosts — anything else is rejected at registration.
_WEBHOOK_RE = re.compile(
    r"^https://[A-Za-z0-9.-]+\.(office\.com|logic\.azure\.com)(:\d+)?/\S{10,}$")


# ---------------------------------------------------------------------------
# Validation + secret handling
# ---------------------------------------------------------------------------

def validate_webhook_url(value) -> str:
    """Validate a Teams incoming-webhook URL; returns it stripped.

    Raises ValueError on anything that is not a Microsoft webhook host.
    """
    s = str(value or "").strip()
    if not _WEBHOOK_RE.match(s):
        raise ValueError(
            "invalid Teams webhook URL: must be an Incoming Webhook URL on"
            " *.office.com or *.logic.azure.com")
    return s


def mask_webhook_url(url: str) -> str:
    """Non-reversible masked display form for API responses."""
    m = re.match(r"^(https://[^/]+)/", url or "")
    host = m.group(1) if m else "https://…"
    return f"{host}/…{(url or '')[-6:]}"


def _encrypt(raw: str) -> str:
    from vcs import encrypt_secret  # noqa: E402  (deferred: light import graph)
    return encrypt_secret(raw)


def _decrypt(enc: str) -> str:
    from vcs import decrypt_secret  # noqa: E402
    return decrypt_secret(enc)


# ---------------------------------------------------------------------------
# Message building (MessageCard, short Arabic text)
# ---------------------------------------------------------------------------

def _sev_ar(sev: str) -> str:
    return SEV_AR.get(sev, sev)


def _sev_color(sev: str) -> str:
    return SEV_COLOR.get(sev, "0078D4")


def build_teams_card(event: str, heading: str, subheading: str,
                     new_findings: list[dict], highest_severity: str,
                     link: str) -> dict:
    """Build a Teams MessageCard (text kept <= MAX_MESSAGE_CHARS)."""
    heading = re.sub(r"\s+", " ", heading or "").strip()
    subheading = re.sub(r"\s+", " ", subheading or "").strip()
    link = re.sub(r"\s+", " ", link or "").strip()
    if event.endswith(".failed"):
        title = "⚠️ BraimSec: فشل الفحص"
        text = (f"**{heading}**\n\n{subheading}\n\n"
                f"الفحص الآلي توقف بخطأ — راجع التفاصيل في اللوحة.")
        color = _sev_color("error")
    else:
        n = len(new_findings)
        sev = _sev_ar(highest_severity)
        title = f"🛡️ BraimSec: {n} نتيجة جديدة ({sev})"
        lines = [f"**{heading}**", "", subheading, ""]
        for f in new_findings[:MAX_TEAMS_FINDINGS]:
            msg = re.sub(r"\s+", " ", str(f.get("message") or "")
                         ).strip()[:120]
            lines.append(f"• **[{f.get('severity')}]** {f.get('rule_id')} — "
                         f"`{f.get('file')}:{f.get('line')}`")
            if msg:
                lines.append(f"  {msg}")
        if n > MAX_TEAMS_FINDINGS:
            lines.append(f"…و{n - MAX_TEAMS_FINDINGS} أخرى")
        text = "\n\n".join(lines)
        color = _sev_color(highest_severity)
    if link:
        text += f"\n\n[فتح اللوحة]({link})"
    text = text[:MAX_MESSAGE_CHARS]
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": title,
        "sections": [{"activityTitle": title, "text": text,
                      "markdown": True}],
    }


# ---------------------------------------------------------------------------
# Delivery (retried, recorded)
# ---------------------------------------------------------------------------

def send_teams(webhook_url: str, card: dict) -> tuple[bool, int, str | None]:
    """POST one MessageCard to an incoming webhook.

    Returns (ok, attempts, error). Best-effort by design: exceptions are
    caught and retried, never raised. The webhook URL never appears in the
    returned error or any log line. Any 2xx counts as delivered (workflow
    webhooks answer 202 with an empty body; classic connectors 200/"1").
    """
    body = json.dumps(card, ensure_ascii=False).encode("utf-8")
    attempts = 0
    last_err = None
    for attempt in range(1, TEAMS_ATTEMPTS + 1):
        attempts = attempt
        try:
            req = Request(webhook_url, data=body,
                          headers={"Content-Type": "application/json"},
                          method="POST")
            with urlopen(req, timeout=TEAMS_TIMEOUT_S) as resp:
                code = resp.status
            if 200 <= code < 300:
                return True, attempts, None
            last_err = f"teams http {code}"
            log.warning("teams alert failed (attempt %d): %s", attempt,
                        last_err)
        except Exception as e:  # noqa: BLE001 - best effort by design
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
            log.warning("teams alert failed (attempt %d): %s", attempt,
                        last_err)
        time.sleep(2 ** attempt)
    return False, attempts, last_err


def _dashboard_link() -> str:
    return (os.environ.get("PUBLIC_BASE_URL") or "").rstrip("/")


def dispatch_teams_alerts(db, *, org_id: str, schedule_id: str | None,
                          vcs_repo_id: str | None, scan_id: str,
                          event: str, severity: str, new_count: int,
                          heading: str, subheading: str,
                          findings: list[dict]) -> dict:
    """Send a Teams alert to each registered webhook of the org.

    Same trigger as the webhook/email/telegram/slack path: the caller has
    already decided this event deserves an alert. One ``notifications`` row
    per webhook with ``channel='teams'`` and the masked URL in
    ``recipient``. Returns a small outcome dict for tests/logs.
    """
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    rows = db.execute(
        "SELECT id, webhook_url_enc, label FROM teams_webhooks"
        " WHERE org_id=? ORDER BY id", (org_id,)).fetchall()
    if not rows:
        return {"teamsed": False, "reason": "no webhooks"}

    def _record(label, masked, status, attempts, err):
        db.execute(
            "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
            " scan_id, event, severity, new_count, webhook_url, channel,"
            " recipient, status, attempts, response_code, error, payload,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (org_id, schedule_id, vcs_repo_id, scan_id, event, severity,
             new_count, "", "teams", f"{label} {masked}".strip(),
             status, attempts, None, err, "{}", now_iso))

    card = build_teams_card(event, heading, subheading, findings,
                            severity, _dashboard_link())
    sent, failed, skipped = 0, 0, 0
    for r in rows:
        label = r["label"] or ""
        try:
            url = _decrypt(r["webhook_url_enc"])
        except Exception as e:  # noqa: BLE001 - corrupt row must not kill scan
            log.warning("teams webhook %s undecryptable: %s", r["id"], e)
            _record(label, mask_webhook_url(""), "skipped", 0,
                    "stored webhook URL undecryptable")
            skipped += 1
            continue
        masked = mask_webhook_url(url)
        ok, attempts, err = send_teams(url, card)
        _record(label, masked, "sent" if ok else "failed", attempts, err)
        if ok:
            sent += 1
        else:
            failed += 1
    db.commit()
    return {"teamsed": sent > 0, "sent": sent, "failed": failed,
            "skipped": skipped, "webhooks": len(rows)}


def get_org_webhooks(org_id: str) -> list[dict]:
    """Webhook rows for an org — masked URLs only, never the secret."""
    db = get_db()
    try:
        out = []
        for r in db.execute(
                "SELECT id, webhook_url_enc, label, created_at"
                " FROM teams_webhooks WHERE org_id=? ORDER BY id",
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
