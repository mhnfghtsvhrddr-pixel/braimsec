#!/usr/bin/env python3
"""BraimSec Telegram alerts (Bot API).

The third alert channel, twin of webhooks and email: a Telegram message
fires on the *same* trigger (new findings >= severity threshold, or a failed
scan), for the org's registered chat ids. There is no new paid service —
the operator creates one bot via @BotFather and points BraimSec at it::

    BRAIMSEC_TELEGRAM_BOT_TOKEN   (required, e.g. 123456:ABC-DEF...)

If the token is not configured, Telegram alerts are recorded as ``skipped``
in the ``notifications`` table (channel='telegram') — never silently
dropped, never a crash. Delivery retries 3 times with backoff. The token
is never logged and never stored in the DB (only chat ids are).

``urlopen`` is imported as a module-level name (``from urllib.request import
urlopen``) so tests can monkeypatch ``telegram_alerts.urlopen`` without
touching global urllib. ``time.sleep`` is module-level ``time`` for the
same reason.

Setup for an org owner (one-time):
  1. Talk to @BotFather on Telegram -> /newbot -> copy the token.
  2. Set BRAIMSEC_TELEGRAM_BOT_TOKEN on the BraimSec server and restart
     the API/worker.
  3. Message the new bot once from the account/group that should receive
     alerts (a bot cannot message you first).
  4. Find the chat id: open
     https://api.telegram.org/bot<token>/getUpdates in a browser and read
     ``message.chat.id`` (negative for groups).
  5. POST /api/telegram-chats {"chat_id": "<id>", "label": "on-call"}
     with a member+ API key. Alerts start flowing on the next trigger.
"""

import json
import logging
import os
import re
import time
from urllib.request import Request, urlopen

from database import get_db

log = logging.getLogger("braimsec.telegram_alerts")

TELEGRAM_ATTEMPTS = 3
TELEGRAM_TIMEOUT_S = 10.0
MAX_MESSAGE_CHARS = 4000
MAX_TG_FINDINGS = 5

SEV_AR = {"error": "حرجة", "warning": "متوسطة", "note": "منخفضة"}

# Telegram chat ids are integers; group/supergroup ids are negative.
_CHAT_RE = re.compile(r"^-?\d{1,20}$")


# ---------------------------------------------------------------------------
# Configuration + validation
# ---------------------------------------------------------------------------

def bot_token() -> str | None:
    """Bot token from the environment, or None when not configured.

    Read at call time (not import time) so tests and reconfigured workers
    pick up changes without a restart of the import graph.
    """
    tok = (os.environ.get("BRAIMSEC_TELEGRAM_BOT_TOKEN") or "").strip()
    return tok or None


def telegram_configured() -> bool:
    return bot_token() is not None


def validate_chat_id(value) -> str:
    """Validate a Telegram chat id; returns the normalized string form.

    Raises ValueError on anything that is not a plausible integer chat id.
    """
    s = str(value or "").strip()
    if not _CHAT_RE.match(s):
        raise ValueError(f"invalid telegram chat id: {s!r}"[:80])
    if len(s.lstrip("-")) > 1 and s.lstrip("-").startswith("0"):
        raise ValueError(f"invalid telegram chat id: {s!r}"[:80])
    return s


def _api_url(token: str) -> str:
    return f"https://api.telegram.org/bot{token}/sendMessage"


def _redact_token(text: str, token: str) -> str:
    """Strip the bot token from an error string before logging/storing."""
    if not text:
        return text
    out = text.replace(token, "[redacted]")
    # Belt and braces: Bot API tokens look like 123456:AAH... — nuke any
    # residual token-shaped substring that survived the direct replace.
    out = re.sub(r"\b\d{5,}:[A-Za-z0-9_-]{20,}\b", "[redacted]", out)
    return out[:200]


# ---------------------------------------------------------------------------
# Message building (short Arabic plain text)
# ---------------------------------------------------------------------------

def _sev_ar(sev: str) -> str:
    return SEV_AR.get(sev, sev)


def build_telegram_message(event: str, heading: str, subheading: str,
                           new_findings: list[dict], highest_severity: str,
                           link: str) -> str:
    """Build the short Arabic alert text (<= MAX_MESSAGE_CHARS)."""
    heading = re.sub(r"\s+", " ", heading or "").strip()
    subheading = re.sub(r"\s+", " ", subheading or "").strip()
    link = re.sub(r"\s+", " ", link or "").strip()
    if event.endswith(".failed"):
        text = (f"⚠️ BraimSec: فشل الفحص\n«{heading}»\n{subheading}\n\n"
                f"الفحص الآلي توقف بخطأ — راجع التفاصيل في اللوحة."
                + (f"\n{link}" if link else ""))
        return text[:MAX_MESSAGE_CHARS]

    n = len(new_findings)
    sev = _sev_ar(highest_severity)
    lines = [f"🛡️ BraimSec: {n} نتيجة جديدة ({sev})",
             f"«{heading}»",
             subheading, ""]
    for f in new_findings[:MAX_TG_FINDINGS]:
        msg = re.sub(r"\s+", " ", str(f.get("message") or "")).strip()[:120]
        lines.append(f"• [{f.get('severity')}] {f.get('rule_id')} — "
                     f"{f.get('file')}:{f.get('line')}")
        if msg:
            lines.append(f"  {msg}")
    if n > MAX_TG_FINDINGS:
        lines.append(f"…و{n - MAX_TG_FINDINGS} أخرى")
    if link:
        lines += ["", link]
    return "\n".join(lines)[:MAX_MESSAGE_CHARS]


# ---------------------------------------------------------------------------
# Delivery (retried, recorded)
# ---------------------------------------------------------------------------

def send_telegram(chat_id: str, text: str) -> tuple[bool, int, str | None]:
    """Send one message; returns (ok, attempts, error).

    Best-effort by design (mirrors send_alert): exceptions are caught and
    retried, never raised. The bot token is never included in the returned
    error or any log line.
    """
    token = bot_token()
    if not token:
        return False, 0, "Telegram bot token not configured"
    body = json.dumps({"chat_id": int(chat_id), "text": text,
                       "disable_web_page_preview": True}).encode("utf-8")
    attempts = 0
    last_err = None
    for attempt in range(1, TELEGRAM_ATTEMPTS + 1):
        attempts = attempt
        try:
            req = Request(_api_url(token), data=body,
                          headers={"Content-Type": "application/json"},
                          method="POST")
            with urlopen(req, timeout=TELEGRAM_TIMEOUT_S) as resp:
                payload = json.loads(resp.read().decode("utf-8") or "{}")
            if payload.get("ok"):
                return True, attempts, None
            desc = str(payload.get("description") or "telegram api error")
            last_err = _redact_token(desc, token)
            log.warning("telegram alert to chat %s failed (attempt %d): %s",
                        chat_id, attempt, last_err)
        except Exception as e:  # noqa: BLE001 - best effort by design
            last_err = _redact_token(str(e), token)
            log.warning("telegram alert to chat %s failed (attempt %d): %s",
                        chat_id, attempt, last_err)
        time.sleep(2 ** attempt)
    return False, attempts, last_err


def _dashboard_link() -> str:
    return (os.environ.get("PUBLIC_BASE_URL") or "").rstrip("/")


def dispatch_telegram_alerts(db, *, org_id: str, schedule_id: str | None,
                             vcs_repo_id: str | None, scan_id: str,
                             event: str, severity: str, new_count: int,
                             heading: str, subheading: str,
                             findings: list[dict]) -> dict:
    """Send a Telegram alert to each registered chat of the org.

    Same trigger as the webhook/email path: the caller has already decided
    this event deserves an alert. One ``notifications`` row per chat with
    ``channel='telegram'`` and the chat id in ``recipient``. Returns a small
    outcome dict for tests/logs.
    """
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    chats = [r["chat_id"] for r in db.execute(
        "SELECT chat_id FROM telegram_chats WHERE org_id=?"
        " ORDER BY chat_id", (org_id,)).fetchall()]
    if not chats:
        return {"telegrammed": False, "reason": "no chats"}
    if not telegram_configured():
        for chat_id in chats:
            db.execute(
                "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
                " scan_id, event, severity, new_count, webhook_url, channel,"
                " recipient, status, attempts, response_code, error, payload,"
                " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (org_id, schedule_id, vcs_repo_id, scan_id, event, severity,
                 new_count, "", "telegram", chat_id, "skipped", 0, None,
                 "Telegram not configured: set BRAIMSEC_TELEGRAM_BOT_TOKEN",
                 "{}", now_iso))
        db.commit()
        return {"telegrammed": False, "reason": "telegram not configured",
                "chats": len(chats)}
    text = build_telegram_message(event, heading, subheading, findings,
                                  severity, _dashboard_link())
    sent, failed = 0, 0
    for chat_id in chats:
        ok, attempts, err = send_telegram(chat_id, text)
        db.execute(
            "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
            " scan_id, event, severity, new_count, webhook_url, channel,"
            " recipient, status, attempts, response_code, error, payload,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (org_id, schedule_id, vcs_repo_id, scan_id, event, severity,
             new_count, "", "telegram", chat_id, "sent" if ok else "failed",
             attempts, None, err, "{}", now_iso))
        if ok:
            sent += 1
        else:
            failed += 1
    db.commit()
    return {"telegrammed": sent > 0, "sent": sent, "failed": failed,
            "chats": len(chats)}


def get_org_chats(org_id: str) -> list[dict]:
    """All chat rows for an org (for the management API)."""
    db = get_db()
    try:
        return [dict(r) for r in db.execute(
            "SELECT id, chat_id, label, created_at FROM telegram_chats"
            " WHERE org_id=? ORDER BY chat_id", (org_id,)).fetchall()]
    finally:
        db.close()
