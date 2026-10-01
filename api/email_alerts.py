#!/usr/bin/env python3
"""BraimSec email alerts (SMTP).

Mirrors the webhook alert pipeline: an email fires on the *same* trigger as
a webhook alert (new findings >= severity threshold, or a failed scan), for
the org's registered recipient addresses. There is no new paid service —
the operator points BraimSec at their own SMTP server via environment
variables::

    BRAIMSEC_SMTP_HOST      (required, e.g. smtp.gmail.com)
    BRAIMSEC_SMTP_PORT      (default 587)
    BRAIMSEC_SMTP_USER      (optional; login username)
    BRAIMSEC_SMTP_PASS      (optional; never logged, never stored in the DB)
    BRAIMSEC_SMTP_FROM      (defaults to BRAIMSEC_SMTP_USER)
    BRAIMSEC_SMTP_TLS       ("1"/"0", default "1" -> STARTTLS)

If SMTP is not configured, email alerts are recorded as ``skipped`` in the
``notifications`` table (channel='email') — never silently dropped, never a
crash. Delivery retries 3 times with backoff, exactly like ``send_alert``.

``SMTP`` is imported as a module-level name (``from smtplib import SMTP``)
so tests can monkeypatch ``email_alerts.SMTP`` without touching global
smtplib. ``time.sleep`` is module-level ``time`` for the same reason.
"""

import html as _html
import json
import logging
import os
import re
import time
from email.message import EmailMessage
from smtplib import SMTP

from database import get_db

log = logging.getLogger("braimsec.email_alerts")

EMAIL_ATTEMPTS = 3
EMAIL_TIMEOUT_S = 10.0
MAX_EMAIL_FINDINGS = 10

SEV_AR = {"error": "حرجة", "warning": "متوسطة", "note": "منخفضة"}

# Strict-but-sane address check: local@domain.tld, no spaces, no <>, and
# sane dot placement. This is a gate against typos and header injection,
# not a full RFC 5322 validator.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


# ---------------------------------------------------------------------------
# Configuration + validation
# ---------------------------------------------------------------------------

def smtp_settings() -> dict | None:
    """SMTP settings from the environment, or None when not configured.

    Read at call time (not import time) so tests and reconfigured workers
    pick up changes without a restart of the import graph.
    """
    host = (os.environ.get("BRAIMSEC_SMTP_HOST") or "").strip()
    if not host:
        return None
    try:
        port = int((os.environ.get("BRAIMSEC_SMTP_PORT") or "587").strip())
    except ValueError:
        port = 587
    user = (os.environ.get("BRAIMSEC_SMTP_USER") or "").strip()
    password = os.environ.get("BRAIMSEC_SMTP_PASS") or ""
    from_addr = (os.environ.get("BRAIMSEC_SMTP_FROM") or "").strip() or user
    tls = (os.environ.get("BRAIMSEC_SMTP_TLS") or "1").strip() not in (
        "0", "false", "no")
    return {"host": host, "port": port, "user": user, "password": password,
            "from_addr": from_addr, "tls": tls}


def smtp_configured() -> bool:
    return smtp_settings() is not None


def validate_email(addr: str) -> str:
    """Strict address validation; returns the normalized address.

    Raises ValueError on anything that is not a plausible, header-safe
    email address.
    """
    addr = (addr or "").strip().lower()
    if len(addr) > 254 or not _EMAIL_RE.match(addr):
        raise ValueError(f"invalid email address: {addr!r}"[:80])
    local, _, domain = addr.partition("@")
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise ValueError(f"invalid email address: {addr!r}"[:80])
    if domain.startswith("-") or domain.startswith(".") or ".." in domain:
        raise ValueError(f"invalid email address: {addr!r}"[:80])
    return addr


def _header_safe(value: str) -> str:
    """Collapse whitespace so user-controlled strings can't inject headers."""
    return re.sub(r"\s+", " ", value or "").strip()


# ---------------------------------------------------------------------------
# Message building (Arabic RTL, multipart text+HTML)
# ---------------------------------------------------------------------------

def _sev_ar(sev: str) -> str:
    return SEV_AR.get(sev, sev)


def build_email(event: str, heading: str, subheading: str,
                new_findings: list[dict], highest_severity: str,
                link: str) -> tuple[str, str, str]:
    """Build (subject, text_body, html_body) for an alert event.

    ``heading`` is the short title (schedule name / repo full_name),
    ``subheading`` one extra context line, ``findings`` the top findings
    (already trimmed by the caller), ``link`` the dashboard/API URL.
    """
    heading = _header_safe(heading)
    subheading = _header_safe(subheading)
    link = _header_safe(link)
    if event.endswith(".failed"):
        subject = f"⚠️ BraimSec: فشل الفحص — {heading}"
        text = (f"BraimSec: فشل الفحص «{heading}»\n{subheading}\n\n"
                f"الفحص الآلي توقف بخطأ — راجع التفاصيل في اللوحة."
                + (f"\n{link}" if link else ""))
        html = (
            f'<html dir="rtl" lang="ar"><body style="font-family:sans-serif">'
            f"<h2>⚠️ BraimSec: فشل الفحص</h2>"
            f"<p><b>{_html.escape(heading)}</b></p>"
            f"<p>{_html.escape(subheading)}</p>"
            f"<p>الفحص الآلي توقف بخطأ — راجع التفاصيل في اللوحة.</p>"
            + (f'<p><a href="{_html.escape(link)}">فتح اللوحة</a></p>' if link else "")
            + "</body></html>")
        return subject, text, html

    n = len(new_findings)
    sev = _sev_ar(highest_severity)
    subject = f"🛡️ BraimSec: {n} نتائج جديدة ({sev}) — {heading}"
    rows_txt = "\n".join(
        f"• [{f.get('severity')}] {f.get('rule_id')} — "
        f"{f.get('file')}:{f.get('line')}\n  {(f.get('message') or '')[:200]}"
        for f in new_findings[:MAX_EMAIL_FINDINGS])
    more_txt = (f"\n…و{n - MAX_EMAIL_FINDINGS} أخرى"
                if n > MAX_EMAIL_FINDINGS else "")
    text = (f"BraimSec: {n} نتيجة جديدة (أعلى خطورة: {sev}) في «{heading}»\n"
            f"{subheading}\n\n{rows_txt}{more_txt}\n"
            + (f"\nرابط الفحص: {link}" if link else ""))
    rows_html = "".join(
        f"<tr><td>{_html.escape(str(f.get('severity')))}</td>"
        f"<td><code>{_html.escape(str(f.get('rule_id')))}</code></td>"
        f"<td><code>{_html.escape(str(f.get('file')))}:"
        f"{_html.escape(str(f.get('line')))}</code></td>"
        f"<td>{_html.escape((f.get('message') or '')[:200])}</td></tr>"
        for f in new_findings[:MAX_EMAIL_FINDINGS])
    more_html = (f"<p>…و{n - MAX_EMAIL_FINDINGS} أخرى</p>"
                 if n > MAX_EMAIL_FINDINGS else "")
    html = (
        f'<html dir="rtl" lang="ar"><body style="font-family:sans-serif">'
        f"<h2>🛡️ BraimSec: نتائج جديدة</h2>"
        f"<p><b>{_html.escape(heading)}</b> — {n} نتيجة جديدة "
        f"(أعلى خطورة: {_html.escape(sev)})</p>"
        f"<p>{_html.escape(subheading)}</p>"
        f'<table border="1" cellpadding="6" cellspacing="0" '
        f'style="border-collapse:collapse">'
        f"<tr><th>الخطورة</th><th>القاعدة</th><th>الموقع</th>"
        f"<th>الوصف</th></tr>{rows_html}</table>{more_html}"
        + (f'<p><a href="{_html.escape(link)}">فتح اللوحة</a></p>' if link else "")
        + "</body></html>")
    return subject, text, html


# ---------------------------------------------------------------------------
# Delivery (retried, recorded)
# ---------------------------------------------------------------------------

def send_email(to_addr: str, subject: str, text_body: str,
               html_body: str,
               attachments: list[tuple[str, bytes, str]] | None = None
               ) -> tuple[bool, int, str | None]:
    """Send one message; returns (ok, attempts, error).

    ``attachments`` is an optional list of (filename, data, mime_type)
    tuples, e.g. the executive-report PDF. Best-effort by design (mirrors
    send_alert): exceptions are caught and retried, never raised. The SMTP
    password is never included in the returned error or any log line.
    """
    cfg = smtp_settings()
    if not cfg:
        return False, 0, "SMTP not configured"
    if not cfg["from_addr"]:
        return False, 0, "BRAIMSEC_SMTP_FROM (or USER) is required"
    msg = EmailMessage()
    msg["From"] = cfg["from_addr"]
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["X-BraimSec-Event"] = "alert"
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    for filename, data, mime_type in (attachments or []):
        maintype, _, subtype = (mime_type or "application/octet-stream").partition("/")
        msg.add_attachment(data, maintype=maintype or "application",
                           subtype=subtype or "octet-stream",
                           filename=_header_safe(filename) or "attachment")
    attempts = 0
    last_err = None
    for attempt in range(1, EMAIL_ATTEMPTS + 1):
        attempts = attempt
        server = None
        try:
            server = SMTP(cfg["host"], cfg["port"], timeout=EMAIL_TIMEOUT_S)
            if cfg["tls"]:
                server.starttls()
            if cfg["user"]:
                server.login(cfg["user"], cfg["password"])
            server.send_message(msg)
            return True, attempts, None
        except Exception as e:  # noqa: BLE001 - best effort by design
            last_err = re.sub(r"(?i)(pass\w*|pwd|secret|token)\S*",
                              "[redacted]", str(e))[:200]
            log.warning("email alert to %s failed (attempt %d): %s",
                        to_addr, attempt, last_err)
        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:  # noqa: BLE001 - quit is best-effort
                    pass
        time.sleep(2 ** attempt)
    return False, attempts, last_err


def _dashboard_link() -> str:
    return (os.environ.get("PUBLIC_BASE_URL") or "").rstrip("/")


def dispatch_email_alerts(db, *, org_id: str, schedule_id: str | None,
                          vcs_repo_id: str | None, scan_id: str,
                          event: str, severity: str, new_count: int,
                          heading: str, subheading: str,
                          findings: list[dict]) -> dict:
    """Send an alert email to each enabled recipient of the org.

    Same trigger as the webhook path: the caller has already decided this
    event deserves an alert. One ``notifications`` row per recipient with
    ``channel='email'``. Returns a small outcome dict for tests/logs.
    """
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    recipients = [r["email"] for r in db.execute(
        "SELECT email FROM alert_emails WHERE org_id=? AND enabled=1"
        " ORDER BY email", (org_id,)).fetchall()]
    if not recipients:
        return {"emailed": False, "reason": "no recipients"}
    if not smtp_configured():
        for rcpt in recipients:
            db.execute(
                "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
                " scan_id, event, severity, new_count, webhook_url, channel,"
                " recipient, status, attempts, response_code, error, payload,"
                " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (org_id, schedule_id, vcs_repo_id, scan_id, event, severity,
                 new_count, "", "email", rcpt, "skipped", 0, None,
                 "SMTP not configured: set BRAIMSEC_SMTP_HOST (and friends)",
                 "{}", now_iso))
        db.commit()
        return {"emailed": False, "reason": "smtp not configured",
                "recipients": len(recipients)}
    subject, text_body, html_body = build_email(
        event, heading, subheading, findings, severity, _dashboard_link())
    sent, failed = 0, 0
    for rcpt in recipients:
        ok, attempts, err = send_email(rcpt, subject, text_body, html_body)
        db.execute(
            "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
            " scan_id, event, severity, new_count, webhook_url, channel,"
            " recipient, status, attempts, response_code, error, payload,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (org_id, schedule_id, vcs_repo_id, scan_id, event, severity,
             new_count, "", "email", rcpt, "sent" if ok else "failed",
             attempts, None, err,
             '{"subject": %s}' % json.dumps(subject, ensure_ascii=False),
             now_iso))
        if ok:
            sent += 1
        else:
            failed += 1
    db.commit()
    return {"emailed": sent > 0, "sent": sent, "failed": failed,
            "recipients": len(recipients)}


def get_org_emails(org_id: str) -> list[dict]:
    """All recipient rows for an org (for the management API)."""
    db = get_db()
    try:
        return [dict(r) for r in db.execute(
            "SELECT id, email, enabled, created_at FROM alert_emails"
            " WHERE org_id=? ORDER BY email", (org_id,)).fetchall()]
    finally:
        db.close()


def dispatch_report_emails(db, *, org_id: str, report_schedule_id: str,
                           scan_id: str, subject: str, text_body: str,
                           html_body: str, pdf_bytes: bytes, filename: str,
                           severity: str) -> dict:
    """Email a scheduled executive report (PDF attachment) to the org.

    Mirrors :func:`dispatch_email_alerts`: one ``notifications`` row per
    recipient with ``channel='email_report'`` and the report schedule id.
    No SMTP configured -> every recipient is recorded as ``skipped``,
    never silently dropped. Returns a small outcome dict.
    """
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    recipients = [r["email"] for r in db.execute(
        "SELECT email FROM alert_emails WHERE org_id=? AND enabled=1"
        " ORDER BY email", (org_id,)).fetchall()]
    if not recipients:
        return {"emailed": False, "reason": "no recipients"}
    if not smtp_configured():
        for rcpt in recipients:
            db.execute(
                "INSERT INTO notifications (org_id, schedule_id,"
                " report_schedule_id, vcs_repo_id, scan_id, event, severity,"
                " new_count, webhook_url, channel, recipient, status,"
                " attempts, response_code, error, payload, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (org_id, None, report_schedule_id, None, scan_id,
                 "report.scheduled", severity, 0, "", "email_report", rcpt,
                 "skipped", 0, None,
                 "SMTP not configured: set BRAIMSEC_SMTP_HOST (and friends)",
                 "{}", now_iso))
        db.commit()
        return {"emailed": False, "reason": "smtp not configured",
                "recipients": len(recipients)}
    sent, failed = 0, 0
    for rcpt in recipients:
        ok, attempts, err = send_email(
            rcpt, subject, text_body, html_body,
            attachments=[(filename, pdf_bytes, "application/pdf")])
        db.execute(
            "INSERT INTO notifications (org_id, schedule_id,"
            " report_schedule_id, vcs_repo_id, scan_id, event, severity,"
            " new_count, webhook_url, channel, recipient, status,"
            " attempts, response_code, error, payload, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (org_id, None, report_schedule_id, None, scan_id,
             "report.scheduled", severity, 0, "", "email_report", rcpt,
             "sent" if ok else "failed", attempts, None, err,
             '{"subject": %s}' % json.dumps(subject, ensure_ascii=False),
             now_iso))
        if ok:
            sent += 1
        else:
            failed += 1
    db.commit()
    return {"emailed": sent > 0, "sent": sent, "failed": failed,
            "recipients": len(recipients)}
