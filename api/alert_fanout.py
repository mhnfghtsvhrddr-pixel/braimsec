"""Shared fan-out for monitor alerts (TLS expiry, uptime, ...).

Every monitor alert goes through one code path: it is delivered to each
channel the org configured and each delivery is recorded in the
notifications log. Channel semantics are identical for all monitors:

- webhook: the exact JSON payload, HMAC-signed via scheduler.send_alert
  (resend replays the stored payload verbatim).
- telegram / slack / teams / email: human-readable texts built from the
  payload by the monitor's registered text builder, so the resend flow can
  rebuild a faithful message from the stored payload alone.
"""

import json
import logging
import time

log = logging.getLogger("braimsec.fanout")

# event -> fn(payload_dict) -> texts dict. Registered by monitor modules at
# import time. texts keys: telegram, slack, email_subject, email_text,
# email_html, teams_title, teams_facts (list of (name, value)).
_BUILDERS = {}


def register_text_builder(event: str, fn):
    _BUILDERS[event] = fn


def build_texts(event: str, payload: dict) -> dict:
    try:
        return _BUILDERS[event](payload)
    except KeyError:
        raise ValueError(f"no text builder registered for {event!r}")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def record(db, org_id: str, *, event: str, scan_id: str, severity: str,
           count: int, webhook_url: str, channel: str, recipient: str,
           status: str, attempts: int, error: str | None,
           payload: dict):
    db.execute(
        "INSERT INTO notifications (org_id, scan_id, event, severity,"
        " new_count, webhook_url, channel, recipient, status, attempts,"
        " response_code, error, payload, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (org_id, scan_id, event, severity, count, webhook_url or "",
         channel, recipient, status, attempts, None, error,
         json.dumps(payload, ensure_ascii=False), _now_iso()))


def fan_out(db, org_id: str, *, event: str, scan_id: str, severity: str,
            count: int, webhook_url: str, payload: dict):
    """Deliver a monitor alert on every channel the org configured.

    ``payload`` is the exact JSON sent to webhook URLs (and replayed by
    resend); human texts are derived from it via the registered builder.
    Never raises: a broken channel must not kill the others.
    """
    from scheduler import send_alert  # noqa: E402
    from telegram_alerts import send_telegram  # noqa: E402
    from slack_alerts import _decrypt as _decrypt_slack, send_slack  # noqa: E402
    from teams_alerts import _decrypt as _decrypt_teams, send_teams  # noqa: E402
    from email_alerts import send_email  # noqa: E402

    texts = build_texts(event, payload)

    def _rec(channel, recipient, status, attempts, err):
        try:
            record(db, org_id, event=event, scan_id=scan_id,
                   severity=severity, count=count, webhook_url=webhook_url,
                   channel=channel, recipient=recipient, status=status,
                   attempts=attempts, error=err, payload=payload)
        except Exception:  # noqa: BLE001 - recording must not kill fan-out
            log.exception("failed to record %s notification", channel)

    # 1) the target's own webhook URL
    if webhook_url:
        try:
            ok, attempts, _code, err = send_alert(webhook_url, payload,
                                                  org_id=org_id)
        except Exception as e:  # noqa: BLE001 - sender must not raise
            ok, attempts, err = False, 0, f"{type(e).__name__}: {e}"
        _rec("webhook", "", "sent" if ok else "failed", attempts, err)

    # 2) telegram chats
    for r in db.execute("SELECT chat_id FROM telegram_chats WHERE org_id=?",
                        (org_id,)).fetchall():
        try:
            ok, attempts, err = send_telegram(r["chat_id"], texts["telegram"])
        except Exception as e:  # noqa: BLE001
            ok, attempts, err = False, 0, f"{type(e).__name__}: {e}"
        _rec("telegram", r["chat_id"], "sent" if ok else "failed",
             attempts, err)

    # 3) slack webhooks
    for r in db.execute("SELECT webhook_url_enc, label FROM slack_webhooks"
                        " WHERE org_id=?", (org_id,)).fetchall():
        try:
            url = _decrypt_slack(r["webhook_url_enc"])
        except Exception as e:  # noqa: BLE001 - corrupt row stays listed
            log.warning("slack webhook undecryptable: %s", e)
            _rec("slack", r["label"] or "", "skipped", 0,
                 "stored webhook URL undecryptable")
            continue
        try:
            ok, attempts, err = send_slack(url, texts["slack"])
        except Exception as e:  # noqa: BLE001
            ok, attempts, err = False, 0, f"{type(e).__name__}: {e}"
        _rec("slack", r["label"] or "", "sent" if ok else "failed",
             attempts, err)

    # 4) teams webhooks
    for r in db.execute("SELECT webhook_url_enc, label FROM teams_webhooks"
                        " WHERE org_id=?", (org_id,)).fetchall():
        try:
            url = _decrypt_teams(r["webhook_url_enc"])
        except Exception as e:  # noqa: BLE001 - corrupt row stays listed
            log.warning("teams webhook undecryptable: %s", e)
            _rec("teams", r["label"] or "", "skipped", 0,
                 "stored webhook URL undecryptable")
            continue
        card = {"@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "FF0000" if severity in ("critical", "high")
                else "2E9BFF",
                "summary": texts["teams_title"],
                "sections": [{
                    "activityTitle": texts["teams_title"],
                    "facts": [{"name": n, "value": v}
                              for n, v in texts.get("teams_facts", [])],
                    "markdown": True}]}
        try:
            ok, attempts, err = send_teams(url, card)
        except Exception as e:  # noqa: BLE001
            ok, attempts, err = False, 0, f"{type(e).__name__}: {e}"
        _rec("teams", r["label"] or "", "sent" if ok else "failed",
             attempts, err)

    # 5) email recipients
    for r in db.execute("SELECT email FROM alert_emails"
                        " WHERE org_id=? AND enabled=1", (org_id,)).fetchall():
        try:
            ok, attempts, err = send_email(
                r["email"], texts["email_subject"], texts["email_text"],
                texts.get("email_html"))
        except Exception as e:  # noqa: BLE001
            ok, attempts, err = False, 0, f"{type(e).__name__}: {e}"
        _rec("email", r["email"], "sent" if ok else "failed", attempts, err)

    db.commit()
