"""Tests for POST /api/notifications/{id}/resend.

- webhook rows replay their stored payload exactly
- telegram/email rows rebuild the message from the scan's findings
- slack/teams -> 409 (masked destination), sent/skipped -> 409
- 404 for unknown id / other org's row, 403 for viewers, 422 for bad id
- row updated in place + notification.resent audit event
"""
import json
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-resend-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-resend-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import scheduler  # noqa: E402
import telegram_alerts  # noqa: E402
import email_alerts  # noqa: E402
from billing import (create_org, ensure_owner_org, provision_key,  # noqa: E402
                     seed_plans)
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


def _notif(db, org, channel, status, **kw):
    base = {"org_id": org, "schedule_id": None, "vcs_repo_id": None,
            "scan_id": kw.get("scan_id", "scan-rs1"), "event": "schedule.alert",
            "severity": "high", "new_count": 2,
            "webhook_url": "", "channel": channel, "recipient": "",
            "status": status, "attempts": 1, "response_code": 500,
            "error": "boom", "payload": "{}",
            "created_at": "2026-10-02T00:00:00+00:00"}
    base.update(kw)
    cur = db.execute(
        "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
        " scan_id, event, severity, new_count, webhook_url, channel,"
        " recipient, status, attempts, response_code, error, payload,"
        " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        tuple(base[c] for c in
              ["org_id", "schedule_id", "vcs_repo_id", "scan_id", "event",
               "severity", "new_count", "webhook_url", "channel",
               "recipient", "status", "attempts", "response_code", "error",
               "payload", "created_at"]))
    db.commit()
    return cur.lastrowid


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = os.urandom(4).hex()
    org = create_org(f"ResendCo_{uid}", plan="free")
    other = create_org(f"ResendOther_{uid}", plan="free")
    member = provision_key(org, "rs-member", actor="owner", role="member")
    viewer = provision_key(org, "rs-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "rs-o-member", actor="owner",
                             role="member")
    db = get_db()
    sched_id = f"sched-rs-{uid}"
    scan_id = f"scan-rs1-{uid}"
    db.execute("INSERT INTO schedules (id, org_id, name, target_path,"
               " frequency, webhook_url, next_run_at, created_at)"
               " VALUES (?,?,?,?,?,?,?,?)",
               (sched_id, org, "Nightly", "/tmp", "daily", "",
                "2026-10-03T02:00:00+00:00", "2026-10-02T00:00:00+00:00"))
    db.execute("INSERT INTO findings (scan_id, tool, rule_id, severity,"
               " message, file, line) VALUES (?,?,?,?,?,?,?)",
               (scan_id, "semgrep", "py-exec", "critical",
                "os.system sink", "app.py", 10))
    db.execute("INSERT INTO findings (scan_id, tool, rule_id, severity,"
               " message, file, line) VALUES (?,?,?,?,?,?,?)",
               (scan_id, "semgrep", "py-xss", "medium",
                "xss sink", "view.py", 3))
    nid_wh = _notif(db, org, "webhook", "failed",
                    webhook_url="https://hooks.example/x",
                    payload=json.dumps({"alert": "new", "n": 2},
                                       ensure_ascii=False))
    nid_wh_ok = _notif(db, org, "webhook", "failed",
                       webhook_url="https://hooks.example/y",
                       payload='{"alert": "new"}')
    nid_tg = _notif(db, org, "telegram", "failed", recipient="12345",
                    schedule_id=sched_id, scan_id=scan_id)
    nid_em = _notif(db, org, "email", "failed",
                    recipient="ops@example.com", scan_id=scan_id)
    nid_slack = _notif(db, org, "slack", "failed",
                       recipient="ops ••••1234")
    nid_sent = _notif(db, org, "webhook", "sent",
                      webhook_url="https://hooks.example/z")
    nid_skip = _notif(db, org, "email", "skipped",
                      recipient="ops@example.com")
    nid_other = _notif(db, other, "webhook", "failed",
                       webhook_url="https://hooks.example/o")
    db.close()
    return {"org": org, "other": other, "member": member, "viewer": viewer,
            "o_member": o_member, "wh": nid_wh, "wh_ok": nid_wh_ok,
            "tg": nid_tg, "em": nid_em, "slack": nid_slack,
            "sent": nid_sent, "skip": nid_skip, "other": nid_other}


def _post(c, key, nid):
    return c.post(f"/api/notifications/{nid}/resend",
                  headers={"X-API-Key": key})


def _row(nid):
    db = get_db()
    r = dict(db.execute("SELECT * FROM notifications WHERE id=?",
                        (nid,)).fetchone())
    db.close()
    return r


def _audit(org, action):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM audit_log WHERE org_id=? AND action=?",
        (org, action)).fetchall()
    db.close()
    return [dict(r) for r in rows]


def test_webhook_resend_replays_stored_payload(ctx, monkeypatch):
    c = TestClient(main.app)
    seen = {}

    def fake(url, payload, org_id=None):
        seen.update(url=url, payload=payload, org_id=org_id)
        return (True, 1, 200, None)

    monkeypatch.setattr(scheduler, "send_alert", fake)
    r = _post(c, ctx["member"], ctx["wh"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "sent" and body["attempts"] == 2
    assert body["error"] is None
    # exact replay of the stored payload, same org
    assert seen["url"] == "https://hooks.example/x"
    assert seen["payload"] == {"alert": "new", "n": 2}
    assert seen["org_id"] == ctx["org"]
    row = _row(ctx["wh"])
    assert row["status"] == "sent" and row["attempts"] == 2
    assert row["error"] is None and row["response_code"] == 200


def test_webhook_resend_failure_keeps_failed(ctx, monkeypatch):
    c = TestClient(main.app)
    monkeypatch.setattr(scheduler, "send_alert",
                        lambda url, payload, org_id=None:
                        (False, 3, 500, "conn reset"))
    r = _post(c, ctx["member"], ctx["wh_ok"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "failed" and body["attempts"] == 2
    assert body["error"] == "conn reset"
    row = _row(ctx["wh_ok"])
    assert row["status"] == "failed" and row["attempts"] == 2


def test_telegram_resend_rebuilds_message(ctx, monkeypatch):
    c = TestClient(main.app)
    seen = {}

    def fake(chat_id, text):
        seen.update(chat_id=chat_id, text=text)
        return (True, 1, None)

    monkeypatch.setattr(telegram_alerts, "send_telegram", fake)
    r = _post(c, ctx["member"], ctx["tg"])
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "sent"
    assert seen["chat_id"] == "12345"
    # rebuilt from the scan: schedule name + top finding (critical first)
    assert "Nightly" in seen["text"]
    assert "py-exec" in seen["text"]
    assert "py-xss" in seen["text"]
    assert seen["text"].index("py-exec") < seen["text"].index("py-xss")


def test_email_resend_rebuilds_message(ctx, monkeypatch):
    c = TestClient(main.app)
    seen = {}

    def fake(to_addr, subject, text_body, html_body):
        seen.update(to=to_addr, subject=subject, text=text_body,
                    html=html_body)
        return (True, 1, None)

    monkeypatch.setattr(email_alerts, "send_email", fake)
    r = _post(c, ctx["member"], ctx["em"])
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "sent"
    assert seen["to"] == "ops@example.com"
    assert "BraimSec" in seen["subject"]
    assert "py-exec" in seen["text"]


def test_slack_resend_409_masked_destination(ctx):
    c = TestClient(main.app)
    r = _post(c, ctx["member"], ctx["slack"])
    assert r.status_code == 409, r.text
    assert _row(ctx["slack"])["attempts"] == 1  # untouched


def test_sent_and_skipped_409(ctx):
    c = TestClient(main.app)
    assert _post(c, ctx["member"], ctx["sent"]).status_code == 409
    assert _post(c, ctx["member"], ctx["skip"]).status_code == 409


def test_unknown_id_404(ctx):
    c = TestClient(main.app)
    assert _post(c, ctx["member"], 999999).status_code == 404


def test_other_org_row_404(ctx):
    c = TestClient(main.app)
    assert _post(c, ctx["member"], ctx["other"]).status_code == 404


def test_viewer_403(ctx):
    c = TestClient(main.app)
    assert _post(c, ctx["viewer"], ctx["wh"]).status_code == 403


def test_bad_id_422(ctx):
    c = TestClient(main.app)
    r = c.post("/api/notifications/abc/resend",
               headers={"X-API-Key": ctx["member"]})
    assert r.status_code == 422


def test_audit_event_recorded(ctx, monkeypatch):
    c = TestClient(main.app)
    monkeypatch.setattr(scheduler, "send_alert",
                        lambda url, payload, org_id=None:
                        (True, 1, 200, None))
    assert _post(c, ctx["member"], ctx["wh"]).status_code == 200
    evs = _audit(ctx["org"], "notification.resent")
    assert len(evs) == 1
    detail = json.loads(evs[0]["detail"])
    assert detail["notif_id"] == ctx["wh"]
    assert detail["channel"] == "webhook"
    assert detail["status"] == "sent"
    assert detail["attempts"] == 2


def test_second_resend_of_still_failed_row(ctx, monkeypatch):
    c = TestClient(main.app)
    monkeypatch.setattr(scheduler, "send_alert",
                        lambda url, payload, org_id=None:
                        (False, 1, 500, "down"))
    assert _post(c, ctx["member"], ctx["wh_ok"]).status_code == 200
    assert _post(c, ctx["member"], ctx["wh_ok"]).status_code == 200
    row = _row(ctx["wh_ok"])
    assert row["attempts"] == 3 and row["status"] == "failed"
