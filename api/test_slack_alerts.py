"""Tests for Slack alerts (api/slack_alerts.py + /api/slack-webhooks).

- webhook URL validation: only hooks.slack.com/services/* accepted
- secret hygiene: encrypted at rest, masked in API, never in logs/responses
- message building: alert + failed variants, truncation
- delivery: success / http-error / exception paths with retry
- dispatch: no webhooks -> reason; per-webhook notifications rows;
  corrupt enc row -> skipped, never a crash
- endpoints: CRUD + RBAC (viewer lists, member manages) + org isolation
"""
import hashlib
import json
import os
import sys
import tempfile

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-slack-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-slack-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import slack_alerts  # noqa: E402
from billing import (create_org, ensure_owner_org, provision_key,  # noqa: E402
                     seed_plans)
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()

URL = "https://hooks.slack.com/services/T00000000/B00000000/xxxxxxxxxxxxxxxx"
URL2 = "https://hooks.slack.com/services/T11111111/B11111111/yyyyyyyyyyyyyyyy"


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture()
def _no_sleep(monkeypatch):
    monkeypatch.setattr(slack_alerts.time, "sleep", lambda s: None)


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = os.urandom(4).hex()
    org = create_org(f"SlackCo_{uid}", plan="free")
    other = create_org(f"SlackOther_{uid}", plan="free")
    admin = provision_key(org, "s-admin", actor="owner", role="admin")
    member = provision_key(org, "s-member", actor="owner", role="member")
    viewer = provision_key(org, "s-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "o-member", actor="owner", role="member")
    return {"org": org, "other": other, "admin": admin, "member": member,
            "viewer": viewer, "o_member": o_member, "uid": uid}


def _h(key):
    return {"X-API-Key": key}


def _add_webhook(db, org, url, label=""):
    enc = slack_alerts._encrypt(url)
    h = hashlib.sha256(url.encode()).hexdigest()
    cur = db.execute(
        "INSERT INTO slack_webhooks (org_id, webhook_url_enc, url_hash,"
        " label, created_at) VALUES (?,?,?,?,?)",
        (org, enc, h, label, "2026-10-01T00:00:00+00:00"))
    db.commit()
    return cur.lastrowid


class FakeResp:
    def __init__(self, status=200, body=b"ok"):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeUrlopen:
    calls = []
    script = []  # list of FakeResp | Exception, consumed in order

    def __call__(self, req, timeout=None):
        FakeUrlopen.calls.append(
            (req.full_url, json.loads(req.data.decode())))
        if FakeUrlopen.script:
            nxt = FakeUrlopen.script.pop(0)
            if isinstance(nxt, Exception):
                raise nxt
            return nxt
        return FakeResp()


@pytest.fixture()
def _slack(monkeypatch, _no_sleep):
    FakeUrlopen.calls = []
    FakeUrlopen.script = []
    monkeypatch.setattr(slack_alerts, "urlopen", FakeUrlopen())
    return FakeUrlopen


# ---------------------------------------------------------------------------
# Validation + masking
# ---------------------------------------------------------------------------

def test_validate_webhook_url():
    assert slack_alerts.validate_webhook_url(URL) == URL
    assert slack_alerts.validate_webhook_url("  " + URL + "  ") == URL
    for bad in ["", "http://hooks.slack.com/services/T/B/x",
                "https://hooks.slack.com/services/",
                "https://evil.com/services/T000/B000/xxxx",
                "https://hooks.slack.com.evil.com/services/T000/B000/xxxx",
                "not a url", None]:
        with pytest.raises(ValueError):
            slack_alerts.validate_webhook_url(bad)


def test_mask_never_leaks_secret():
    masked = slack_alerts.mask_webhook_url(URL)
    assert "xxxxxxxxxxxxxxxx" not in masked
    assert masked.startswith("https://hooks.slack.com/services/")


def test_encrypt_roundtrip():
    assert slack_alerts._decrypt(slack_alerts._encrypt(URL)) == URL


# ---------------------------------------------------------------------------
# Message building
# ---------------------------------------------------------------------------

def test_build_slack_text_alert():
    t = slack_alerts.build_slack_text(
        "schedule.alert", "my app", "target: api", [
            {"severity": "error", "rule_id": "r1", "message": "boom",
             "file": "a.py", "line": 3}],
        "error", "https://dash.example")
    assert "1 نتيجة جديدة" in t and "حرجة" in t
    assert "r1" in t and "a.py:3" in t
    assert "https://dash.example" in t


def test_build_slack_text_failed():
    t = slack_alerts.build_slack_text("schedule.failed", "h", "sub", [],
                                      "error", "")
    assert "فشل الفحص" in t


def test_build_slack_text_truncates():
    big = [{"severity": "error", "rule_id": "r", "message": "x" * 5000,
            "file": "a.py", "line": 1}]
    t = slack_alerts.build_slack_text("e", "h", "s", big, "error", "")
    assert len(t) <= slack_alerts.MAX_MESSAGE_CHARS


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def test_send_slack_ok(_slack):
    ok, attempts, err = slack_alerts.send_slack(URL, "hi")
    assert ok and attempts == 1 and err is None
    posted_url, body = _slack.calls[0]
    assert posted_url == URL
    assert body == {"text": "hi"}


def test_send_slack_retries_then_gives_up(_slack):
    _slack.script = [ConnectionError("down"), ConnectionError("down"),
                     ConnectionError("down")]
    ok, attempts, err = slack_alerts.send_slack(URL, "hi")
    assert not ok and attempts == 3 and err
    assert URL not in err  # secret never in the error


def test_send_slack_http_error_recorded(_slack):
    _slack.script = [FakeResp(status=404, body=b"not_found")] * 3
    ok, attempts, err = slack_alerts.send_slack(URL, "hi")
    assert not ok and "404" in err


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def _dispatch(db, org, **kw):
    base = dict(org_id=org, schedule_id=None, vcs_repo_id=None,
                scan_id="s1", event="schedule.alert", severity="error",
                new_count=1, heading="h", subheading="s", findings=[])
    base.update(kw)
    return slack_alerts.dispatch_slack_alerts(db, **base)


def test_dispatch_no_webhooks(ctx):
    db = get_db()
    try:
        out = _dispatch(db, ctx["org"])
        assert out == {"slacked": False, "reason": "no webhooks"}
    finally:
        db.close()


def test_dispatch_sends_and_records(ctx, _slack):
    db = get_db()
    try:
        _add_webhook(db, ctx["org"], URL, label="#sec")
        out = _dispatch(db, ctx["org"], new_count=2,
                        findings=[{"severity": "error", "rule_id": "r",
                                   "message": "m", "file": "a.py",
                                   "line": 1}])
        assert out["slacked"] and out["sent"] == 1
        rows = db.execute(
            "SELECT channel, recipient, status FROM notifications"
            " WHERE org_id=?", (ctx["org"],)).fetchall()
        assert len(rows) == 1
        assert rows[0]["channel"] == "slack"
        assert rows[0]["status"] == "sent"
        assert "xxxxxxxxxxxxxxxx" not in rows[0]["recipient"]
        assert "#sec" in rows[0]["recipient"]
    finally:
        db.close()


def test_dispatch_failed_records_failed(ctx, _slack):
    _slack.script = [ConnectionError("x")] * 3
    db = get_db()
    try:
        _add_webhook(db, ctx["org"], URL)
        out = _dispatch(db, ctx["org"])
        assert not out["slacked"] and out["failed"] == 1
        row = db.execute(
            "SELECT status, error FROM notifications WHERE org_id=?",
            (ctx["org"],)).fetchone()
        assert row["status"] == "failed"
        assert URL not in (row["error"] or "")
    finally:
        db.close()


def test_dispatch_corrupt_row_skipped_not_crashed(ctx, _slack):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO slack_webhooks (org_id, webhook_url_enc, url_hash,"
            " label, created_at) VALUES (?,?,?,?,?)",
            (ctx["org"], "not-fernet-at-all", "h", "", "t"))
        db.commit()
        out = _dispatch(db, ctx["org"])
        assert out["skipped"] == 1 and not out["slacked"]
        assert _slack.calls == []
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _api_list(key):
    return TestClient(main.app).get("/api/slack-webhooks", headers=_h(key))


def _api_add(key, url, label=""):
    c = TestClient(main.app)
    return c.post("/api/slack-webhooks", headers=_h(key),
                  json={"webhook_url": url, "label": label})


def test_endpoint_crud(ctx):
    # add (member)
    r = _api_add(ctx["member"], URL, "#security")
    assert r.status_code == 200, r.text
    row_id = r.json()["id"]
    assert r.json()["label"] == "#security"
    assert "xxxxxxxxxxxxxxxx" not in r.text
    # duplicate -> 409
    assert _api_add(ctx["member"], URL).status_code == 409
    # invalid -> 400
    assert _api_add(ctx["member"], "https://evil.com/x").status_code == 400
    # list (viewer) — masked only
    r = _api_list(ctx["viewer"])
    assert r.status_code == 200
    webhooks = r.json()["webhooks"]
    assert len(webhooks) == 1
    assert webhooks[0]["webhook_url_masked"].startswith(
        "https://hooks.slack.com/services/")
    assert "xxxxxxxxxxxxxxxx" not in r.text
    # viewer cannot add
    assert _api_add(ctx["viewer"], URL2).status_code == 403
    # delete (member)
    c = TestClient(main.app)
    d = c.delete(f"/api/slack-webhooks/{row_id}", headers=_h(ctx["member"]))
    assert d.status_code == 200
    assert _api_list(ctx["viewer"]).json()["webhooks"] == []
    # delete missing -> 404
    assert c.delete("/api/slack-webhooks/99999",
                    headers=_h(ctx["member"])).status_code == 404


def test_endpoint_org_isolation(ctx):
    r = _api_add(ctx["member"], URL)
    row_id = r.json()["id"]
    # other org cannot see or delete it
    assert _api_list(ctx["o_member"]).json()["webhooks"] == []
    c = TestClient(main.app)
    assert c.delete(f"/api/slack-webhooks/{row_id}",
                    headers=_h(ctx["o_member"])).status_code == 404
    # and no key at all -> 401
    assert TestClient(main.app).get("/api/slack-webhooks").status_code == 401


def test_endpoint_audit_trail(ctx):
    r = _api_add(ctx["admin"], URL, "audit-me")
    row_id = r.json()["id"]
    c = TestClient(main.app)
    c.delete(f"/api/slack-webhooks/{row_id}", headers=_h(ctx["admin"]))
    trail = c.get("/api/audit-log", headers=_h(ctx["admin"])).json()
    actions = [e["action"] for e in trail]
    assert "slack_webhook.added" in actions
    assert "slack_webhook.removed" in actions
