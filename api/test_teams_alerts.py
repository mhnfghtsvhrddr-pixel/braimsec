"""Tests for Microsoft Teams alerts (api/teams_alerts.py + /api/teams-webhooks).

- webhook URL validation: only *.office.com / *.logic.azure.com accepted
- secret hygiene: encrypted at rest, masked in API, never in logs/responses
- MessageCard building: alert + failed variants, themeColor, truncation
- delivery: success on any 2xx / http-error / exception paths with retry
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
_tmp = tempfile.mkdtemp(prefix="braimsec-test-teams-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-teams-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import teams_alerts  # noqa: E402
from billing import (create_org, ensure_owner_org, provision_key,  # noqa: E402
                     seed_plans)
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()

URL = ("https://outlook.office.com/webhook/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
       "/IncomingWebhook/ffffffffffffffffffffffffffffffff/11111111-2222-3333-4444-555555555555")
URL2 = ("https://prod-11.westus.logic.azure.com:443/workflows/abcdef1234567890"
        "/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2F&sig=zzzzzz")


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture()
def _no_sleep(monkeypatch):
    monkeypatch.setattr(teams_alerts.time, "sleep", lambda s: None)


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = os.urandom(4).hex()
    org = create_org(f"TeamsCo_{uid}", plan="free")
    other = create_org(f"TeamsOther_{uid}", plan="free")
    admin = provision_key(org, "tm-admin", actor="owner", role="admin")
    member = provision_key(org, "tm-member", actor="owner", role="member")
    viewer = provision_key(org, "tm-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "o-member", actor="owner", role="member")
    return {"org": org, "other": other, "admin": admin, "member": member,
            "viewer": viewer, "o_member": o_member}


def _h(key):
    return {"X-API-Key": key}


def _add_webhook(db, org, url, label=""):
    enc = teams_alerts._encrypt(url)
    h = hashlib.sha256(url.encode()).hexdigest()
    cur = db.execute(
        "INSERT INTO teams_webhooks (org_id, webhook_url_enc, url_hash,"
        " label, created_at) VALUES (?,?,?,?,?)",
        (org, enc, h, label, "2026-10-01T00:00:00+00:00"))
    db.commit()
    return cur.lastrowid


class FakeResp:
    def __init__(self, status=200):
        self.status = status

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
def _teams(monkeypatch, _no_sleep):
    FakeUrlopen.calls = []
    FakeUrlopen.script = []
    monkeypatch.setattr(teams_alerts, "urlopen", FakeUrlopen())
    return FakeUrlopen


# ---------------------------------------------------------------------------
# Validation + masking
# ---------------------------------------------------------------------------

def test_validate_webhook_url():
    assert teams_alerts.validate_webhook_url(URL) == URL
    assert teams_alerts.validate_webhook_url(URL2) == URL2
    assert teams_alerts.validate_webhook_url("  " + URL + "  ") == URL
    for bad in ["", "http://outlook.office.com/webhook/x",
                "https://hooks.slack.com/services/T/B/x",
                "https://evil.com/webhook/abc",
                "https://office.com.evil.com/webhook/abc",
                "https://outlook.office.com/",
                "not a url", None]:
        with pytest.raises(ValueError):
            teams_alerts.validate_webhook_url(bad)


def test_mask_never_leaks_secret():
    masked = teams_alerts.mask_webhook_url(URL)
    assert "555555555555" not in masked
    assert masked.startswith("https://outlook.office.com/")


def test_encrypt_roundtrip():
    assert teams_alerts._decrypt(teams_alerts._encrypt(URL)) == URL


# ---------------------------------------------------------------------------
# MessageCard building
# ---------------------------------------------------------------------------

def test_build_teams_card_alert():
    card = teams_alerts.build_teams_card(
        "schedule.alert", "my app", "target: api", [
            {"severity": "error", "rule_id": "r1", "message": "boom",
             "file": "a.py", "line": 3}],
        "error", "https://dash.example")
    assert card["@type"] == "MessageCard"
    assert card["themeColor"] == "FF0000"
    body = card["sections"][0]
    assert "1 نتيجة جديدة" in body["activityTitle"]
    assert "r1" in body["text"] and "a.py:3" in body["text"]
    assert "https://dash.example" in body["text"]
    assert json.dumps(card, ensure_ascii=False)


def test_build_teams_card_failed():
    card = teams_alerts.build_teams_card("schedule.failed", "h", "sub", [],
                                         "error", "")
    assert "فشل الفحص" in card["summary"]
    assert card["themeColor"] == "FF0000"


def test_build_teams_card_truncates():
    big = [{"severity": "error", "rule_id": "r", "message": "x" * 5000,
            "file": "a.py", "line": 1}]
    card = teams_alerts.build_teams_card("e", "h", "s", big, "error", "")
    assert len(card["sections"][0]["text"]) <= teams_alerts.MAX_MESSAGE_CHARS


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def test_send_teams_ok_on_202(_teams):
    _teams.script = [FakeResp(status=202)]
    ok, attempts, err = teams_alerts.send_teams(URL, {"@type": "x"})
    assert ok and attempts == 1 and err is None
    posted_url, body = _teams.calls[0]
    assert posted_url == URL
    assert body["@type"] == "x"


def test_send_teams_retries_then_gives_up(_teams):
    _teams.script = [ConnectionError("down")] * 3
    ok, attempts, err = teams_alerts.send_teams(URL, {})
    assert not ok and attempts == 3 and err
    assert URL not in err  # secret never in the error


def test_send_teams_http_error_recorded(_teams):
    _teams.script = [FakeResp(status=500)] * 3
    ok, attempts, err = teams_alerts.send_teams(URL, {})
    assert not ok and "500" in err


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def _dispatch(db, org, **kw):
    base = dict(org_id=org, schedule_id=None, vcs_repo_id=None,
                scan_id="s1", event="schedule.alert", severity="error",
                new_count=1, heading="h", subheading="s", findings=[])
    base.update(kw)
    return teams_alerts.dispatch_teams_alerts(db, **base)


def test_dispatch_no_webhooks(ctx):
    db = get_db()
    try:
        out = _dispatch(db, ctx["org"])
        assert out == {"teamsed": False, "reason": "no webhooks"}
    finally:
        db.close()


def test_dispatch_sends_and_records(ctx, _teams):
    db = get_db()
    try:
        _add_webhook(db, ctx["org"], URL, label="Security")
        out = _dispatch(db, ctx["org"], new_count=2,
                        findings=[{"severity": "error", "rule_id": "r",
                                   "message": "m", "file": "a.py",
                                   "line": 1}])
        assert out["teamsed"] and out["sent"] == 1
        rows = db.execute(
            "SELECT channel, recipient, status FROM notifications"
            " WHERE org_id=?", (ctx["org"],)).fetchall()
        assert len(rows) == 1
        assert rows[0]["channel"] == "teams"
        assert rows[0]["status"] == "sent"
        assert "555555555555" not in rows[0]["recipient"]
        assert "Security" in rows[0]["recipient"]
    finally:
        db.close()


def test_dispatch_failed_records_failed(ctx, _teams):
    _teams.script = [ConnectionError("x")] * 3
    db = get_db()
    try:
        _add_webhook(db, ctx["org"], URL)
        out = _dispatch(db, ctx["org"])
        assert not out["teamsed"] and out["failed"] == 1
        row = db.execute(
            "SELECT status, error FROM notifications WHERE org_id=?",
            (ctx["org"],)).fetchone()
        assert row["status"] == "failed"
        assert URL not in (row["error"] or "")
    finally:
        db.close()


def test_dispatch_corrupt_row_skipped_not_crashed(ctx, _teams):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO teams_webhooks (org_id, webhook_url_enc, url_hash,"
            " label, created_at) VALUES (?,?,?,?,?)",
            (ctx["org"], "not-fernet-at-all", "h", "", "t"))
        db.commit()
        out = _dispatch(db, ctx["org"])
        assert out["skipped"] == 1 and not out["teamsed"]
        assert _teams.calls == []
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _api_list(key):
    return TestClient(main.app).get("/api/teams-webhooks", headers=_h(key))


def _api_add(key, url, label=""):
    c = TestClient(main.app)
    return c.post("/api/teams-webhooks", headers=_h(key),
                  json={"webhook_url": url, "label": label})


def test_endpoint_crud(ctx):
    # add (member)
    r = _api_add(ctx["member"], URL, "Security")
    assert r.status_code == 200, r.text
    row_id = r.json()["id"]
    assert r.json()["label"] == "Security"
    assert "555555555555" not in r.text
    # duplicate -> 409
    assert _api_add(ctx["member"], URL).status_code == 409
    # non-Microsoft URL -> 400
    assert _api_add(ctx["member"],
                    "https://hooks.slack.com/services/T/B/x").status_code == 400
    # list (viewer) — masked only
    r = _api_list(ctx["viewer"])
    assert r.status_code == 200
    webhooks = r.json()["webhooks"]
    assert len(webhooks) == 1
    assert webhooks[0]["webhook_url_masked"].startswith(
        "https://outlook.office.com/")
    assert "555555555555" not in r.text
    # viewer cannot add
    assert _api_add(ctx["viewer"], URL2).status_code == 403
    # delete (member)
    c = TestClient(main.app)
    d = c.delete(f"/api/teams-webhooks/{row_id}", headers=_h(ctx["member"]))
    assert d.status_code == 200
    assert _api_list(ctx["viewer"]).json()["webhooks"] == []
    # delete missing -> 404
    assert c.delete("/api/teams-webhooks/99999",
                    headers=_h(ctx["member"])).status_code == 404


def test_endpoint_org_isolation(ctx):
    r = _api_add(ctx["member"], URL)
    row_id = r.json()["id"]
    # other org cannot see or delete it
    assert _api_list(ctx["o_member"]).json()["webhooks"] == []
    c = TestClient(main.app)
    assert c.delete(f"/api/teams-webhooks/{row_id}",
                    headers=_h(ctx["o_member"])).status_code == 404
    # and no key at all -> 401
    assert TestClient(main.app).get("/api/teams-webhooks").status_code == 401


def test_endpoint_audit_trail(ctx):
    r = _api_add(ctx["admin"], URL, "audit-me")
    row_id = r.json()["id"]
    c = TestClient(main.app)
    c.delete(f"/api/teams-webhooks/{row_id}", headers=_h(ctx["admin"]))
    trail = c.get("/api/audit-log", headers=_h(ctx["admin"])).json()
    actions = [e["action"] for e in trail]
    assert "teams_webhook.added" in actions
    assert "teams_webhook.removed" in actions
