"""Tests for the Paddle Billing (card) integration.

- webhook signature: valid / wrong secret / tampered body / missing or
  malformed header / stale timestamp / multiple h1 (secret rotation)
- evaluate_event: fulfill / ignore / reject paths, paused -> canceled
- fulfill_event: end-to-end through the webhook endpoint, idempotent on
  event_id, 400 on bad signature
- POST /api/checkout/paddle: 503 when unconfigured, price + one-time key
  for new orgs, renewal reuses the org (api_key null), 400 on bad tier
"""
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-paddle-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-paddle-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import paddle_pay as pp  # noqa: E402
from billing import create_org, get_subscription, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()

SECRET = "pdl_ntfset_test_secret_abc123"
PRICE_MAP = {
    "pri_test_sm": ["starter", "monthly"],
    "pri_test_sa": ["starter", "annual"],
    "pri_test_pm": ["pro", "monthly"],
    "pri_test_pa": ["pro", "annual"],
    "pri_test_am": ["advanced", "monthly"],
    "pri_test_aa": ["advanced", "annual"],
}

_created_orgs = []


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture(autouse=True)
def _clean_paddle_state():
    yield
    pp.init_paddle_tables()
    if _created_orgs:
        db = get_db()
        q = ",".join("?" * len(_created_orgs))
        db.execute(f"DELETE FROM paddle_events WHERE org_id IN ({q})",
                   tuple(_created_orgs))
        db.commit()
        db.close()
        _created_orgs.clear()


def _org():
    uid = os.urandom(4).hex()
    org_id = create_org(f"PaddleCo_{uid}", plan="free")
    _created_orgs.append(org_id)
    return org_id


def _sign(raw: bytes, secret: str = SECRET, ts=None):
    ts = int(time.time()) if ts is None else ts
    digest = hmac.new(secret.encode(), f"{ts}:".encode() + raw,
                      hashlib.sha256).hexdigest()
    return f"ts={ts};h1={digest}"


def _sub_event(org_id, tier="pro", cycle="monthly", status="active",
               event_type="subscription.activated", event_id=None,
               price_id="pri_test_pm", custom=None):
    eid = event_id or ("evt_" + os.urandom(6).hex())
    cd = {"org_id": org_id, "tier": tier, "cycle": cycle,
          "email": "buyer@example.com"}
    if custom is not None:
        cd = custom
    return {
        "event_id": eid,
        "event_type": event_type,
        "occurred_at": "2026-10-02T09:00:00Z",
        "data": {
            "id": "sub_" + os.urandom(6).hex(),
            "customer_id": "ctm_" + os.urandom(6).hex(),
            "status": status,
            "custom_data": cd,
            "items": [{"price": {"id": price_id,
                                 "product_id": "pro_test"}}],
            "current_billing_period": {
                "starts_at": "2026-10-02T09:00:00Z",
                "ends_at": "2026-11-02T09:00:00Z"},
        },
    }


# ------------------------------------------------------- signature checks

def test_verify_valid():
    raw = b'{"event_id":"evt_1"}'
    assert pp.verify_webhook_signature(raw, _sign(raw), SECRET) is True


def test_verify_wrong_secret():
    raw = b'{"event_id":"evt_1"}'
    assert pp.verify_webhook_signature(raw, _sign(raw), "nope") is False


def test_verify_tampered_body():
    raw = b'{"event_id":"evt_1"}'
    sig = _sign(raw)
    assert pp.verify_webhook_signature(b'{"event_id":"evt_2"}', sig,
                                       SECRET) is False


def test_verify_missing_header():
    assert pp.verify_webhook_signature(b"{}", None, SECRET) is False
    assert pp.verify_webhook_signature(b"{}", "", SECRET) is False


def test_verify_missing_secret():
    raw = b"{}"
    assert pp.verify_webhook_signature(raw, _sign(raw), "") is False


def test_verify_malformed_header():
    raw = b"{}"
    for bad in ["ts=abc;h1=deadbeef", "h1=deadbeef", "ts=123",
                "bogus", "ts=123;h1="]:
        assert pp.verify_webhook_signature(raw, bad, SECRET) is False


def test_verify_stale_timestamp_rejected():
    raw = b"{}"
    old = int(time.time()) - 301
    assert pp.verify_webhook_signature(raw, _sign(raw, ts=old),
                                       SECRET) is False
    fresh = int(time.time()) - 299
    assert pp.verify_webhook_signature(raw, _sign(raw, ts=fresh),
                                       SECRET) is True


def test_verify_future_timestamp_rejected():
    raw = b"{}"
    future = int(time.time()) + 301
    assert pp.verify_webhook_signature(raw, _sign(raw, ts=future),
                                       SECRET) is False


def test_verify_multiple_h1_rotation():
    raw = b"{}"
    good = _sign(raw)
    rotated = good + ";h1=" + "0" * 64
    assert pp.verify_webhook_signature(raw, rotated, SECRET) is True
    # ... and in the other order too
    assert pp.verify_webhook_signature(
        raw, "h1=" + "0" * 64 + ";" + good.split(";", 1)[0] + ";" +
        good.split(";", 1)[1], SECRET) is True


def test_verify_ts_verbatim_not_reserialized():
    # ts with surrounding spaces still signs the exact ts string
    raw = b"{}"
    ts = str(int(time.time()))
    digest = hmac.new(SECRET.encode(), ts.encode() + b":" + raw,
                      hashlib.sha256).hexdigest()
    assert pp.verify_webhook_signature(
        raw, f"ts= {ts} ; h1={digest}", SECRET) is True


# ------------------------------------------------------- evaluate_event

def test_evaluate_created_fulfills():
    org = _org()
    verdict, info = pp.evaluate_event(_sub_event(org))
    assert verdict == "fulfill"
    assert info["org_id"] == org
    assert info["plan_id"] == "pro"
    assert info["status"] == "active"
    assert info["period_end"] == "2026-11-02T09:00:00Z"


def test_evaluate_unknown_org_rejected():
    verdict, info = pp.evaluate_event(_sub_event("org_nope"))
    assert verdict == "reject"
    assert "unknown org" in info


def test_evaluate_unknown_event_ignored():
    org = _org()
    verdict, _ = pp.evaluate_event(_sub_event(
        org, event_type="customer.created"))
    assert verdict == "ignore"


def test_evaluate_transaction_completed_ignored():
    org = _org()
    verdict, info = pp.evaluate_event(_sub_event(
        org, event_type="transaction.completed"))
    assert verdict == "ignore"
    assert "subscription-driven" in info


def test_evaluate_paused_maps_to_canceled():
    org = _org()
    verdict, info = pp.evaluate_event(_sub_event(org, status="paused"))
    assert verdict == "fulfill"
    assert info["status"] == "canceled"


def test_evaluate_unknown_status_rejected():
    org = _org()
    verdict, _ = pp.evaluate_event(_sub_event(org, status="weird"))
    assert verdict == "reject"


def test_evaluate_price_fallback(monkeypatch):
    monkeypatch.setenv("PADDLE_PRICE_MAP", json.dumps(PRICE_MAP))
    org = _org()
    ev = _sub_event(org, custom={"org_id": org})  # no tier/cycle
    verdict, info = pp.evaluate_event(ev)
    assert verdict == "fulfill"
    assert (info["tier"], info["cycle"]) == ("pro", "monthly")


def test_evaluate_unmappable_rejected():
    org = _org()
    ev = _sub_event(org, custom={"org_id": org}, price_id="pri_unknown")
    verdict, _ = pp.evaluate_event(ev)
    assert verdict == "reject"


# ------------------------------------------------------- webhook endpoint

@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("PADDLE_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("PADDLE_PRICE_MAP", json.dumps(PRICE_MAP))
    return TestClient(main.app)


def _post_webhook(client, event, secret=SECRET, ts=None):
    raw = json.dumps(event).encode()
    return client.post("/api/webhooks/paddle", content=raw,
                       headers={"Paddle-Signature": _sign(raw, secret, ts),
                                "Content-Type": "application/json"})


def test_webhook_activates_subscription(client):
    org = _org()
    r = _post_webhook(client, _sub_event(org))
    assert r.status_code == 200
    assert r.json()["verdict"] == "fulfilled"
    sub = get_subscription(org)
    assert sub["plan_id"] == "pro"
    assert sub["status"] == "active"
    assert sub["payment_provider"] == "paddle"
    assert sub["current_period_end"] == "2026-11-02T09:00:00Z"


def test_webhook_idempotent_on_event_id(client):
    org = _org()
    ev = _sub_event(org)
    assert _post_webhook(client, ev).json()["verdict"] == "fulfilled"
    r2 = _post_webhook(client, ev)
    assert r2.status_code == 200
    assert r2.json()["verdict"] == "duplicate"


def test_webhook_bad_signature_400(client):
    org = _org()
    r = _post_webhook(client, _sub_event(org), secret="wrong")
    assert r.status_code == 400


def test_webhook_canceled_keeps_access_until_period_end(client):
    org = _org()
    _post_webhook(client, _sub_event(org))
    r = _post_webhook(client, _sub_event(
        org, event_type="subscription.canceled", status="canceled"))
    assert r.json()["verdict"] == "fulfilled"
    sub = get_subscription(org)
    assert sub["status"] == "canceled"
    assert sub["plan_id"] == "pro"  # access until period end


def test_webhook_past_due(client):
    org = _org()
    r = _post_webhook(client, _sub_event(
        org, event_type="subscription.past_due", status="past_due"))
    assert r.json()["verdict"] == "fulfilled"
    assert get_subscription(org)["status"] == "past_due"


def test_webhook_rejected_unknown_org_still_200(client):
    # Valid signature, unresolvable org: 200 (no retry storm), rejected.
    r = _post_webhook(client, _sub_event("org_nope"))
    assert r.status_code == 200
    assert r.json()["verdict"] == "reject"


# ------------------------------------------------------- checkout session

def test_checkout_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("PADDLE_PRICE_MAP", raising=False)
    c = TestClient(main.app)
    r = c.post("/api/checkout/paddle",
               json={"tier": "pro", "cycle": "monthly",
                     "email": "new@example.com"})
    assert r.status_code == 503


def test_checkout_returns_price_and_key(monkeypatch):
    monkeypatch.setenv("PADDLE_PRICE_MAP", json.dumps(PRICE_MAP))
    c = TestClient(main.app)
    email = f"paddle-new-{os.urandom(4).hex()}@example.com"
    r = c.post("/api/checkout/paddle",
               json={"tier": "pro", "cycle": "monthly", "email": email})
    assert r.status_code == 200
    j = r.json()
    assert j["price_id"] == "pri_test_pm"
    assert j["custom_data"]["tier"] == "pro"
    assert j["custom_data"]["email"] == email
    assert j["api_key"] and j["api_key"].startswith("bs_")
    org_id = j["custom_data"]["org_id"]
    _created_orgs.append(org_id)

    # Renewal: same email -> same org, no new key.
    r2 = c.post("/api/checkout/paddle",
                json={"tier": "pro", "cycle": "monthly", "email": email})
    j2 = r2.json()
    assert j2["custom_data"]["org_id"] == org_id
    assert j2["api_key"] is None


def test_checkout_unknown_tier_400(monkeypatch):
    monkeypatch.setenv("PADDLE_PRICE_MAP", json.dumps(PRICE_MAP))
    c = TestClient(main.app)
    r = c.post("/api/checkout/paddle",
               json={"tier": "nope", "cycle": "monthly",
                     "email": "x@example.com"})
    assert r.status_code == 400


def test_checkout_bad_email_400(monkeypatch):
    monkeypatch.setenv("PADDLE_PRICE_MAP", json.dumps(PRICE_MAP))
    c = TestClient(main.app)
    r = c.post("/api/checkout/paddle",
               json={"tier": "pro", "cycle": "monthly", "email": "not-an-email"})
    assert r.status_code == 400


def test_entry_for_tier_cycle():
    assert pp.entry_for_tier_cycle("pro", "monthly", PRICE_MAP) == (
        "pri_test_pm", "pro")
    assert pp.entry_for_tier_cycle("advanced", "annual", PRICE_MAP) == (
        "pri_test_aa", "team")
    assert pp.entry_for_tier_cycle("nope", "monthly", PRICE_MAP) is None


def test_price_map_invalid_entries_dropped(monkeypatch):
    monkeypatch.setenv("PADDLE_PRICE_MAP", json.dumps({
        "pri_ok": ["pro", "monthly"],
        "pri_bad_tier": ["nope", "monthly"],
        "pri_bad_shape": ["pro"],
        "pri_not_list": "pro",
    }))
    assert pp.price_map() == {"pri_ok": ("pro", "monthly")}
    monkeypatch.setenv("PADDLE_PRICE_MAP", "not-json{{")
    assert pp.price_map() == {}
