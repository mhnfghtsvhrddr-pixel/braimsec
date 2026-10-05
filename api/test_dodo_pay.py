"""Tests for the Dodo Payments (card) integration.

- webhook signature (Standard Webhooks): valid / wrong secret / tampered
  body / missing headers / stale + future timestamps / multiple v1
  signatures (secret rotation) / whsec_ prefix handling
- evaluate_event: fulfill / ignore / reject paths, paused + on_hold ->
  canceled, unknown product/org/status rejected, metadata tampering
  rejected, tier always derived from the provider-reported product_id
- fulfill_event: end-to-end through the webhook endpoint, idempotent on
  the webhook-id header, 400 on bad signature, 503 when unconfigured
- POST /api/checkout/dodo: 503 when unconfigured, checkout_url + one-time
  key for new orgs, renewal reuses the org (api_key null), 400 on bad tier
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-dodo-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-dodo-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import dodo_pay as dp  # noqa: E402
from billing import create_org, get_subscription, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()
dp.init_dodo_tables()

SECRET = "whsec_" + base64.b64encode(b"dodo-test-secret-1234567890").decode()
PRODUCT_MAP = {
    "pdt_test_sm": ["starter", "monthly"],
    "pdt_test_sa": ["starter", "annual"],
    "pdt_test_pm": ["pro", "monthly"],
    "pdt_test_pa": ["pro", "annual"],
    "pdt_test_am": ["advanced", "monthly"],
    "pdt_test_aa": ["advanced", "annual"],
}

_created_orgs = []


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture(autouse=True)
def _clean_dodo_state():
    yield
    dp.init_dodo_tables()
    if _created_orgs:
        db = get_db()
        q = ",".join("?" * len(_created_orgs))
        db.execute(f"DELETE FROM dodo_events WHERE org_id IN ({q})",
                   tuple(_created_orgs))
        # orgs themselves live in the shared organizations table; the
        # names are unique per test (uid suffix) so they cannot collide.
        db.commit()
        db.close()
        _created_orgs.clear()


def _org():
    uid = os.urandom(4).hex()
    org_id = create_org(f"dodo-test-{uid}@example.com", plan="free")
    _created_orgs.append(org_id)
    return org_id


def _sign(raw: bytes, secret: str = SECRET, ts=None, msg_id="msg_test"):
    ts = int(time.time()) if ts is None else int(ts)
    key = dp._decode_secret(secret)
    signed = f"{msg_id}.{ts}.".encode() + raw
    sig = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest())
    return ({"webhook-id": msg_id,
             "webhook-timestamp": str(ts),
             "webhook-signature": "v1," + sig.decode()}, msg_id)


def _sub_event(org_id, product_id="pdt_test_pm", status="active",
               event_type="subscription.active", tier="pro",
               cycle="monthly", meta=None):
    md = {"org_id": org_id, "tier": tier, "cycle": cycle,
          "email": "buyer@example.com"}
    if meta is not None:
        md = meta
    return {
        "business_id": "biz_test",
        "timestamp": "2026-10-05T09:00:00Z",
        "type": event_type,
        "data": {
            "subscription_id": "sub_" + os.urandom(6).hex(),
            "product_id": product_id,
            "status": status,
            "customer": {"email": "buyer@example.com",
                         "name": "Buyer"},
            "metadata": md,
            "next_billing_date": "2026-11-05T09:00:00Z",
            "recurring_pre_tax_amount": 4000,
        },
    }


# ------------------------------------------------------- signature checks

def test_verify_valid():
    raw = b'{"type":"subscription.active"}'
    headers, _ = _sign(raw)
    assert dp.verify_webhook_signature(raw, headers, SECRET) is True


def test_verify_wrong_secret():
    raw = b'{"type":"subscription.active"}'
    headers, _ = _sign(raw, secret="whsec_" + base64.b64encode(b"wrong").decode())
    assert dp.verify_webhook_signature(raw, headers, SECRET) is False


def test_verify_tampered_body():
    raw = b'{"type":"subscription.active"}'
    headers, _ = _sign(raw)
    assert dp.verify_webhook_signature(b'{"type":"subscription.cancelled"}',
                                       headers, SECRET) is False


def test_verify_missing_headers():
    raw = b'{}'
    assert dp.verify_webhook_signature(raw, {}, SECRET) is False
    headers, _ = _sign(raw)
    del headers["webhook-id"]
    assert dp.verify_webhook_signature(raw, headers, SECRET) is False


def test_verify_missing_secret():
    raw = b'{}'
    headers, _ = _sign(raw)
    assert dp.verify_webhook_signature(raw, headers, "") is False


def test_verify_stale_timestamp_rejected():
    raw = b'{}'
    headers, _ = _sign(raw, ts=time.time() - 600)
    assert dp.verify_webhook_signature(raw, headers, SECRET) is False


def test_verify_future_timestamp_rejected():
    raw = b'{}'
    headers, _ = _sign(raw, ts=time.time() + 600)
    assert dp.verify_webhook_signature(raw, headers, SECRET) is False


def test_verify_multiple_v1_rotation():
    raw = b'{}'
    headers, _ = _sign(raw)
    old_secret = "whsec_" + base64.b64encode(b"old-secret").decode()
    old_headers, _ = _sign(raw, secret=old_secret,
                           ts=headers["webhook-timestamp"],
                           msg_id=headers["webhook-id"])
    headers["webhook-signature"] = (old_headers["webhook-signature"] + " " +
                                    headers["webhook-signature"])
    assert dp.verify_webhook_signature(raw, headers, SECRET) is True


def test_verify_secret_without_prefix():
    raw = b'{}'
    no_prefix = SECRET[len("whsec_"):]
    headers, _ = _sign(raw, secret=no_prefix)
    assert dp.verify_webhook_signature(raw, headers, no_prefix) is True


# ------------------------------------------------------- evaluate_event

def test_evaluate_active_fulfills(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    org_id = _org()
    verdict, info = dp.evaluate_event(_sub_event(org_id))
    assert verdict == "fulfill"
    assert info["org_id"] == org_id
    assert info["plan_id"] == "pro"
    assert info["status"] == "active"
    assert info["tier"] == "pro" and info["cycle"] == "monthly"


def test_evaluate_unknown_product_rejected(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    org_id = _org()
    verdict, info = dp.evaluate_event(_sub_event(org_id,
                                                 product_id="pdt_nope"))
    assert verdict == "reject"
    assert "pdt_nope" in info


def test_evaluate_unknown_org_rejected(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    verdict, info = dp.evaluate_event(_sub_event("org_does_not_exist"))
    assert verdict == "reject"
    assert "unknown org" in info


def test_evaluate_metadata_tampering_rejected(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    org_id = _org()
    # Paid for pro/monthly (pdt_test_pm) but metadata claims advanced.
    ev = _sub_event(org_id, tier="advanced", cycle="monthly")
    verdict, info = dp.evaluate_event(ev)
    assert verdict == "reject"
    assert "disagrees" in info


def test_evaluate_paused_maps_to_canceled(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    org_id = _org()
    verdict, info = dp.evaluate_event(_sub_event(org_id, status="paused"))
    assert verdict == "fulfill"
    assert info["status"] == "canceled"


def test_evaluate_on_hold_maps_to_canceled(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    org_id = _org()
    verdict, info = dp.evaluate_event(_sub_event(org_id, status="on_hold"))
    assert verdict == "fulfill"
    assert info["status"] == "canceled"


def test_evaluate_pending_ignored(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    org_id = _org()
    verdict, _ = dp.evaluate_event(_sub_event(org_id, status="pending"))
    assert verdict == "ignore"


def test_evaluate_payment_event_ignored():
    verdict, _ = dp.evaluate_event({"type": "payment.succeeded",
                                    "data": {}})
    assert verdict == "ignore"


def test_evaluate_unknown_event_ignored():
    verdict, _ = dp.evaluate_event({"type": "thing.happened", "data": {}})
    assert verdict == "ignore"


def test_evaluate_unknown_status_rejected(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    org_id = _org()
    verdict, info = dp.evaluate_event(_sub_event(org_id, status="weird"))
    assert verdict == "reject"
    assert "unknown Dodo status" in info


def test_evaluate_not_a_dict():
    assert dp.evaluate_event("nope")[0] == "reject"


# ------------------------------------------------------- fulfill via HTTP

def _client(monkeypatch):
    monkeypatch.setenv("DODO_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    return TestClient(main.app)


def test_webhook_fulfilled_end_to_end(monkeypatch):
    client = _client(monkeypatch)
    org_id = _org()
    raw = json.dumps(_sub_event(org_id)).encode()
    headers, msg_id = _sign(raw)
    r = client.post("/api/webhooks/dodo", content=raw, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == "fulfilled"
    sub = get_subscription(org_id)
    assert sub["plan_id"] == "pro" and sub["status"] == "active"
    ev = dp.get_event(msg_id)
    assert ev["verdict"] == "fulfilled" and ev["org_id"] == org_id


def test_webhook_idempotent_on_webhook_id(monkeypatch):
    client = _client(monkeypatch)
    org_id = _org()
    raw = json.dumps(_sub_event(org_id)).encode()
    headers, msg_id = _sign(raw)
    assert client.post("/api/webhooks/dodo", content=raw,
                       headers=headers).json()["verdict"] == "fulfilled"
    r = client.post("/api/webhooks/dodo", content=raw, headers=headers)
    assert r.json()["verdict"] == "duplicate"


def test_webhook_bad_signature_400(monkeypatch):
    client = _client(monkeypatch)
    org_id = _org()
    raw = json.dumps(_sub_event(org_id)).encode()
    headers, _ = _sign(raw)
    headers["webhook-signature"] = "v1," + base64.b64encode(b"bad").decode()
    r = client.post("/api/webhooks/dodo", content=raw, headers=headers)
    assert r.status_code == 400


def test_webhook_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("DODO_PRODUCT_MAP", raising=False)
    monkeypatch.delenv("DODO_WEBHOOK_SECRET", raising=False)
    client = TestClient(main.app)
    r = client.post("/api/webhooks/dodo", content=b"{}")
    assert r.status_code == 503


# ------------------------------------------------------- checkout endpoint

def test_checkout_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("DODO_PRODUCT_MAP", raising=False)
    monkeypatch.delenv("DODO_API_KEY", raising=False)
    client = TestClient(main.app)
    r = client.post("/api/checkout/dodo",
                    json={"tier": "pro", "cycle": "monthly",
                          "email": "n@n.co"})
    assert r.status_code == 503


def test_checkout_returns_url_and_key(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    monkeypatch.setenv("DODO_API_KEY", "dodo_test_x")
    monkeypatch.setattr(dp, "create_checkout_session",
                        lambda *a, **k: ("https://test.dodopayments.com/c/1",
                                         "sess_1"))
    client = TestClient(main.app)
    email = f"dodo-new-{os.urandom(4).hex()}@example.com"
    r = client.post("/api/checkout/dodo",
                    json={"tier": "pro", "cycle": "monthly", "email": email})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["checkout_url"].startswith("https://")
    assert body["api_key"] and body["api_key"].startswith("bs_")


def test_checkout_renewal_reuses_org(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    monkeypatch.setenv("DODO_API_KEY", "dodo_test_x")
    monkeypatch.setattr(dp, "create_checkout_session",
                        lambda *a, **k: ("https://test.dodopayments.com/c/2",
                                         "sess_2"))
    client = TestClient(main.app)
    email = f"dodo-renew-{os.urandom(4).hex()}@example.com"
    first = client.post("/api/checkout/dodo",
                        json={"tier": "starter", "cycle": "annual",
                              "email": email}).json()
    assert first["api_key"]
    second = client.post("/api/checkout/dodo",
                         json={"tier": "starter", "cycle": "annual",
                               "email": email}).json()
    assert second["api_key"] is None


def test_checkout_400_on_bad_tier(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    monkeypatch.setenv("DODO_API_KEY", "dodo_test_x")
    client = TestClient(main.app)
    r = client.post("/api/checkout/dodo",
                    json={"tier": "nope", "cycle": "monthly",
                          "email": "a@b.co"})
    assert r.status_code == 400


def test_entry_for_tier_cycle(monkeypatch):
    monkeypatch.setenv("DODO_PRODUCT_MAP", json.dumps(PRODUCT_MAP))
    pid, plan = dp.entry_for_tier_cycle("advanced", "annual")
    assert pid == "pdt_test_aa" and plan == "team"
    assert dp.entry_for_tier_cycle("nope", "monthly") is None
