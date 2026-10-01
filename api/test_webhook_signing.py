"""Tests for outgoing webhook HMAC signing (api/webhook_signing.py).

- secret generation/parsing roundtrip
- sign/verify roundtrip, tampered body, wrong secret, stale timestamp,
  malformed timestamp
- signing header format (Stripe-style t=<ts>,v1=<hex>)
- rotate endpoint: secret shown once, encrypted at rest, never via GET
- GET: status only, org isolation
- RBAC: viewer reads, member rotates (viewer rotate -> 403)
- send_alert: signed headers when secret configured, unsigned otherwise,
  corrupt row -> unsigned without crashing
- audit trail on rotate
"""
import base64
import os
import sys
import tempfile

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-wsign-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-wsign-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import scheduler  # noqa: E402
import webhook_signing as ws  # noqa: E402
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


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = os.urandom(4).hex()
    org = create_org(f"SignCo_{uid}", plan="free")
    other = create_org(f"SignOther_{uid}", plan="free")
    member = provision_key(org, "sg-member", actor="owner", role="member")
    viewer = provision_key(org, "sg-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "o-member", actor="owner", role="member")
    return {"org": org, "other": other, "member": member, "viewer": viewer,
            "o_member": o_member}


def _h(key):
    return {"X-API-Key": key}


# --- crypto primitives -------------------------------------------------------

def test_generate_parse_roundtrip():
    raw, display = ws.generate_signing_secret()
    assert len(raw) == 32
    assert display.startswith("whsec_")
    assert ws.parse_display_secret(display) == raw


def test_parse_rejects_bad_format():
    with pytest.raises(ValueError):
        ws.parse_display_secret("not-a-secret")


def test_sign_verify_roundtrip():
    raw, _ = ws.generate_signing_secret()
    body = b'{"event":"schedule.alert"}'
    ts, sig = ws.sign_payload(raw, body, ts=1_700_000_000)
    assert ws.verify_signature(raw, body, ts, sig,
                               now=1_700_000_100)


def test_verify_rejects_tampered_body():
    raw, _ = ws.generate_signing_secret()
    ts, sig = ws.sign_payload(raw, b'{"a":1}', ts=1_700_000_000)
    assert not ws.verify_signature(raw, b'{"a":2}', ts, sig,
                                   now=1_700_000_100)


def test_verify_rejects_wrong_secret():
    raw1, _ = ws.generate_signing_secret()
    raw2, _ = ws.generate_signing_secret()
    ts, sig = ws.sign_payload(raw1, b'{}', ts=1_700_000_000)
    assert not ws.verify_signature(raw2, b'{}', ts, sig,
                                   now=1_700_000_100)


def test_verify_rejects_stale_timestamp():
    raw, _ = ws.generate_signing_secret()
    ts, sig = ws.sign_payload(raw, b'{}', ts=1_700_000_000)
    assert not ws.verify_signature(raw, b'{}', ts, sig,
                                   now=1_700_000_000 + 301)
    # boundary still ok
    assert ws.verify_signature(raw, b'{}', ts, sig,
                               now=1_700_000_000 + 300)


def test_verify_rejects_malformed_ts():
    raw, _ = ws.generate_signing_secret()
    _, sig = ws.sign_payload(raw, b'{}', ts=1_700_000_000)
    assert not ws.verify_signature(raw, b'{}', "not-a-ts", sig,
                                   now=1_700_000_000)


def test_signing_headers_format():
    raw, _ = ws.generate_signing_secret()
    body = b'{"x":1}'
    hdrs = ws.signing_headers(raw, body)
    assert ws.TIMESTAMP_HEADER in hdrs
    sig_hdr = hdrs[ws.SIGNATURE_HEADER]
    assert sig_hdr.startswith("t=") and ",v1=" in sig_hdr
    ts, v1 = sig_hdr.split(",v1=")
    ts = ts[2:]
    assert ws.verify_signature(raw, body, ts, v1, now=int(ts))


# --- rotate / status endpoints -----------------------------------------------

def test_get_unconfigured(ctx):
    c = TestClient(main.app)
    r = c.get("/api/webhook-signing", headers=_h(ctx["viewer"]))
    assert r.status_code == 200
    d = r.json()
    assert d["configured"] is False and d["created_at"] is None
    assert "signing_secret" not in d
    assert d["scheme"] == "HMAC-SHA256"


def test_rotate_returns_secret_once(ctx):
    c = TestClient(main.app)
    r = c.post("/api/webhook-signing/rotate", headers=_h(ctx["member"]))
    assert r.status_code == 200
    d = r.json()
    assert d["signing_secret"].startswith("whsec_")
    # GET afterwards: configured, but never the secret
    r2 = c.get("/api/webhook-signing", headers=_h(ctx["viewer"]))
    d2 = r2.json()
    assert d2["configured"] is True and d2["created_at"]
    assert "signing_secret" not in d2


def test_secret_encrypted_at_rest(ctx):
    c = TestClient(main.app)
    r = c.post("/api/webhook-signing/rotate", headers=_h(ctx["member"]))
    display = r.json()["signing_secret"]
    db = get_db()
    row = db.execute(
        "SELECT secret_enc FROM webhook_signing_secrets WHERE org_id=?",
        (ctx["org"],)).fetchone()
    db.close()
    assert row and display not in row["secret_enc"]
    # and the stored value decrypts back to the same secret
    raw = ws.get_org_signing_secret(get_db(), ctx["org"])
    assert raw == ws.parse_display_secret(display)


def test_rotate_viewer_forbidden(ctx):
    c = TestClient(main.app)
    r = c.post("/api/webhook-signing/rotate", headers=_h(ctx["viewer"]))
    assert r.status_code == 403


def test_rotate_replaces_old_secret(ctx):
    c = TestClient(main.app)
    old = c.post("/api/webhook-signing/rotate",
                 headers=_h(ctx["member"])).json()["signing_secret"]
    new = c.post("/api/webhook-signing/rotate",
                 headers=_h(ctx["member"])).json()["signing_secret"]
    assert old != new
    db = get_db()
    raw = ws.get_org_signing_secret(db, ctx["org"])
    db.close()
    assert raw == ws.parse_display_secret(new)
    assert raw != ws.parse_display_secret(old)


def test_org_isolation(ctx):
    c = TestClient(main.app)
    c.post("/api/webhook-signing/rotate", headers=_h(ctx["member"]))
    r = c.get("/api/webhook-signing", headers=_h(ctx["o_member"]))
    assert r.status_code == 200
    assert r.json()["configured"] is False


def test_rotate_audit_trail(ctx):
    c = TestClient(main.app)
    c.post("/api/webhook-signing/rotate", headers=_h(ctx["member"]))
    db = get_db()
    row = db.execute(
        "SELECT id FROM audit_log WHERE org_id=? AND action=?",
        (ctx["org"], "webhook_signing.rotated")).fetchone()
    db.close()
    assert row is not None


def test_rotate_rate_limited(ctx):
    c = TestClient(main.app)
    for _ in range(10):
        r = c.post("/api/webhook-signing/rotate", headers=_h(ctx["member"]))
        assert r.status_code == 200
    r = c.post("/api/webhook-signing/rotate", headers=_h(ctx["member"]))
    assert r.status_code == 429


# --- send_alert wiring -------------------------------------------------------

def _capture_post(monkeypatch):
    captured = {}

    def fake_post(url, body, headers, timeout):
        captured["url"] = url
        captured["body"] = body
        captured["headers"] = dict(headers)
        return 200

    monkeypatch.setattr(scheduler, "safe_webhook_post", fake_post)
    monkeypatch.setattr(scheduler.time, "sleep", lambda s: None)
    return captured


def _rotate(ctx):
    db = get_db()
    display = ws.rotate_org_signing_secret(db, ctx["org"])
    db.close()
    return display


def test_send_alert_signed_when_configured(ctx, monkeypatch):
    display = _rotate(ctx)
    captured = _capture_post(monkeypatch)
    payload = {"event": "schedule.alert", "scan_id": "abc"}
    ok, attempts, code, err = scheduler.send_alert(
        "https://example.com/hook", payload, org_id=ctx["org"])
    assert ok and code == 200
    hdrs = captured["headers"]
    assert ws.SIGNATURE_HEADER in hdrs and ws.TIMESTAMP_HEADER in hdrs
    ts, v1 = hdrs[ws.SIGNATURE_HEADER].split(",v1=")
    ts = ts[2:]
    assert hdrs[ws.TIMESTAMP_HEADER] == ts
    raw = ws.parse_display_secret(display)
    assert ws.verify_signature(raw, captured["body"], ts, v1,
                               now=int(ts))


def test_send_alert_unsigned_without_secret(ctx, monkeypatch):
    captured = _capture_post(monkeypatch)
    ok, _, code, _ = scheduler.send_alert(
        "https://example.com/hook", {"event": "schedule.alert"},
        org_id=ctx["org"])
    assert ok and code == 200
    assert ws.SIGNATURE_HEADER not in captured["headers"]


def test_send_alert_unsigned_when_no_org(monkeypatch):
    captured = _capture_post(monkeypatch)
    ok, _, code, _ = scheduler.send_alert(
        "https://example.com/hook", {"event": "schedule.alert"})
    assert ok and code == 200
    assert ws.SIGNATURE_HEADER not in captured["headers"]


def test_send_alert_corrupt_row_sends_unsigned(ctx, monkeypatch):
    _rotate(ctx)
    db = get_db()
    db.execute("UPDATE webhook_signing_secrets SET secret_enc='corrupt!!'"
               " WHERE org_id=?", (ctx["org"],))
    db.commit()
    db.close()
    captured = _capture_post(monkeypatch)
    ok, _, code, _ = scheduler.send_alert(
        "https://example.com/hook", {"event": "schedule.alert"},
        org_id=ctx["org"])
    assert ok and code == 200  # best-effort: alert still delivered
    assert ws.SIGNATURE_HEADER not in captured["headers"]
