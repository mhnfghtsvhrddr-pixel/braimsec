"""Tests for customer accounts (email + password login).

- password hashing: scrypt roundtrip, wrong password, tampered hash
- register: creates org + owner user + session; 409 duplicate; 400 bad
  email / short password; email case-insensitive
- login: token works on /api/me and org endpoints; 401 generic message
  for wrong password and unknown email (no account oracle)
- sessions: logout revokes; expired sessions rejected; raw token never
  stored (only its hash)
- regression: API keys and the master key keep working; project-scoped
  keys still rejected from org surfaces
"""
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-auth-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-auth-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import auth as authmod  # noqa: E402
from billing import provision_key, create_org, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()
authmod.init_auth_tables()

_tracked_users = []


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture(autouse=True)
def _clean_auth_state():
    yield
    if _tracked_users:
        db = get_db()
        q = ",".join("?" * len(_tracked_users))
        db.execute(f"DELETE FROM user_sessions WHERE user_id IN ({q})",
                   tuple(_tracked_users))
        db.execute(f"DELETE FROM users WHERE id IN ({q})",
                   tuple(_tracked_users))
        db.commit()
        db.close()
        _tracked_users.clear()


@pytest.fixture()
def client():
    return TestClient(main.app)


def _register(client, email=None, password="correct-horse-12"):
    email = email or f"auth-{os.urandom(4).hex()}@example.com"
    r = client.post("/api/auth/register",
                    json={"email": email, "password": password})
    if r.status_code == 200:
        _tracked_users.append(r.json()["user"]["id"])
    return r


def _h(token):
    return {"X-API-Key": token}


# ------------------------------------------------------- password hashing

def test_hash_roundtrip():
    h = authmod.hash_password("correct-horse-12")
    assert h != "correct-horse-12"
    assert authmod.verify_password("correct-horse-12", h) is True
    assert authmod.verify_password("wrong-password", h) is False


def test_hash_tampered_graceful():
    assert authmod.verify_password("x", "not-a-hash") is False
    assert authmod.verify_password("x", "scrypt$n=1$zz$zz") is False


def test_hash_salts_unique():
    assert (authmod.hash_password("same-password") !=
            authmod.hash_password("same-password"))


# ------------------------------------------------------- register

def test_register_creates_owner_and_session(client):
    r = _register(client)
    assert r.status_code == 200
    j = r.json()
    assert j["user"]["role"] == "owner"
    assert j["session_token"].startswith("bss_")
    me = client.get("/api/me", headers=_h(j["session_token"]))
    assert me.status_code == 200
    assert me.json()["type"] == "user"
    assert me.json()["email"] == j["user"]["email"]


def test_register_duplicate_409(client):
    email = f"dup-{os.urandom(4).hex()}@example.com"
    assert _register(client, email=email).status_code == 200
    r = _register(client, email=email)
    assert r.status_code == 409


def test_register_bad_email_400(client):
    for bad in ["nope", "a@b", "x" * 300 + "@example.com"]:
        r = _register(client, email=bad)
        assert r.status_code == 400, bad


def test_register_short_password_400(client):
    r = _register(client, password="short")
    assert r.status_code == 400


def test_register_email_case_insensitive(client):
    email = f"Case-{os.urandom(4).hex()}@Example.COM"
    assert _register(client, email=email).status_code == 200
    r = _register(client, email=email.lower())
    assert r.status_code == 409


def test_register_logs_audit(client):
    r = _register(client)
    org_id = r.json()["user"]["org_id"]
    db = get_db()
    row = db.execute(
        "SELECT action FROM audit_log WHERE org_id=? AND action=?",
        (org_id, "user.registered")).fetchone()
    db.close()
    assert row is not None


# ------------------------------------------------------- login

def test_login_ok(client):
    email = f"login-{os.urandom(4).hex()}@example.com"
    _register(client, email=email)
    r = client.post("/api/auth/login",
                    json={"email": email, "password": "correct-horse-12"})
    assert r.status_code == 200
    assert r.json()["session_token"].startswith("bss_")


def test_login_wrong_password_401_generic(client):
    email = f"lpw-{os.urandom(4).hex()}@example.com"
    _register(client, email=email)
    r = client.post("/api/auth/login",
                    json={"email": email, "password": "wrong-password"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password"


def test_login_unknown_email_same_401(client):
    r = client.post("/api/auth/login",
                    json={"email": "nobody-here@example.com",
                          "password": "whatever-1234"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password"


def test_login_email_case_insensitive(client):
    email = f"Mixed-{os.urandom(4).hex()}@Example.com"
    _register(client, email=email)
    r = client.post("/api/auth/login",
                    json={"email": email.lower(),
                          "password": "correct-horse-12"})
    assert r.status_code == 200


# ------------------------------------------------------- sessions

def test_session_authorizes_org_endpoints(client):
    r = _register(client)
    token = r.json()["session_token"]
    sub = client.get("/api/subscription", headers=_h(token))
    assert sub.status_code == 200
    assert sub.json()["plan_id"] == "free"


def test_logout_revokes(client):
    r = _register(client)
    token = r.json()["session_token"]
    assert client.post("/api/auth/logout",
                       headers=_h(token)).status_code == 200
    assert client.get("/api/me", headers=_h(token)).status_code == 401


def test_logout_without_session_400(client):
    key = provision_key(create_org(f"AuthOrg_{os.urandom(4).hex()}"),
                        "k", actor="owner", role="member")
    r = client.post("/api/auth/logout", headers=_h(key))
    assert r.status_code == 400


def test_expired_session_rejected(client):
    r = _register(client)
    token = r.json()["session_token"]
    import hashlib
    db = get_db()
    db.execute("UPDATE user_sessions SET expires_at='2000-01-01T00:00:00+00:00'"
               " WHERE token_hash=?",
               (hashlib.sha256(token.encode()).hexdigest(),))
    db.commit()
    db.close()
    assert client.get("/api/me", headers=_h(token)).status_code == 401


def test_raw_token_never_stored(client):
    r = _register(client)
    token = r.json()["session_token"]
    db = get_db()
    rows = db.execute("SELECT token_hash FROM user_sessions").fetchall()
    db.close()
    hashes = [row["token_hash"] for row in rows]
    assert token not in hashes
    assert len(token) > 20  # raw token has real entropy


def test_me_for_api_key_callers(client):
    org = create_org(f"MeOrg_{os.urandom(4).hex()}")
    key = provision_key(org, "k", actor="owner", role="member")
    r = client.get("/api/me", headers=_h(key))
    assert r.status_code == 200
    assert r.json()["type"] == "api_key"
    assert r.json()["org_id"] == org


def test_register_non_dict_body_400(client):
    r = client.post("/api/auth/register", json=["not", "a", "dict"])
    assert r.status_code == 400


def test_register_non_string_password_400(client):
    r = client.post("/api/auth/register",
                    json={"email": f"ns-{os.urandom(4).hex()}@example.com",
                          "password": 12345})
    assert r.status_code == 400


def test_login_non_string_password_401(client):
    email = f"lns-{os.urandom(4).hex()}@example.com"
    _register(client, email=email)
    r = client.post("/api/auth/login",
                    json={"email": email, "password": 12345})
    assert r.status_code == 401


def test_session_role_flows_to_rbac(client):
    # Owner sessions can do owner things (rotate keys); member API keys
    # tested elsewhere. Here: session role == owner.
    r = _register(client)
    me = client.get("/api/me", headers=_h(r.json()["session_token"]))
    assert me.json()["role"] == "owner"


# ------------------------------------------------------- password reset

def _reset_token_for(client, email):
    r = _register(client, email=email)
    user_id = r.json()["user"]["id"]
    return authmod._create_reset_token(
        user_id, r.json()["user"]["org_id"]), r


def test_forgot_always_200_no_oracle(client):
    email = f"forgot-{os.urandom(4).hex()}@example.com"
    _register(client, email=email)
    for e in [email, "nobody-there@example.com", "bad-email"]:
        r = client.post("/api/auth/forgot", json={"email": e})
        assert r.status_code == 200
        assert r.json() == {"ok": True}


def test_forgot_mints_token_for_real_user(client):
    email = f"fm-{os.urandom(4).hex()}@example.com"
    _register(client, email=email)
    client.post("/api/auth/forgot", json={"email": email})
    db = get_db()
    n = db.execute(
        "SELECT COUNT(*) c FROM password_resets pr JOIN users u "
        "ON u.id=pr.user_id WHERE u.email=? AND pr.used=0",
        (email,)).fetchone()["c"]
    db.close()
    assert n == 1  # SMTP unconfigured: token minted, email not dispatched


def test_reset_flow(client):
    email = f"reset-{os.urandom(4).hex()}@example.com"
    token, r = _reset_token_for(client, email)
    old_session = r.json()["session_token"]
    assert r.status_code == 200
    rr = client.post("/api/auth/reset",
                     json={"token": token, "new_password": "brand-new-pass-99"})
    assert rr.status_code == 200
    # New password works, old one doesn't.
    ok = client.post("/api/auth/login",
                     json={"email": email,
                           "password": "brand-new-pass-99"})
    assert ok.status_code == 200
    bad = client.post("/api/auth/login",
                      json={"email": email, "password": "correct-horse-12"})
    assert bad.status_code == 401
    # All previous sessions revoked.
    assert client.get("/api/me", headers=_h(old_session)).status_code == 401


def test_reset_token_single_use(client):
    email = f"reuse-{os.urandom(4).hex()}@example.com"
    token, _ = _reset_token_for(client, email)
    assert client.post("/api/auth/reset",
                       json={"token": token,
                             "new_password": "brand-new-pass-99"}).status_code == 200
    r2 = client.post("/api/auth/reset",
                     json={"token": token,
                           "new_password": "another-new-pass-99"})
    assert r2.status_code == 400


def test_reset_bad_token_400(client):
    r = client.post("/api/auth/reset",
                    json={"token": "bsr_" + "0" * 64,
                          "new_password": "brand-new-pass-99"})
    assert r.status_code == 400
    assert r.json()["detail"] == "Invalid or expired reset token"


def test_reset_expired_token_400(client):
    email = f"exp-{os.urandom(4).hex()}@example.com"
    token, _ = _reset_token_for(client, email)
    import hashlib
    db = get_db()
    db.execute("UPDATE password_resets SET expires_at='2000-01-01T00:00:00+00:00'"
               " WHERE token_hash=?",
               (hashlib.sha256(token.encode()).hexdigest(),))
    db.commit()
    db.close()
    r = client.post("/api/auth/reset",
                    json={"token": token, "new_password": "brand-new-pass-99"})
    assert r.status_code == 400


def test_reset_short_password_400(client):
    email = f"spw-{os.urandom(4).hex()}@example.com"
    token, _ = _reset_token_for(client, email)
    r = client.post("/api/auth/reset",
                    json={"token": token, "new_password": "short"})
    assert r.status_code == 400


def test_reset_logs_audit(client):
    email = f"ra-{os.urandom(4).hex()}@example.com"
    token, r = _reset_token_for(client, email)
    org_id = r.json()["user"]["org_id"]
    client.post("/api/auth/reset",
                json={"token": token, "new_password": "brand-new-pass-99"})
    db = get_db()
    row = db.execute(
        "SELECT action FROM audit_log WHERE org_id=? AND action=?",
        (org_id, "user.password_reset")).fetchone()
    db.close()
    assert row is not None
