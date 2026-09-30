"""Tests for RBAC: roles on API keys + key-management endpoints.

Roles (weakest -> strongest): viewer < member < admin < owner.
- viewer: read-only; POST /api/scans and AI actions -> 403
- member: viewer + scans + AI actions
- admin:  member + key management (viewer/member keys only)
- owner:  admin + grant admin/owner roles (master env key is always owner)
"""
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-rbac-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import tasks  # noqa: E402
from billing import create_org, ensure_owner_org, provision_key  # noqa: E402
from database import init_db  # noqa: E402

init_db()
MASTER = "test-key-123"


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture()
def _mock_engines(monkeypatch):
    monkeypatch.setattr(tasks, "run_semgrep", lambda d, scope=None: [])
    monkeypatch.setattr(tasks, "run_gitleaks", lambda d: [])
    monkeypatch.setattr(tasks, "run_sca", lambda d: [])
    monkeypatch.setattr(tasks.time, "sleep", lambda s: None)


@pytest.fixture()
def keys():
    ensure_owner_org()
    org = create_org("Initech", plan="free")
    out = {"org": org}
    for role in ("viewer", "member", "admin", "owner"):
        out[role] = provision_key(org, role, actor="owner", role=role)
    return out


def _target():
    from pathlib import Path
    d = Path(main.SCAN_ROOT) / "pytest-rbac"
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.py").write_text("x = 1\n")
    return str(d)


def _h(key):
    return {"x-api-key": key}


def test_viewer_is_read_only(keys, _mock_engines):
    v = _h(keys["viewer"])
    with TestClient(main.app) as c:
        assert c.get("/api/scans", headers=v).status_code == 200
        r = c.post("/api/scans", headers=v, data={"target_path": _target()})
        assert r.status_code == 403, r.text
        r = c.post("/api/scans/nope/ai-review", headers=v)
        assert r.status_code == 403, r.text
        r = c.post("/api/keys", headers=v, json={"role": "viewer"})
        assert r.status_code == 403, r.text


def test_member_can_scan_but_not_manage_keys(keys, _mock_engines):
    m = _h(keys["member"])
    with TestClient(main.app) as c:
        r = c.post("/api/scans", headers=m, data={"target_path": _target()})
        assert r.status_code == 200, r.text
        assert c.get("/api/keys", headers=m).status_code == 403
        assert c.post("/api/keys", headers=m, json={"role": "viewer"}).status_code == 403


def test_admin_manages_keys_but_cannot_grant_admin(keys):
    a = _h(keys["admin"])
    with TestClient(main.app) as c:
        # Admin mints a viewer key: OK, raw key shown once.
        r = c.post("/api/keys", headers=a,
                   json={"name": "ci-read", "role": "viewer"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["key"].startswith("bs_") and body["role"] == "viewer"
        # Admin cannot grant admin/owner.
        r = c.post("/api/keys", headers=a, json={"role": "admin"})
        assert r.status_code == 403, r.text
        # List shows prefixes, never hashes.
        keys_list = c.get("/api/keys", headers=a).json()
        assert keys_list and all("key_hash" not in k for k in keys_list)
        assert {k["role"] for k in keys_list} >= {"viewer", "member", "admin"}
        # The minted viewer key really works as viewer.
        vkey = body["key"]
        assert c.get("/api/scans", headers=_h(vkey)).status_code == 200
        r = c.post("/api/scans", headers=_h(vkey), data={"target_path": _target()})
        assert r.status_code == 403
        # Revoke it.
        kid = next(k["id"] for k in keys_list if k["key_prefix"] == body["key_prefix"])
        r = c.delete(f"/api/keys/{kid}", headers=a)
        assert r.status_code == 200, r.text
        assert c.get("/api/scans", headers=_h(vkey)).status_code == 401


def test_admin_cannot_revoke_own_key(keys):
    from database import get_db
    db = get_db()
    row = db.execute("SELECT id, key_prefix FROM api_keys WHERE org_id=? AND role='admin'",
                     (keys["org"],)).fetchone()
    db.close()
    with TestClient(main.app) as c:
        r = c.delete(f"/api/keys/{row['id']}", headers=_h(keys["admin"]))
        assert r.status_code == 400, r.text


def test_owner_can_grant_admin(keys):
    with TestClient(main.app) as c:
        r = c.post("/api/keys", headers=_h(MASTER),
                   json={"name": "second-admin", "role": "admin"})
        assert r.status_code == 200, r.text
        assert r.json()["role"] == "admin"


def test_unknown_role_rejected(keys):
    with TestClient(main.app) as c:
        r = c.post("/api/keys", headers=_h(MASTER), json={"role": "superuser"})
        assert r.status_code == 400, r.text


def test_key_management_is_org_scoped(keys):
    other_org = create_org("Umbrella", plan="free")
    other_admin = provision_key(other_org, "a", actor="owner", role="admin")
    from database import get_db
    db = get_db()
    row = db.execute("SELECT id FROM api_keys WHERE org_id=? AND role='viewer'",
                     (keys["org"],)).fetchone()
    db.close()
    with TestClient(main.app) as c:
        # Other org's admin cannot see or revoke Initech's keys.
        assert c.get("/api/keys", headers=_h(other_admin)).json() == [] or \
            all(k["id"] != row["id"] for k in
                c.get("/api/keys", headers=_h(other_admin)).json())
        r = c.delete(f"/api/keys/{row['id']}", headers=_h(other_admin))
        assert r.status_code == 404, r.text
