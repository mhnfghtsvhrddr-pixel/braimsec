"""Tests for API key rotation: POST /api/keys/{key_id}/rotate.

Rotation is an atomic swap — the replacement inherits org/name/role/
project and the old key dies in the SAME transaction, so there is never
a window with zero or two valid keys. A key may always rotate itself;
rotating someone else's key needs admin+.
"""
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-keyrot-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import billing  # noqa: E402
import main  # noqa: E402
from billing import (create_org, create_project, ensure_owner_org,  # noqa: E402
                     provision_key, rotate_key)
from database import get_db, init_db  # noqa: E402

init_db()
MASTER = "test-key-123"


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture()
def ctx():
    ensure_owner_org()
    org = create_org("RotationCorp", plan="free")
    member = provision_key(org, "svc", actor="owner", role="member")
    admin = provision_key(org, "ops", actor="owner", role="admin")
    p1 = create_project(org, "mobile", actor="owner")
    p_admin = provision_key(org, "p1-admin", actor="owner",
                            role="admin", project_id=p1)
    return {"org": org, "member": member, "admin": admin,
            "p_admin": p_admin, "p1": p1}


def _h(key):
    return {"x-api-key": key}


def _key_id(raw):
    db = get_db()
    try:
        row = db.execute("SELECT id, revoked FROM api_keys WHERE key_prefix=?",
                         (raw[:8],)).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def _key_id_by_prefix(prefix):
    db = get_db()
    try:
        row = db.execute("SELECT id FROM api_keys WHERE key_prefix=?",
                         (prefix,)).fetchone()
        return row["id"] if row else None
    finally:
        db.close()


def _audit_actions(org, action, limit=20):
    from audit import read_events  # noqa: E402
    return read_events(org, action=action, limit=limit)


def test_self_rotation_by_member(ctx):
    old_raw = ctx["member"]
    old = _key_id(old_raw)
    with TestClient(main.app) as c:
        r = c.post(f"/api/keys/{old['id']}/rotate", headers=_h(old_raw))
        assert r.status_code == 200, r.text
        body = r.json()
        new_raw = body["key"]
        assert new_raw != old_raw
        assert new_raw.startswith("bs_")
        assert body["rotated_from"] == old["id"]
        assert "warning" in body
        # Old key is dead immediately...
        assert c.get("/api/scans", headers=_h(old_raw)).status_code == 401
        # ...and the replacement works with the same (member) privilege.
        assert c.get("/api/scans", headers=_h(new_raw)).status_code == 200
        assert c.post("/api/keys", headers=_h(new_raw),
                      json={"role": "viewer"}).status_code == 403
        # Listing shows the new key with the inherited name and role.
        rows = c.get("/api/keys", headers=_h(ctx["admin"])).json()
        new_row = [x for x in rows if x["key_prefix"] == new_raw[:8]][0]
        assert new_row["name"] == "svc" and new_row["role"] == "member"
        old_row = [x for x in rows if x["id"] == old["id"]][0]
        assert old_row["revoked"] == 1
    # Audit: created + revoked events linked to each other.
    created = _audit_actions(ctx["org"], "api_key.created")
    assert any(e["resource_id"] == body["key_id"]
               and e["detail"]["rotation_of"] == old["id"] for e in created)
    revoked = _audit_actions(ctx["org"], "api_key.revoked")
    assert any(e["resource_id"] == old["id"]
               and e["detail"]["rotated_to"] == body["key_id"]
               for e in revoked)


def test_member_cannot_rotate_others(ctx):
    admin_id = _key_id(ctx["admin"])["id"]
    with TestClient(main.app) as c:
        r = c.post(f"/api/keys/{admin_id}/rotate", headers=_h(ctx["member"]))
        assert r.status_code == 403, r.text
    # The target key is untouched.
    with TestClient(main.app) as c:
        assert c.get("/api/scans", headers=_h(ctx["admin"])).status_code == 200


def test_admin_can_rotate_member_key(ctx):
    member_id = _key_id(ctx["member"])["id"]
    with TestClient(main.app) as c:
        r = c.post(f"/api/keys/{member_id}/rotate", headers=_h(ctx["admin"]))
        assert r.status_code == 200, r.text
        new_raw = r.json()["key"]
        assert c.get("/api/scans", headers=_h(ctx["member"])).status_code == 401
        assert c.get("/api/scans", headers=_h(new_raw)).status_code == 200


def test_rotate_revoked_key_is_400(ctx):
    member_id = _key_id(ctx["member"])["id"]
    with TestClient(main.app) as c:
        r = c.post(f"/api/keys/{member_id}/rotate", headers=_h(ctx["admin"]))
        assert r.status_code == 200, r.text
        r = c.post(f"/api/keys/{member_id}/rotate", headers=_h(ctx["admin"]))
        assert r.status_code == 400, r.text


def test_rotate_unknown_key_is_404(ctx):
    with TestClient(main.app) as c:
        r = c.post("/api/keys/key_deadbeefcafe/rotate",
                   headers=_h(ctx["admin"]))
        assert r.status_code == 404, r.text


def test_project_scoped_key_cannot_rotate_outside(ctx):
    org_member_id = _key_id(ctx["member"])["id"]
    with TestClient(main.app) as c:
        r = c.post(f"/api/keys/{org_member_id}/rotate",
                   headers=_h(ctx["p_admin"]))
        assert r.status_code == 404, r.text
    # And it CAN rotate a key inside its own project.
    p_admin_id = _key_id(ctx["p_admin"])["id"]
    with TestClient(main.app) as c:
        r = c.post(f"/api/keys/{p_admin_id}/rotate",
                   headers=_h(ctx["p_admin"]))
        assert r.status_code == 200, r.text
        assert c.get("/api/scans",
                     headers=_h(r.json()["key"])).status_code == 200


def test_rotation_rolls_back_on_audit_failure(ctx, monkeypatch):
    """If the second audit write blows up, the whole rotation must roll
    back: the old key stays valid and no replacement row exists."""
    member_id = _key_id(ctx["member"])["id"]
    before = {r["id"] for r in
              get_db().execute("SELECT id FROM api_keys").fetchall()}
    get_db().close()
    calls = []
    orig = billing.log_event

    def boom(*a, **k):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("audit down")
        return orig(*a, **k)

    monkeypatch.setattr(billing, "log_event", boom)
    with pytest.raises(RuntimeError, match="audit down"):
        rotate_key(member_id, actor="owner")
    db = get_db()
    try:
        after = {r["id"] for r in
                 db.execute("SELECT id FROM api_keys").fetchall()}
        still = db.execute("SELECT revoked FROM api_keys WHERE id=?",
                           (member_id,)).fetchone()["revoked"]
    finally:
        db.close()
    assert after == before, "partial rotation leaked a key row"
    assert still == 0, "old key was revoked despite the rollback"
    with TestClient(main.app) as c:
        assert c.get("/api/scans",
                     headers=_h(ctx["member"])).status_code == 200
