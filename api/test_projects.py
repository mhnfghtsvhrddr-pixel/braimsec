"""Tests for projects: org-internal scoping of scans and API keys.

- projects are created/listed/deleted per org (admin+; org scope)
- scans can be filed under a project; project-scoped keys see only theirs
- project-scoped keys cannot mint org-wide keys (no scope escape)
- org-level surfaces (audit log, usage) reject project-scoped keys
- deleting a project with scans/keys is refused
"""
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-projects-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import tasks  # noqa: E402
from billing import (create_org, create_project, ensure_owner_org,  # noqa: E402
                     provision_key)
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
def ctx():
    ensure_owner_org()
    org = create_org("Hooli", plan="free")
    other = create_org("PiedPiper", plan="free")
    admin = provision_key(org, "admin", actor="owner", role="admin")
    member = provision_key(org, "member", actor="owner", role="member")
    viewer = provision_key(org, "viewer", actor="owner", role="viewer")
    p1 = create_project(org, "mobile", actor="owner")
    p2 = create_project(org, "backend", actor="owner")
    p_member = provision_key(org, "p1-member", actor="owner",
                             role="member", project_id=p1)
    p_admin = provision_key(org, "p1-admin", actor="owner",
                            role="admin", project_id=p1)
    return {"org": org, "other": other, "admin": admin, "member": member,
            "viewer": viewer, "p1": p1, "p2": p2,
            "p_member": p_member, "p_admin": p_admin}


def _h(key):
    return {"x-api-key": key}


def _target(name):
    from pathlib import Path
    d = Path(main.SCAN_ROOT) / f"pytest-proj-{name}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.py").write_text("x = 1\n")
    return str(d)


def _scan(c, key, target, project_id=None):
    data = {"target_path": target}
    if project_id:
        data["project_id"] = project_id
    r = c.post("/api/scans", headers=_h(key), data=data)
    assert r.status_code == 200, r.text
    return r.json()["scan_id"]


def test_project_crud(ctx):
    a = _h(ctx["admin"])
    with TestClient(main.app) as c:
        # Create.
        r = c.post("/api/projects", headers=a, json={"name": "web"})
        assert r.status_code == 200, r.text
        pid = r.json()["project_id"]
        # List (admin sees all).
        names = {p["name"] for p in c.get("/api/projects", headers=a).json()}
        assert {"mobile", "backend", "web"} <= names
        # Viewer can list but not create.
        assert c.get("/api/projects", headers=_h(ctx["viewer"])).status_code == 200
        assert c.post("/api/projects", headers=_h(ctx["viewer"]),
                      json={"name": "x"}).status_code == 403
        # Member cannot create either.
        assert c.post("/api/projects", headers=_h(ctx["member"]),
                      json={"name": "x"}).status_code == 403
        # Empty project deletes cleanly.
        r = c.delete(f"/api/projects/{pid}", headers=a)
        assert r.status_code == 200, r.text
        # Unknown project -> 404.
        assert c.delete("/api/projects/proj_nope", headers=a).status_code == 404


def test_scan_filing_and_visibility(ctx, _mock_engines):
    with TestClient(main.app) as c:
        s_p1 = _scan(c, ctx["member"], _target("a"), project_id=ctx["p1"])
        s_plain = _scan(c, ctx["member"], _target("b"))
        s_scoped = _scan(c, ctx["p_member"], _target("c"))  # pinned to p1
        # Org-wide member sees everything.
        ids = {s["id"] for s in c.get("/api/scans", headers=_h(ctx["member"])).json()}
        assert {s_p1, s_plain, s_scoped} <= ids
        # Project-scoped key sees only its own project's scans.
        ids = {s["id"] for s in
               c.get("/api/scans", headers=_h(ctx["p_member"])).json()}
        assert s_p1 in ids and s_scoped in ids and s_plain not in ids
        # Direct fetch of another project's scan -> 404.
        assert c.get(f"/api/scans/{s_plain}",
                     headers=_h(ctx["p_member"])).status_code == 404
        # Scoped key cannot file into another project.
        r = c.post("/api/scans", headers=_h(ctx["p_member"]),
                   data={"target_path": _target("d"), "project_id": ctx["p2"]})
        assert r.status_code == 403, r.text
        # Unknown project_id -> 400.
        r = c.post("/api/scans", headers=_h(ctx["member"]),
                   data={"target_path": _target("e"), "project_id": "proj_nope"})
        assert r.status_code == 400, r.text


def test_project_key_minting_scope(ctx):
    pa = _h(ctx["p_admin"])
    with TestClient(main.app) as c:
        # Scoped admin mints a key in its own project: OK.
        r = c.post("/api/keys", headers=pa,
                   json={"name": "p1-ci", "role": "member",
                         "project_id": ctx["p1"]})
        assert r.status_code == 200, r.text
        assert r.json()["project_id"] == ctx["p1"]
        # Scoped admin cannot mint org-wide keys: no scope escape.
        r = c.post("/api/keys", headers=pa,
                   json={"name": "evil", "role": "member"})
        assert r.status_code == 403, r.text
        # ...nor keys for another project.
        r = c.post("/api/keys", headers=pa,
                   json={"name": "evil", "role": "member",
                         "project_id": ctx["p2"]})
        assert r.status_code == 403, r.text
        # Scoped key listing shows only its project's keys.
        listed = c.get("/api/keys", headers=pa).json()
        assert listed and all(k["project_id"] == ctx["p1"] for k in listed)
        # The minted key is project-scoped and sees only p1.
        minted = r = c.post("/api/keys", headers=pa,
                            json={"name": "p1b", "role": "viewer",
                                  "project_id": ctx["p1"]}).json()["key"]
        projs = c.get("/api/projects", headers=_h(minted)).json()
        assert [p["id"] for p in projs] == [ctx["p1"]]


def test_org_surfaces_reject_scoped_keys(ctx):
    pm = _h(ctx["p_member"])
    with TestClient(main.app) as c:
        assert c.get("/api/audit-log", headers=pm).status_code == 403
        assert c.get("/api/usage", headers=pm).status_code == 403
        assert c.get("/api/subscription", headers=pm).status_code == 403
        # ...but org-wide keys still pass.
        assert c.get("/api/audit-log", headers=_h(ctx["member"])).status_code == 200


def test_delete_project_with_scans_refused(ctx, _mock_engines):
    a = _h(ctx["admin"])
    with TestClient(main.app) as c:
        _scan(c, ctx["member"], _target("f"), project_id=ctx["p1"])
        r = c.delete(f"/api/projects/{ctx['p1']}", headers=a)
        assert r.status_code == 400, r.text
        assert "scan" in r.json()["detail"]


def test_project_audit_trail(ctx):
    a = _h(ctx["admin"])
    with TestClient(main.app) as c:
        r = c.post("/api/projects", headers=a, json={"name": "tmp-audit"})
        pid = r.json()["project_id"]
        c.delete(f"/api/projects/{pid}", headers=a)
        log = c.get("/api/audit-log", headers=_h(ctx["member"])).json()
    acts = {(e["action"], e["resource_id"]) for e in log}
    assert ("project.created", pid) in acts
    assert ("project.deleted", pid) in acts


def test_projects_are_org_isolated(ctx):
    other_admin = provision_key(ctx["other"], "a", actor="owner", role="admin")
    with TestClient(main.app) as c:
        # Other org cannot use Hooli's project id.
        r = c.post("/api/scans", headers=_h(other_admin),
                   data={"target_path": _target("g"), "project_id": ctx["p1"]})
        assert r.status_code in (400, 403), r.text
        # Other org's project list is empty.
        assert c.get("/api/projects", headers=_h(other_admin)).json() == []
