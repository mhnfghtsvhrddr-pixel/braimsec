"""Tests for scan diff (GET /api/scans/{id}/diff?against={other_id}).

- three-way split (new / fixed / persisting) by stable fingerprint
  (tool|rule_id|file|message — line/column insensitive)
- summary numbers: counts, fix_rate, severity splits
- guards: 404 foreign scan, 400 non-done / self / target mismatch /
  project mismatch, 422 missing `against`
- isolation: org-scoped, project-scoped keys, RBAC (viewer reads)
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-diff-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-diff-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from billing import (create_org, create_project, ensure_owner_org,  # noqa: E402
                     provision_key, seed_plans)
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()
MASTER = os.environ["BRAIMSEC_API_KEY"]


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


def _uid():
    import uuid as _u
    return _u.uuid4().hex[:8]


def _h(key):
    return {"X-API-Key": key}


def _ts(days_ago=0):
    return (datetime.now(timezone.utc) -
            timedelta(days=days_ago)).isoformat()


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = _uid()
    org = create_org(f"DiffCo_{uid}", plan="free")
    other = create_org(f"DiffOther_{uid}", plan="free")
    admin = provision_key(org, "d-admin", actor="owner", role="admin")
    viewer = provision_key(org, "d-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "o-member", actor="owner", role="member")
    p1 = create_project(org, f"DProj1_{uid}", actor="owner")
    p2 = create_project(org, f"DProj2_{uid}", actor="owner")
    scoped = provision_key(org, "d-scoped", actor="owner", role="member",
                           project_id=p1)
    return {"org": org, "other": other, "admin": admin, "viewer": viewer,
            "o_member": o_member, "p1": p1, "p2": p2, "scoped": scoped,
            "uid": uid}


def _mk_scan(org, scan_id, days_ago, status, findings, project_id=None,
             target="api"):
    """findings: list of (tool, rule_id, severity, message, file, line)."""
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, project_id, target_name, status,"
        " created_at, total_findings) VALUES (?,?,?,?,?,?,?)",
        (scan_id, org, project_id, target, status, _ts(days_ago),
         len(findings)))
    for tool, rule, sev, msg, f, line in findings:
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, tool, rule, sev, msg, f, line, 1))
    db.commit()
    db.close()


def _diff(c, key, scan_id, against=None):
    qs = f"?against={against}" if against else ""
    return c.get(f"/api/scans/{scan_id}/diff{qs}", headers=_h(key))


# ---------------------------------------------------------------------------
# Core: three-way split and numbers
# ---------------------------------------------------------------------------

def test_diff_split_and_numbers(ctx):
    uid = ctx["uid"]
    # line-insensitive: `a` moved from line 10 to line 40 -> still persisting
    a_old = ("semgrep", "r-a", "error", "msg-a", "a.py", 10)
    a_new = ("semgrep", "r-a", "error", "msg-a", "a.py", 40)
    b = ("semgrep", "r-b", "warning", "msg-b", "b.py", 10)
    c = ("gitleaks", "r-c", "note", "msg-c", "c.py", 10)
    d = ("semgrep", "r-d", "error", "msg-d", "d.py", 10)
    _mk_scan(ctx["org"], f"df1_{uid}", 5, "done", [a_old, b, c])
    _mk_scan(ctx["org"], f"df2_{uid}", 1, "done", [a_new, b, d])
    r = _diff(TestClient(main.app), ctx["admin"], f"df2_{uid}", f"df1_{uid}")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["scan"]["id"] == f"df2_{uid}"
    assert data["against"]["id"] == f"df1_{uid}"
    assert data["scan"]["total"] == 3
    assert data["against"]["total"] == 3
    sm = data["summary"]
    assert sm["new"] == 1 and sm["fixed"] == 1 and sm["persisting"] == 2
    # fix_rate = fixed / old_total
    assert sm["fix_rate"] == pytest.approx(1 / 3, abs=0.001)
    assert sm["new_by_severity"] == {"error": 1}
    assert sm["fixed_by_severity"] == {"note": 1}
    assert [f["rule_id"] for f in data["new"]] == ["r-d"]
    assert [f["rule_id"] for f in data["fixed"]] == ["r-c"]
    assert sorted(f["rule_id"] for f in data["persisting"]) == ["r-a", "r-b"]
    # persisting rows come from the NEW scan (line 40, not 10)
    ra = [f for f in data["persisting"] if f["rule_id"] == "r-a"][0]
    assert ra["line"] == 40


def test_diff_empty_old_scan_fix_rate_zero(ctx):
    uid = ctx["uid"]
    a = ("semgrep", "r-a", "error", "msg-a", "a.py", 10)
    _mk_scan(ctx["org"], f"de1_{uid}", 5, "done", [])
    _mk_scan(ctx["org"], f"de2_{uid}", 1, "done", [a])
    r = _diff(TestClient(main.app), ctx["admin"], f"de2_{uid}", f"de1_{uid}")
    assert r.status_code == 200, r.text
    sm = r.json()["summary"]
    assert sm["new"] == 1 and sm["fixed"] == 0 and sm["persisting"] == 0
    assert sm["fix_rate"] == 0.0


def test_viewer_can_read(ctx):
    uid = ctx["uid"]
    a = ("semgrep", "r-a", "error", "msg-a", "a.py", 10)
    _mk_scan(ctx["org"], f"dv1_{uid}", 5, "done", [a])
    _mk_scan(ctx["org"], f"dv2_{uid}", 1, "done", [a])
    r = _diff(TestClient(main.app), ctx["viewer"], f"dv2_{uid}", f"dv1_{uid}")
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

def test_missing_against_is_422(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"dg1_{uid}", 1, "done", [])
    r = _diff(TestClient(main.app), ctx["admin"], f"dg1_{uid}")
    assert r.status_code == 422


def test_unknown_scan_404(ctx):
    r = _diff(TestClient(main.app), ctx["admin"], "nope", "alsono")
    assert r.status_code == 404


def test_nondone_scan_400(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"dn1_{uid}", 2, "done", [])
    _mk_scan(ctx["org"], f"dn2_{uid}", 1, "running", [])
    r = _diff(TestClient(main.app), ctx["admin"], f"dn2_{uid}", f"dn1_{uid}")
    assert r.status_code == 400
    assert "not completed" in r.json()["detail"]


def test_self_diff_400(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"ds1_{uid}", 1, "done", [])
    r = _diff(TestClient(main.app), ctx["admin"], f"ds1_{uid}", f"ds1_{uid}")
    assert r.status_code == 400


def test_target_mismatch_400(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"dt1_{uid}", 2, "done", [], target="api")
    _mk_scan(ctx["org"], f"dt2_{uid}", 1, "done", [], target="web")
    r = _diff(TestClient(main.app), ctx["admin"], f"dt2_{uid}", f"dt1_{uid}")
    assert r.status_code == 400
    assert "different codebases" in r.json()["detail"]


def test_project_mismatch_400(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"dp1_{uid}", 2, "done", [], project_id=ctx["p1"])
    _mk_scan(ctx["org"], f"dp2_{uid}", 1, "done", [], project_id=ctx["p2"])
    r = _diff(TestClient(main.app), ctx["admin"], f"dp2_{uid}", f"dp1_{uid}")
    assert r.status_code == 400
    assert "different projects" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------

def test_foreign_org_scan_404(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"df_own_{uid}", 1, "done", [])
    _mk_scan(ctx["other"], f"df_for_{uid}", 2, "done", [])
    # other org's member cannot touch our scan
    r = _diff(TestClient(main.app), ctx["o_member"], f"df_own_{uid}",
              f"df_for_{uid}")
    assert r.status_code == 404
    # our admin cannot touch the foreign scan either
    r = _diff(TestClient(main.app), ctx["admin"], f"df_own_{uid}",
              f"df_for_{uid}")
    assert r.status_code == 404


def test_project_scoped_key(ctx):
    uid = ctx["uid"]
    a = ("semgrep", "r-a", "error", "msg-a", "a.py", 10)
    _mk_scan(ctx["org"], f"dk1_{uid}", 2, "done", [a], project_id=ctx["p1"])
    _mk_scan(ctx["org"], f"dk2_{uid}", 1, "done", [a], project_id=ctx["p1"])
    _mk_scan(ctx["org"], f"dk3_{uid}", 1, "done", [a], project_id=ctx["p2"])
    # scoped key diffs its own project's scans fine
    r = _diff(TestClient(main.app), ctx["scoped"], f"dk2_{uid}", f"dk1_{uid}")
    assert r.status_code == 200, r.text
    # but cannot reach the other project's scan
    r = _diff(TestClient(main.app), ctx["scoped"], f"dk2_{uid}", f"dk3_{uid}")
    assert r.status_code == 404


def test_unauthorized_401(ctx):
    r = _diff(TestClient(main.app), "bogus", "x", "y")
    assert r.status_code == 401
