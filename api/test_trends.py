"""Tests for vulnerability trends over time (GET /api/trends).

- one point per completed scan, chronological: totals, severity split,
  new vs fixed findings (fingerprint = tool|rule_id|file|message)
- filters: days window, project_id
- isolation: org-scoped, project-scoped keys, RBAC (viewer reads)
- validation: bad days, unknown/foreign project, non-done scans excluded
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-trends-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-trends-master-key")
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
    org = create_org(f"TrendsCo_{uid}", plan="free")
    other = create_org(f"TrendsOther_{uid}", plan="free")
    admin = provision_key(org, "t-admin", actor="owner", role="admin")
    viewer = provision_key(org, "t-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "o-member", actor="owner", role="member")
    p1 = create_project(org, f"Proj1_{uid}", actor="owner")
    p2 = create_project(org, f"Proj2_{uid}", actor="owner")
    scoped = provision_key(org, "t-scoped", actor="owner", role="member",
                           project_id=p1)
    return {"org": org, "other": other, "admin": admin, "viewer": viewer,
            "o_member": o_member, "p1": p1, "p2": p2, "scoped": scoped,
            "uid": uid}


def _mk_scan(org, scan_id, days_ago, status, findings, project_id=None,
             target="api"):
    """findings: list of (tool, rule_id, severity, message, file)."""
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, project_id, target_name, status,"
        " created_at, total_findings) VALUES (?,?,?,?,?,?,?)",
        (scan_id, org, project_id, target, status, _ts(days_ago),
         len(findings)))
    for tool, rule, sev, msg, f in findings:
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, tool, rule, sev, msg, f, 10, 1))
    db.commit()
    db.close()


def _get(c, key, qs=""):
    return c.get(f"/api/trends{qs}", headers=_h(key))


# ---------------------------------------------------------------------------
# Core: points, severity split, new/fixed, summary trend
# ---------------------------------------------------------------------------

def test_points_new_fixed_and_trend(ctx):
    uid = ctx["uid"]
    a = ("semgrep", "r-a", "error", "msg-a", "a.py")
    b = ("semgrep", "r-b", "warning", "msg-b", "b.py")
    c = ("gitleaks", "r-c", "note", "msg-c", "c.py")
    d = ("semgrep", "r-d", "error", "msg-d", "d.py")
    _mk_scan(ctx["org"], f"ts1_{uid}", 20, "done", [a, b, c])
    _mk_scan(ctx["org"], f"ts2_{uid}", 10, "done", [a, b, d])
    _mk_scan(ctx["org"], f"ts3_{uid}", 1, "done", [a])
    r = _get(TestClient(main.app), ctx["admin"], "?days=0")
    assert r.status_code == 200, r.text
    data = r.json()
    pts = data["points"]
    assert len(pts) == 3
    # chronological
    assert [p["scan_id"] for p in pts] == \
        [f"ts1_{uid}", f"ts2_{uid}", f"ts3_{uid}"]
    p1, p2, p3 = pts
    assert p1["total"] == 3 and p1["new"] == 3 and p1["fixed"] == 0
    assert p1["by_severity"] == {"error": 1, "warning": 1, "note": 1}
    assert p2["total"] == 3 and p2["new"] == 1 and p2["fixed"] == 1
    assert p2["by_severity"]["error"] == 2
    assert p3["total"] == 1 and p3["new"] == 0 and p3["fixed"] == 2
    s = data["summary"]
    assert s["scans"] == 3
    assert s["latest_total"] == 1 and s["previous_total"] == 3
    assert s["delta"] == -2 and s["trend"] == "improving"


def test_trend_worsening_and_stable(ctx):
    uid = ctx["uid"]
    a = ("semgrep", "r-a", "error", "msg-a", "a.py")
    b = ("semgrep", "r-b", "warning", "msg-b", "b.py")
    _mk_scan(ctx["org"], f"ws1_{uid}", 5, "done", [a])
    _mk_scan(ctx["org"], f"ws2_{uid}", 2, "done", [a, b])
    r = _get(TestClient(main.app), ctx["admin"], "?days=0")
    assert r.json()["summary"]["trend"] == "worsening"
    # stable: same findings twice
    _mk_scan(ctx["org"], f"ws3_{uid}", 1, "done", [a, b])
    r = _get(TestClient(main.app), ctx["admin"], "?days=0")
    assert r.json()["summary"]["trend"] == "stable"
    assert r.json()["summary"]["delta"] == 0


def test_trend_insufficient_single_scan(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"is1_{uid}", 1, "done",
             [("semgrep", "r-a", "error", "m", "a.py")])
    s = _get(TestClient(main.app), ctx["admin"], "?days=0").json()["summary"]
    assert s["trend"] == "insufficient"
    assert s["previous_total"] is None
    assert s["scans"] == 1


def test_non_done_scans_excluded(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"nd1_{uid}", 3, "done",
             [("semgrep", "r-a", "error", "m", "a.py")])
    _mk_scan(ctx["org"], f"nd2_{uid}", 1, "failed",
             [("semgrep", "r-b", "warning", "m", "b.py")])
    _mk_scan(ctx["org"], f"nd3_{uid}", 1, "queued",
             [("semgrep", "r-c", "note", "m", "c.py")])
    pts = _get(TestClient(main.app), ctx["admin"], "?days=0").json()["points"]
    assert [p["scan_id"] for p in pts] == [f"nd1_{uid}"]


# ---------------------------------------------------------------------------
# Filters: days window + project
# ---------------------------------------------------------------------------

def test_days_filter(ctx):
    uid = ctx["uid"]
    f = ("semgrep", "r-a", "error", "m", "a.py")
    _mk_scan(ctx["org"], f"df_old_{uid}", 60, "done", [f])
    _mk_scan(ctx["org"], f"df_new_{uid}", 5, "done", [f])
    c = TestClient(main.app)
    assert [p["scan_id"] for p in
            _get(c, ctx["admin"], "?days=30").json()["points"]] == \
        [f"df_new_{uid}"]
    assert len(_get(c, ctx["admin"], "?days=90").json()["points"]) == 2
    assert len(_get(c, ctx["admin"], "?days=0").json()["points"]) == 2
    r = _get(c, ctx["admin"], "?days=-1")
    assert r.status_code == 400


def test_project_filter(ctx):
    uid = ctx["uid"]
    f = ("semgrep", "r-a", "error", "m", "a.py")
    _mk_scan(ctx["org"], f"pf1_{uid}", 2, "done", [f], project_id=ctx["p1"])
    _mk_scan(ctx["org"], f"pf2_{uid}", 1, "done", [f, f], project_id=ctx["p2"])
    _mk_scan(ctx["org"], f"pf3_{uid}", 1, "done", [f])  # unscoped
    c = TestClient(main.app)
    pts = _get(c, ctx["admin"],
               f"?days=0&project_id={ctx['p1']}").json()["points"]
    assert [p["scan_id"] for p in pts] == [f"pf1_{uid}"]
    all_pts = _get(c, ctx["admin"], "?days=0").json()["points"]
    assert {p["scan_id"] for p in all_pts} == \
        {f"pf1_{uid}", f"pf2_{uid}", f"pf3_{uid}"}
    # unknown project -> 404
    r = _get(c, ctx["admin"], "?days=0&project_id=nope")
    assert r.status_code == 404
    # another org's project id -> 404 (not leaked)
    db = get_db()
    foreign = db.execute(
        "SELECT id FROM projects WHERE org_id=?", (ctx["other"],)).fetchone()
    db.close()
    if foreign is None:
        foreign_pid = create_project(ctx["other"], f"FP_{uid}", actor="owner")
    else:
        foreign_pid = foreign["id"]
    r = _get(c, ctx["admin"], f"?days=0&project_id={foreign_pid}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Isolation + RBAC
# ---------------------------------------------------------------------------

def test_org_isolation(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"oi1_{uid}", 1, "done",
             [("semgrep", "r-a", "error", "m", "a.py")])
    c = TestClient(main.app)
    data = _get(c, ctx["o_member"], "?days=0").json()
    assert data["points"] == []
    assert data["summary"]["scans"] == 0


def test_viewer_can_read(ctx):
    uid = ctx["uid"]
    _mk_scan(ctx["org"], f"vr1_{uid}", 1, "done",
             [("semgrep", "r-a", "error", "m", "a.py")])
    r = _get(TestClient(main.app), ctx["viewer"], "?days=0")
    assert r.status_code == 200
    assert len(r.json()["points"]) == 1


def test_project_scoped_key(ctx):
    uid = ctx["uid"]
    f = ("semgrep", "r-a", "error", "m", "a.py")
    _mk_scan(ctx["org"], f"sk1_{uid}", 2, "done", [f], project_id=ctx["p1"])
    _mk_scan(ctx["org"], f"sk2_{uid}", 1, "done", [f], project_id=ctx["p2"])
    c = TestClient(main.app)
    # no param: locked to its own project
    pts = _get(c, ctx["scoped"], "?days=0").json()["points"]
    assert [p["scan_id"] for p in pts] == [f"sk1_{uid}"]
    # asking for its own project explicitly: fine
    pts = _get(c, ctx["scoped"],
               f"?days=0&project_id={ctx['p1']}").json()["points"]
    assert [p["scan_id"] for p in pts] == [f"sk1_{uid}"]
    # asking for another project: 403
    r = _get(c, ctx["scoped"], f"?days=0&project_id={ctx['p2']}")
    assert r.status_code == 403


def test_unauthorized_rejected():
    r = TestClient(main.app).get("/api/trends?days=0")
    assert r.status_code == 401
