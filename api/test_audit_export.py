"""Tests for audit-trail CSV export (GET /api/audit-log/export.csv).

- correct headers + content-type + download filename
- rows newest-first, detail embedded as JSON, RFC 4180 quoting intact
- action filter honored
- org isolation: another org's trail is invisible
- 401 without a key; project-scoped keys rejected (same as /api/audit-log)
"""
import csv
import io
import os
import sys
import tempfile

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-auditexp-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-auditexp-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import audit  # noqa: E402
from billing import (create_org, create_project, ensure_owner_org,  # noqa: E402
                     provision_key, seed_plans)
from database import init_db  # noqa: E402

init_db()
seed_plans()


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


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = _uid()
    a = create_org(f"AudExpA_{uid}", plan="free")
    b = create_org(f"AudExpB_{uid}", plan="free")
    admin = provision_key(a, "ae-admin", actor="owner", role="admin")
    b_admin = provision_key(b, "ae-badmin", actor="owner", role="admin")
    p1 = create_project(a, f"AudExpProj_{uid}", actor="owner")
    scoped = provision_key(a, "ae-scoped", actor="owner", role="member",
                           project_id=p1)
    return {"a": a, "b": b, "admin": admin, "b_admin": b_admin,
            "scoped": scoped, "uid": uid}


def _log(org, actor, action, detail=None):
    audit.log_event(org, actor, action, detail=detail or {})


def _export(key, qs=""):
    c = TestClient(main.app)
    return c.get(f"/api/audit-log/export.csv{qs}", headers=_h(key))


# ---------------------------------------------------------------------------

def test_audit_csv_shape_and_order(ctx):
    _log(ctx["a"], "owner", "scan.created",
         {"target": "x", "note": 'with "quotes", and, commas'})
    _log(ctx["a"], "owner", "scan.completed", {"findings": 3})
    r = _export(ctx["admin"])
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert f'braimsec-audit-{ctx["a"]}.csv' in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0] == ["id", "created_at", "actor", "action", "detail"]
    mine = [row for row in rows[1:]
            if row[3] in ("scan.created", "scan.completed")]
    assert len(mine) == 2
    # newest first
    assert mine[0][3] == "scan.completed"
    assert mine[1][3] == "scan.created"
    # detail is embedded JSON and quoting round-trips
    import json
    d = json.loads(mine[1][4])
    assert d["note"] == 'with "quotes", and, commas'


def test_audit_csv_action_filter(ctx):
    _log(ctx["a"], "owner", "scan.created", {})
    _log(ctx["a"], "owner", "api_key.created", {})
    r = _export(ctx["admin"], "?action=scan.created")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert len(rows) == 2
    assert rows[1][3] == "scan.created"


def test_audit_csv_isolation_and_auth(ctx):
    _log(ctx["a"], "owner", "scan.created",
         {"marker": f"only-org-a-{ctx['uid']}"})
    c = TestClient(main.app)
    assert c.get("/api/audit-log/export.csv").status_code == 401
    # other org never sees org A's rows
    r = _export(ctx["b_admin"])
    assert f"only-org-a-{ctx['uid']}" not in r.text
    # project-scoped key rejected like /api/audit-log
    assert _export(ctx["scoped"]).status_code in (400, 403)
