"""POST /api/reports/executive tests.

- 200 + application/pdf + Content-Disposition on seeded data
- 401 without key; viewer role may read
- body validation: days < 0 / non-integer -> 400
- days filter: old-only org -> 404 with days=30, 200 with days=0
- 404 with no completed scans; cross-org isolation; project filters
- project-scoped key on another project -> 403

Env: setdefault (see AGENTS.md); keys are provisioned per org.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault(
    "BRAIMSEC_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "braimsec-test-exec.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-executive-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from billing import create_org, create_project, provision_key  # noqa: E402
from database import get_db, init_db  # noqa: E402


def _iso(days_ago):
    return (datetime.now(timezone.utc) -
            timedelta(days=days_ago)).isoformat()


def _seed_scan(db, org_id, sid, created, project_id=None, nfind=0):
    db.execute(
        "INSERT INTO scans (id, org_id, project_id, target_name, status,"
        " created_at, finished_at, total_findings)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (sid, org_id, project_id, "webapp", "done", created, created,
         nfind))
    for i in range(nfind):
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (sid, "semgrep", f"x.braimsec.test.rule-{i}", "error",
             f"finding {i}", "app.py", i + 1, 1))


@pytest.fixture()
def env():
    init_db()
    db = get_db()
    org_a = create_org("exec-a-" + os.urandom(3).hex(), plan="pro")
    org_b = create_org("exec-b-" + os.urandom(3).hex(), plan="pro")
    pid = create_project(org_a, "Web")
    uid = os.urandom(4).hex()
    # old scan (outside days=30) + recent scan (inside) with findings
    _seed_scan(db, org_a, "es_old_" + uid, _iso(400), nfind=4)
    _seed_scan(db, org_a, "es_new_" + uid, _iso(5), project_id=pid, nfind=3)
    db.commit()
    db.close()
    return {
        "client": TestClient(main.app),
        "org_a": org_a,
        "org_b": org_b,
        "pid": pid,
        "member_a": {"x-api-key": provision_key(org_a, role="member")},
        "viewer_a": {"x-api-key": provision_key(org_a, role="viewer")},
        "member_b": {"x-api-key": provision_key(org_b, role="member")},
        "proj_key": {"x-api-key": provision_key(
            org_a, role="member", project_id=pid)},
    }


def _post(client, body, headers=None):
    return client.post("/api/reports/executive", json=body,
                       headers=headers or {})


def test_happy_path_pdf(env):
    r = _post(env["client"], {}, headers=env["member_a"])
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert "attachment" in r.headers["content-disposition"]
    assert "braimsec-executive-report.pdf" in r.headers["content-disposition"]
    assert r.content.startswith(b"%PDF-")


def test_no_key_401(env):
    assert _post(env["client"], {}).status_code == 401


def test_viewer_may_read(env):
    r = _post(env["client"], {}, headers=env["viewer_a"])
    assert r.status_code == 200


def test_days_validation(env):
    for bad in (-1, -30, "abc", [1]):
        r = _post(env["client"], {"days": bad}, headers=env["member_a"])
        assert r.status_code == 400, bad


def test_days_filter(env):
    # org B has no scans at all -> 404 either way
    r = _post(env["client"], {"days": 0}, headers=env["member_b"])
    assert r.status_code == 404
    # org A: days=30 excludes the 400-day-old scan but keeps the recent
    # one -> 200 (report is over the recent scan only)
    r = _post(env["client"], {"days": 30}, headers=env["member_a"])
    assert r.status_code == 200
    # days=0 includes everything -> 200
    r = _post(env["client"], {"days": 0}, headers=env["member_a"])
    assert r.status_code == 200


def test_days_filter_all_old_404(env):
    db = get_db()
    org_c = create_org("exec-c-" + os.urandom(3).hex(), plan="pro")
    _seed_scan(db, org_c, "es_cold_" + os.urandom(4).hex(), _iso(400),
               nfind=2)
    db.commit()
    db.close()
    key_c = {"x-api-key": provision_key(org_c, role="member")}
    r = _post(env["client"], {"days": 30}, headers=key_c)
    assert r.status_code == 404
    r = _post(env["client"], {"days": 0}, headers=key_c)
    assert r.status_code == 200


def test_project_filter(env):
    r = _post(env["client"], {"project_id": env["pid"]},
              headers=env["member_a"])
    assert r.status_code == 200
    # unknown project -> 404
    r = _post(env["client"], {"project_id": "proj_nope"},
              headers=env["member_a"])
    assert r.status_code == 404
    # other org's key cannot see org A's project -> 404 (not 403 leak)
    r = _post(env["client"], {"project_id": env["pid"]},
              headers=env["member_b"])
    assert r.status_code == 404


def test_project_scoped_key_wrong_project_403(env):
    r = _post(env["client"], {"project_id": "proj_other"},
              headers=env["proj_key"])
    assert r.status_code == 403
    # scoped key without a body project filter uses its own project -> 200
    r = _post(env["client"], {}, headers=env["proj_key"])
    assert r.status_code == 200
