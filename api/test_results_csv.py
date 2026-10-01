"""Tests for CSV export (GET /api/scans/{id}/results.csv).

- correct headers + content-type + download filename
- RFC 4180: messages with commas/quotes/newlines round-trip via csv.reader
- severity filter honored
- 404 for a missing or foreign-org scan; 401 without a key
- org isolation: another org's scan id -> 404
"""
import csv
import io
import os
import sys
import tempfile
from datetime import datetime, timezone

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-csv-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-csv-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
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


def _uid():
    import uuid as _u
    return _u.uuid4().hex[:8]


def _h(key):
    return {"X-API-Key": key}


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = _uid()
    org = create_org(f"CsvCo_{uid}", plan="free")
    other = create_org(f"CsvOther_{uid}", plan="free")
    admin = provision_key(org, "c-admin", actor="owner", role="admin")
    o_member = provision_key(other, "c-omem", actor="owner", role="member")
    return {"org": org, "other": other, "admin": admin,
            "o_member": o_member, "uid": uid}


def _mk_scan(org, scan_id, findings):
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " total_findings) VALUES (?,?,?,?,?,?)",
        (scan_id, org, "t", "done",
         datetime.now(timezone.utc).isoformat(), len(findings)))
    for tool, rule, sev, msg, f, line in findings:
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, tool, rule, sev, msg, f, line, 1))
    db.commit()
    db.close()


def _csv(key, scan_id, qs=""):
    c = TestClient(main.app)
    return c.get(f"/api/scans/{scan_id}/results.csv{qs}", headers=_h(key))


# ---------------------------------------------------------------------------

def test_csv_download_shape(ctx):
    sid = f"cv1_{ctx['uid']}"
    _mk_scan(ctx["org"], sid,
             [("semgrep", "r-a", "error", "plain message", "a.py", 10),
              ("gitleaks", "r-b", "note", "m2", "b.py", 20)])
    r = _csv(ctx["admin"], sid)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert f'braimsec-{sid}-results.csv' in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0] == list(main.CSV_COLUMNS)
    assert len(rows) == 3  # header + 2 findings
    by_rule = {row[2]: row for row in rows[1:]}
    assert by_rule["r-a"][3] == "error"
    assert by_rule["r-a"][4] == "a.py"
    assert by_rule["r-a"][7] == "plain message"


def test_csv_quoting_round_trip(ctx):
    sid = f"cv2_{ctx['uid']}"
    nasty = 'says "hi", then\nnew line, and; semicolon'
    _mk_scan(ctx["org"], sid, [("semgrep", "r-x", "error", nasty, "a.py", 1)])
    r = _csv(ctx["admin"], sid)
    rows = list(csv.reader(io.StringIO(r.text)))
    assert len(rows) == 2
    assert rows[1][7] == nasty


def test_csv_severity_filter(ctx):
    sid = f"cv3_{ctx['uid']}"
    _mk_scan(ctx["org"], sid,
             [("semgrep", "r-e", "error", "m1", "a.py", 1),
              ("semgrep", "r-w", "warning", "m2", "b.py", 2)])
    r = _csv(ctx["admin"], sid, "?severity=error")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert len(rows) == 2
    assert rows[1][2] == "r-e"


def test_csv_404_and_401(ctx):
    sid = f"cv4_{ctx['uid']}"
    _mk_scan(ctx["org"], sid, [("semgrep", "r1", "error", "m", "a.py", 1)])
    c = TestClient(main.app)
    # no key at all
    assert c.get(f"/api/scans/{sid}/results.csv").status_code == 401
    # unknown scan
    assert _csv(ctx["admin"], "nope_missing").status_code == 404
    # foreign org's scan is invisible -> 404, not 403 (no id oracle)
    assert _csv(ctx["o_member"], sid).status_code == 404
