"""GET /api/findings/{id}/taint-flow tests.

- happy path: linear trace with tri-state sanitization verdict
- sanitized variant -> verdict sanitized
- 404 isolation across orgs, 401 without key
- sources deleted -> available False (zero-retention honesty)
- semgrep binary forced missing so the AST fallback is exercised
  deterministically (no ~3s subprocess in the API suite)

DB isolation: BRAIMSEC_DB points at a tmp file BEFORE any import.
"""
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-tflow-test-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import taintflow  # noqa: E402
from billing import create_org, provision_key  # noqa: E402
from database import get_db, init_db  # noqa: E402

VULN_SRC = """\
import requests
from flask import request

def fetch():
    raw = request.args.get("u")
    cleaned = raw.strip()
    url = "https://" + cleaned
    return requests.get(url, timeout=5).text
"""

SAFE_SRC = """\
import html
import requests
from flask import request

def fetch():
    raw = request.args.get("u")
    safe = html.escape(raw)
    return requests.get("https://x/" + safe, timeout=5).text
"""


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    """Fresh org + scan (target_dir=tmp) + two findings, semgrep disabled."""
    monkeypatch.setattr(taintflow, "SEMGREP_BIN", "/nonexistent/semgrep")
    init_db()
    org_id = create_org("tflow-" + os.urandom(3).hex(), plan="pro")
    headers = {"x-api-key": provision_key(org_id)}
    (tmp_path / "vuln.py").write_text(VULN_SRC)
    (tmp_path / "safe.py").write_text(SAFE_SRC)
    db = get_db()
    scan_id = "scan_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " target_dir) VALUES (?,?,?,?,?,?)",
        (scan_id, org_id, "t", "done", "2026-01-01T00:00:00+00:00",
         str(tmp_path)))
    cur = db.execute(
        "INSERT INTO findings (scan_id, tool, rule_id, severity, message,"
        " file, line, col) VALUES (?,?,?,?,?,?,?,?)",
        (scan_id, "semgrep", "braimsec.taint.ssrf-requests", "error",
         "ssrf", "vuln.py", 8, 5))
    vuln_id = cur.lastrowid
    cur = db.execute(
        "INSERT INTO findings (scan_id, tool, rule_id, severity, message,"
        " file, line, col) VALUES (?,?,?,?,?,?,?,?)",
        (scan_id, "semgrep", "braimsec.taint.ssrf-requests", "error",
         "ssrf", "safe.py", 8, 5))
    safe_id = cur.lastrowid
    db.commit()
    db.close()
    return vuln_id, safe_id, headers, org_id, scan_id


def test_happy_path_linear_trace(seeded):
    vuln_id, _, headers, _, _ = seeded
    with TestClient(main.app) as c:
        r = c.get(f"/api/findings/{vuln_id}/taint-flow", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is True
    assert body["trace_origin"] == "ast-slice"
    types = [s["type"] for s in body["taint_path"]]
    assert types == ["source", "propagation", "propagation", "sink"]
    assert [s["line"] for s in body["taint_path"]] == [5, 6, 7, 8]
    assert body["sanitization"]["verdict"] == "unsanitized"
    assert body["limits"], "honest limits must be present"


def test_sanitized_verdict(seeded):
    _, safe_id, headers, _, _ = seeded
    with TestClient(main.app) as c:
        r = c.get(f"/api/findings/{safe_id}/taint-flow", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["sanitization"]["verdict"] == "sanitized"


def test_other_org_gets_404(seeded):
    vuln_id, _, _, _, _ = seeded
    org2 = create_org("other-" + os.urandom(3).hex(), plan="pro")
    h2 = {"x-api-key": provision_key(org2)}
    with TestClient(main.app) as c:
        r = c.get(f"/api/findings/{vuln_id}/taint-flow", headers=h2)
    assert r.status_code == 404


def test_missing_finding_404(seeded):
    _, _, headers, _, _ = seeded
    with TestClient(main.app) as c:
        r = c.get("/api/findings/999999/taint-flow", headers=headers)
    assert r.status_code == 404


def test_no_key_401(seeded):
    vuln_id, _, _, _, _ = seeded
    with TestClient(main.app) as c:
        r = c.get(f"/api/findings/{vuln_id}/taint-flow")
    assert r.status_code == 401


def test_sources_deleted_reports_unavailable(seeded):
    vuln_id, _, headers, org_id, scan_id = seeded
    db = get_db()
    db.execute("UPDATE scans SET target_dir=? WHERE id=?",
               ("/nonexistent/dir", scan_id))
    db.commit()
    db.close()
    with TestClient(main.app) as c:
        r = c.get(f"/api/findings/{vuln_id}/taint-flow", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False
    assert "zero-retention" in body["reason"]
