"""GET /api/scans/{id}/report.pdf tests.

- 200 + application/pdf + Content-Disposition + ETag/304
- 404 cross-org isolation, 401 without key, 409 when scan not done
- deterministic per scan

DB isolation: BRAIMSEC_DB points at a tmp file BEFORE any import.
"""
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-report-test-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from billing import create_org, provision_key  # noqa: E402
from database import get_db, init_db  # noqa: E402


@pytest.fixture()
def seeded():
    init_db()
    org_id = create_org("rep-" + os.urandom(3).hex(), plan="pro")
    headers = {"x-api-key": provision_key(org_id)}
    db = get_db()
    scan_id = "scan_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " finished_at, engines_json) VALUES (?,?,?,?,?,?,?)",
        (scan_id, org_id, "acme", "done", "2026-01-01T00:00:00+00:00",
         "2026-01-01T00:01:00+00:00",
         '{"semgrep": "1.178.0", "gitleaks": "8.18.0",'
         ' "braimsec_taint_rules": "braimsec-taint.yaml@abc123"}'))
    db.execute(
        "INSERT INTO findings (scan_id, tool, rule_id, severity, message,"
        " file, line, col, ai_verdict, ai_confidence, ai_explanation)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, "semgrep", "r.braimsec.taint.ssrf-requests", "error",
         "ssrf", "app.py", 6, 5, "vulnerable", 0.95,
         "ثغرة SSRF مؤكدة عبر requests.get"))
    db.execute(
        "INSERT INTO findings (scan_id, tool, rule_id, severity, message,"
        " file, line, col) VALUES (?,?,?,?,?,?,?,?)",
        (scan_id, "gitleaks", "generic-api-key", "error",
         "leaked secret", ".env", 3, 1))
    running = "scan_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        (running, org_id, "acme", "queued", "2026-01-01T00:00:00+00:00"))
    db.commit()
    db.close()
    return headers, org_id, scan_id, running


def test_pdf_endpoint(seeded):
    headers, _, scan_id, _ = seeded
    with TestClient(main.app) as c:
        r = c.get(f"/api/scans/{scan_id}/report.pdf", headers=headers)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert "braimsec-" in r.headers["content-disposition"]
    assert r.content.startswith(b"%PDF-")
    etag = r.headers["etag"]
    assert etag
    with TestClient(main.app) as c:
        r2 = c.get(f"/api/scans/{scan_id}/report.pdf", headers=headers)
        r3 = c.get(f"/api/scans/{scan_id}/report.pdf",
                   headers={**headers, "if-none-match": etag})
    assert r2.headers["etag"] == etag, "deterministic per scan"
    assert r3.status_code == 304


def test_not_done_409(seeded):
    headers, _, _, running = seeded
    with TestClient(main.app) as c:
        r = c.get(f"/api/scans/{running}/report.pdf", headers=headers)
    assert r.status_code == 409


def test_cross_org_404_and_401(seeded):
    _, _, scan_id, _ = seeded
    org2 = create_org("other-" + os.urandom(3).hex(), plan="pro")
    h2 = {"x-api-key": provision_key(org2)}
    with TestClient(main.app) as c:
        assert c.get(f"/api/scans/{scan_id}/report.pdf",
                     headers=h2).status_code == 404
        assert c.get(f"/api/scans/{scan_id}/report.pdf").status_code == 401
