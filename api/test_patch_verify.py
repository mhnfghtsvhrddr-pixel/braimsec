"""Closed-loop patch verification endpoint tests.

POST /api/findings/{id}/patch-verify — all deterministic, no LLM, no semgrep:
the engine is monkeypatched with a canned verdict (the real loop is covered
in ai/test_patch_verify.py). Covers: happy path + verdict persistence,
404 org isolation, 401, 400 when no suggestion is stored, 409 when scan
sources are gone, and zero quota consumption.

DB isolation: BRAIMSEC_DB points at a tmp file BEFORE any import.
"""
import json
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-patchverify-test-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from billing import (  # noqa: E402
    create_org, provision_key, usage_count,
)
from database import get_db, init_db  # noqa: E402

HEADERS = {"x-api-key": "test-key-123"}

VULN_SRC = ("from flask import request\n"
            "\n"
            "def download():\n"
            '    name = request.args.get("f")\n'
            "    data = open(name).read()\n"
            "    return data\n")

FAKE_DIFF = ("--- a/app.py\n+++ b/app.py\n"
             "@@ -1,6 +1,7 @@\n"
             " from flask import request\n"
             "+import os\n"
             " \n"
             " def download():\n")

CANNED = {"family": "path-traversal", "eligible": True, "applied": True,
          "fuzzy": False, "syntax_ok": True, "original_gone": True,
          "new_findings": [], "verified": True, "reason": "ok",
          "framing": "verified suggestion — requires human review"}


@pytest.fixture()
def seeded(tmp_path):
    """Fresh org (pro) + scan with target_dir + finding with a stored diff."""
    init_db()
    org_id = create_org("pvorg-" + os.urandom(3).hex(), plan="pro")
    headers = {"x-api-key": provision_key(org_id)}
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text(VULN_SRC)
    db = get_db()
    scan_id = "scan_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, target_dir, status,"
        " created_at) VALUES (?,?,?,?,?,?)",
        (scan_id, org_id, "t", str(target), "done",
         "2026-01-01T00:00:00+00:00"))
    cur = db.execute(
        "INSERT INTO findings (scan_id, tool, rule_id, severity, message,"
        " file, line, col, fix_diff, fix_checks, fix_generated_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, "semgrep", "braimsec.taint.path-traversal-open",
         "error", "m", "app.py", 5, 5, FAKE_DIFF, "{}", "2026-01-01T00:00:00"))
    finding_id = cur.lastrowid
    db.commit()
    db.close()
    return scan_id, finding_id, headers, org_id, str(target)


def _stub_verify(monkeypatch, verdict=None):
    calls = []

    def fake(finding, target_dir, diff):
        calls.append((finding, target_dir, diff))
        return dict(verdict or CANNED)

    monkeypatch.setattr(main, "verify_patch", fake)
    return calls


def test_verify_happy_path_and_persists(seeded, monkeypatch):
    _, finding_id, headers, _, target = seeded
    calls = _stub_verify(monkeypatch)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/patch-verify",
                   headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["finding_id"] == finding_id
    assert body["verification"]["verified"] is True
    assert body["verification"]["family"] == "path-traversal"
    # engine received the stored diff + resolved target dir + finding
    assert len(calls) == 1
    finding_arg, target_arg, diff_arg = calls[0]
    assert diff_arg == FAKE_DIFF
    assert target_arg == target
    assert finding_arg["rule_id"] == "braimsec.taint.path-traversal-open"
    assert finding_arg["line"] == 5
    # verdict persisted into fix_checks["verification"]
    db = get_db()
    row = db.execute("SELECT fix_checks FROM findings WHERE id=?",
                     (finding_id,)).fetchone()
    db.close()
    stored = json.loads(row["fix_checks"])
    assert stored["verification"]["verified"] is True


def test_verify_consumes_no_quota(seeded, monkeypatch):
    _, finding_id, headers, org_id, _ = seeded
    _stub_verify(monkeypatch)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/patch-verify",
                   headers=headers)
    assert r.status_code == 200, r.text
    assert usage_count(org_id, "ai_review") == 0
    assert usage_count(org_id, "scan") == 0


def test_verify_400_no_suggestion_real_finding(seeded, monkeypatch):
    _, finding_id, headers, _, _ = seeded
    _stub_verify(monkeypatch)
    db = get_db()
    db.execute("UPDATE findings SET fix_diff=NULL WHERE id=?", (finding_id,))
    db.commit()
    db.close()
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/patch-verify",
                   headers=headers)
    assert r.status_code == 400, r.text
    assert "fix-suggestion" in r.json()["detail"]


def test_verify_409_when_sources_deleted(seeded, monkeypatch, tmp_path):
    _, finding_id, headers, _, target = seeded
    _stub_verify(monkeypatch)
    import shutil
    shutil.rmtree(target)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/patch-verify",
                   headers=headers)
    assert r.status_code == 409, r.text


def test_verify_404_other_org_finding(seeded, monkeypatch):
    _, finding_id, _, _, _ = seeded
    _stub_verify(monkeypatch)
    org2 = create_org("other-" + os.urandom(3).hex(), plan="pro")
    other_headers = {"x-api-key": provision_key(org2)}
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/patch-verify",
                   headers=other_headers)
    assert r.status_code == 404, r.text


def test_verify_401_without_key(seeded, monkeypatch):
    _, finding_id, _, _, _ = seeded
    _stub_verify(monkeypatch)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/patch-verify")
    assert r.status_code == 401, r.text


def test_verify_failed_verdict_still_200(seeded, monkeypatch):
    _, finding_id, headers, _, _ = seeded
    bad = dict(CANNED, verified=False, original_gone=False,
               reason="patch applied but the original finding is still "
                      "reported after re-scan")
    _stub_verify(monkeypatch, verdict=bad)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/patch-verify",
                   headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["verification"]["verified"] is False
