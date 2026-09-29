"""Incremental (diff-based) scan tests.

Covers the PROPOSAL Part 2 increment through _run_scan_impl with stubbed
engines, plus the POST /api/scans baseline_scan_id contract.

DB isolation: BRAIMSEC_DB is pointed at a tmp file BEFORE any import (same
pattern as test_async_queue; harmless if that module already did it).
"""
import json
import os
import sys
import tempfile
from types import SimpleNamespace

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-incr-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import tasks  # noqa: E402
from database import get_db, init_db  # noqa: E402

HEADERS = {"x-api-key": "test-key-123"}


class FakeSelf:
    class RetryRaised(Exception):
        pass

    def __init__(self, max_retries=0):
        self.max_retries = max_retries
        self.request = SimpleNamespace(retries=0)

    def retry(self, exc=None, countdown=None):
        raise FakeSelf.RetryRaised()


@pytest.fixture()
def target(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("import a\n\ny = a.x\n")
    return tmp_path


def _mk_scan(org="owner"):
    init_db()
    db = get_db()
    scan_id = "iscan_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        (scan_id, org, "t", "queued", "2026-01-01T00:00:00+00:00"))
    db.commit()
    db.close()
    return scan_id


def _findings_of(scan_id):
    db = get_db()
    rows = db.execute("SELECT tool, rule_id, file, line FROM findings"
                      " WHERE scan_id=?", (scan_id,)).fetchall()
    scan = db.execute("SELECT status, incremental_of, fingerprint_json"
                      " FROM scans WHERE id=?", (scan_id,)).fetchone()
    db.close()
    return [dict(r) for r in rows], dict(scan)


@pytest.fixture()
def engines(monkeypatch):
    calls = {"semgrep": [], "gitleaks": [], "sca": []}

    def sg(target, scope=None):
        calls["semgrep"].append(scope)
        if scope is None:
            # full scan: one fake finding per .py file under target
            scope = [os.path.join(target, n) for n in sorted(os.listdir(target))
                     if n.endswith(".py")]
        # one fake finding per scoped file so the merge is observable
        return [{"tool": "semgrep", "rule_id": "r", "severity": "e",
                 "message": "m", "file": s, "line": 1, "col": 1}
                for s in scope]

    def gl(target, scope=None):
        calls["gitleaks"].append(scope)
        return []

    def sca(target):
        calls["sca"].append(target)
        return []

    monkeypatch.setattr(tasks, "run_semgrep", sg)
    monkeypatch.setattr(tasks, "run_gitleaks", gl)
    monkeypatch.setattr(tasks, "run_sca", sca)
    return calls


def _full_scan(target, engines):
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, str(target), None)
    return scan_id


# ---------------------------------------------------------------------------
# incremental behavior
# ---------------------------------------------------------------------------

def test_no_change_carries_findings_without_engines(target, engines):
    base = _full_scan(target, engines)
    n_calls = len(engines["semgrep"])
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, str(target), None,
                         baseline_scan_id=base)
    findings, scan = _findings_of(scan_id)
    assert scan["status"] == "done"
    assert scan["incremental_of"] == base
    assert len(engines["semgrep"]) == n_calls  # no engine ran again
    assert len(findings) == 2  # carried from baseline


def test_changed_file_rescans_with_import_hop(target, engines):
    base = _full_scan(target, engines)
    (target / "a.py").write_text("x = 2\n")  # b.py imports a -> hop
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, str(target), None,
                         baseline_scan_id=base)
    findings, scan = _findings_of(scan_id)
    scope = engines["semgrep"][-1]
    scope_basenames = {os.path.basename(s) for s in scope}
    assert {"a.py", "b.py"} <= scope_basenames  # changed + reverse hop
    assert scan["incremental_of"] == base
    assert len(findings) == 2  # fresh findings for the 2 scoped files


def test_manifest_change_runs_sca(target, engines):
    base = _full_scan(target, engines)
    (target / "requirements.txt").write_text("django==3.2.0\n")
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, str(target), None,
                         baseline_scan_id=base)
    assert len(engines["sca"]) == 2  # full scan + incremental


def test_code_change_skips_sca(target, engines):
    base = _full_scan(target, engines)
    (target / "a.py").write_text("x = 2\n")
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, str(target), None,
                         baseline_scan_id=base)
    assert len(engines["sca"]) == 1  # only the full baseline scan


def test_unknown_baseline_fails_scan(target, engines):
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(max_retries=0), scan_id, str(target), None,
                         baseline_scan_id="nope")
    _, scan = _findings_of(scan_id)
    assert scan["status"] == "failed"


def test_other_org_baseline_fails_scan(target, engines):
    base = _full_scan(target, engines)  # org "owner"
    scan_id = _mk_scan(org="intruder")
    tasks._run_scan_impl(FakeSelf(max_retries=0), scan_id, str(target), None,
                         baseline_scan_id=base)
    _, scan = _findings_of(scan_id)
    assert scan["status"] == "failed"


def test_carried_findings_keep_ai_review(target, engines):
    base = _full_scan(target, engines)
    # simulate a completed AI review on the baseline scan
    db = get_db()
    db.execute("UPDATE findings SET ai_verdict='true_positive',"
               " ai_confidence=0.9, ai_explanation='ثغرة', ai_fix='f'"
               " WHERE scan_id=?", (base,))
    db.commit()
    db.close()
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, str(target), None,
                         baseline_scan_id=base)
    db = get_db()
    rows = db.execute("SELECT ai_verdict, ai_confidence, ai_explanation"
                      " FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
    db.close()
    assert len(rows) == 2
    assert all(r["ai_verdict"] == "true_positive" for r in rows)
    assert all(r["ai_confidence"] == 0.9 for r in rows)


# ---------------------------------------------------------------------------
# HTTP contract
# ---------------------------------------------------------------------------

def _client():
    init_db()  # TestClient paths hit billing tables; ensure schema exists
    from billing import ensure_owner_org, ensure_subscription, seed_plans
    seed_plans()
    ensure_owner_org()
    ensure_subscription("owner")
    return TestClient(main.app)


def test_zip_with_baseline_rejected(target):
    c = _client()
    r = c.post("/api/scans", headers=HEADERS,
               files={"file": ("x.zip", b"PK\x03\x04fake", "application/zip")},
               data={"baseline_scan_id": "whatever"})
    assert r.status_code == 400


def test_unknown_baseline_rejected_before_quota():
    from pathlib import Path
    d = Path(main.SCAN_ROOT) / "pytest-incr-404"
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.py").write_text("x = 1\n")
    c = _client()
    r = c.post("/api/scans", headers=HEADERS,
               data={"target_path": str(d),
                     "baseline_scan_id": "nope-not-here"})
    assert r.status_code == 404
