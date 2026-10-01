"""Docker-sandbox routing tests for the scan tasks.

Proves, with stubbed engines:

- full scan in docker mode calls run_scan_isolated (never the local
  run_semgrep/run_gitleaks) and records its findings
- incremental scan in docker mode calls run_scan_isolated with the union
  scope and never the local engines
- a ContainerError fails the scan loudly (no silent fallback to local mode)

DB isolation: same pattern as test_async_queue (setdefault; harmless if
that module already pinned the vars).
"""
import json
import os
import sys
import tempfile
from types import SimpleNamespace

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-sbx-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))

import tasks  # noqa: E402
from database import get_db, init_db  # noqa: E402
from docker_runner import ContainerError  # noqa: E402


class FakeSelf:
    class RetryRaised(Exception):
        pass

    def __init__(self, max_retries=0):
        self.max_retries = max_retries
        self.request = SimpleNamespace(retries=0)

    def retry(self, exc=None, countdown=None):
        raise FakeSelf.RetryRaised()


ISOLATED_FINDING = {"tool": "semgrep", "rule_id": "sandbox-rule",
                    "severity": "high", "message": "m", "file": "a.py",
                    "line": 1, "col": 1}


@pytest.fixture()
def docker_mode(monkeypatch):
    """Route tasks into docker sandbox mode with a stubbed container run."""
    calls = {"isolated": [], "semgrep": 0, "gitleaks": 0, "sca": 0}
    monkeypatch.setenv("BRAIMSEC_SCAN_SANDBOX", "docker")

    def isolated(target_dir, scope=None):
        calls["isolated"].append((target_dir, scope))
        return [dict(ISOLATED_FINDING)]

    def no_local_semgrep(*a, **k):
        calls["semgrep"] += 1
        raise AssertionError("local semgrep must not run in docker mode")

    def no_local_gitleaks(*a, **k):
        calls["gitleaks"] += 1
        raise AssertionError("local gitleaks must not run in docker mode")

    def sca(target):
        calls["sca"] += 1
        return []

    monkeypatch.setattr(tasks, "run_scan_isolated", isolated)
    monkeypatch.setattr(tasks, "run_semgrep", no_local_semgrep)
    monkeypatch.setattr(tasks, "run_gitleaks", no_local_gitleaks)
    monkeypatch.setattr(tasks, "run_sca", sca)
    return calls


def _mk_scan(org="owner"):
    init_db()
    db = get_db()
    scan_id = "sbx_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        (scan_id, org, "t", "queued", "2026-01-01T00:00:00+00:00"))
    db.commit()
    db.close()
    return scan_id


def _status(scan_id):
    db = get_db()
    row = db.execute("SELECT status, total_findings FROM scans WHERE id=?",
                     (scan_id,)).fetchone()
    n = db.execute("SELECT COUNT(*) c FROM findings WHERE scan_id=?",
                   (scan_id,)).fetchone()["c"]
    db.close()
    return row["status"], row["total_findings"], n


def test_full_scan_uses_sandbox_not_local_engines(tmp_path, docker_mode):
    (tmp_path / "a.py").write_text("x = 1\n")
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, str(tmp_path), None)
    status, total, n = _status(scan_id)
    assert status == "done"
    assert total == 1 and n == 1
    assert len(docker_mode["isolated"]) == 1
    target_dir, scope = docker_mode["isolated"][0]
    assert target_dir == str(tmp_path)
    assert scope is None  # full scan: no scope
    assert docker_mode["semgrep"] == 0
    assert docker_mode["gitleaks"] == 0
    assert docker_mode["sca"] == 1  # SCA stays on the host


def test_sandbox_failure_fails_scan_loudly(tmp_path, docker_mode, monkeypatch):
    def boom(target_dir, scope=None):
        raise ContainerError("docker exploded")

    monkeypatch.setattr(tasks, "run_scan_isolated", boom)
    (tmp_path / "a.py").write_text("x = 1\n")
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(max_retries=0), scan_id, str(tmp_path), None)
    status, _, _ = _status(scan_id)
    assert status == "failed"
    # local engines were never consulted as a fallback
    assert docker_mode["semgrep"] == 0
    assert docker_mode["gitleaks"] == 0


def test_incremental_scan_uses_sandbox_with_scope(tmp_path, docker_mode):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("import a\n")
    # baseline: full docker-mode scan
    base = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), base, str(tmp_path), None)
    assert len(docker_mode["isolated"]) == 1
    # change one file -> incremental
    (tmp_path / "a.py").write_text("x = 2\n")
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, str(tmp_path), None,
                         baseline_scan_id=base)
    status, _, _ = _status(scan_id)
    assert status == "done"
    assert len(docker_mode["isolated"]) == 2
    _, scope = docker_mode["isolated"][1]
    assert scope is not None
    basenames = {os.path.basename(p) for p in scope}
    assert "a.py" in basenames  # changed file (+ import-hop b.py)
    assert docker_mode["semgrep"] == 0
    assert docker_mode["gitleaks"] == 0


def test_local_mode_unchanged_when_sandbox_off(tmp_path, monkeypatch):
    """Sanity: without the env var, tasks still use the local engines."""
    monkeypatch.delenv("BRAIMSEC_SCAN_SANDBOX", raising=False)
    calls = {"semgrep": 0, "isolated": 0}

    def sg(target, scope=None):
        calls["semgrep"] += 1
        return []

    def isolated(*a, **k):
        calls["isolated"] += 1
        raise AssertionError("sandbox must not run in local mode")

    monkeypatch.setattr(tasks, "run_semgrep", sg)
    monkeypatch.setattr(tasks, "run_gitleaks", lambda *a, **k: [])
    monkeypatch.setattr(tasks, "run_sca", lambda t: [])
    monkeypatch.setattr(tasks, "run_scan_isolated", isolated)
    (tmp_path / "a.py").write_text("x = 1\n")
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, str(tmp_path), None)
    status, _, _ = _status(scan_id)
    assert status == "done"
    assert calls["semgrep"] == 1
    assert calls["isolated"] == 0
