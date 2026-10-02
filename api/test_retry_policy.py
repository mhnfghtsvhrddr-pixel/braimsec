"""Retry-policy tests: deterministic vs transient scan failures.

- is_deterministic_failure: unit classification of engine/task errors.
- A deterministic failure (bad target, docker rc=125, missing binary,
  broken baseline) fails the scan immediately: status=failed,
  attempt_count=1, engine invoked exactly once (no retry burned).
- A transient failure (OOM rc=137, soft time limit, engine hiccup)
  still goes through Celery's retry (task_self.retry is invoked).

DB isolation: same pattern as test_async_queue/test_sandbox_tasks
(setdefault; harmless if that module already pinned the vars).
"""
import os
import sys
import tempfile
from types import SimpleNamespace

import pytest
from celery.exceptions import SoftTimeLimitExceeded

_tmp = tempfile.mkdtemp(prefix="braimsec-test-retry-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))

import tasks  # noqa: E402
from database import get_db, init_db  # noqa: E402
from docker_runner import ContainerError  # noqa: E402
from scan_engine import EngineError  # noqa: E402


class FakeSelf:
    class RetryRaised(Exception):
        pass

    def __init__(self, max_retries=2):
        self.max_retries = max_retries
        self.request = SimpleNamespace(retries=0)
        self.retry_calls = 0

    def retry(self, exc=None, countdown=None):
        self.retry_calls += 1
        raise FakeSelf.RetryRaised()


def _mk_scan(org="owner"):
    init_db()
    db = get_db()
    scan_id = "retry_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        (scan_id, org, "t", "queued", "2026-01-01T00:00:00+00:00"))
    db.commit()
    db.close()
    return scan_id


def _scan_row(scan_id):
    db = get_db()
    row = db.execute(
        "SELECT status, error, attempt_count FROM scans WHERE id=?",
        (scan_id,)).fetchone()
    db.close()
    return row["status"], row["error"], row["attempt_count"]


@pytest.fixture()
def local_mode(monkeypatch):
    """Local engine mode; each test installs its own raising semgrep stub."""
    monkeypatch.delenv("BRAIMSEC_SCAN_SANDBOX", raising=False)
    monkeypatch.setattr(tasks, "run_gitleaks", lambda *a, **k: [])
    monkeypatch.setattr(tasks, "run_sca", lambda t: [])

    def raising(exc):
        def boom(target, scope=None):
            raise exc
        return boom
    return raising


# ---------------------------------------------------------------------------
# classification unit tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exc", [
    ContainerError("target not a directory: /nope"),
    ContainerError("sandboxed scan failed (rc=125): unknown flag --cpus"),
    EngineError("binary not found: semgrep"),
    RuntimeError("baseline scan not found: abc123"),
    RuntimeError("baseline scan belongs to another organization"),
    RuntimeError("baseline scan is not complete (status=running)"),
])
def test_deterministic_failures_classified(exc):
    assert tasks.is_deterministic_failure(exc) is True


@pytest.mark.parametrize("exc", [
    SoftTimeLimitExceeded(),
    ContainerError("sandboxed scan failed (rc=137): OOMKilled"),
    ContainerError("sandboxed scan timed out after 600s"),
    EngineError("timed out: semgrep --config auto /t"),
    EngineError("semgrep exited 1 without results: boom"),
    RuntimeError("weird transient engine hiccup"),
])
def test_transient_failures_classified(exc):
    assert tasks.is_deterministic_failure(exc) is False


# ---------------------------------------------------------------------------
# retry behavior
# ---------------------------------------------------------------------------

def test_deterministic_error_fails_immediately_single_attempt(
        tmp_path, local_mode, monkeypatch):
    """rc=125-style deterministic failure: failed, exactly 1 attempt."""
    calls = {"n": 0}
    exc = ContainerError("sandboxed scan failed (rc=125): "
                         "invalid --cpus value")

    def boom(target, scope=None):
        calls["n"] += 1
        raise exc

    monkeypatch.setattr(tasks, "run_semgrep", boom)
    (tmp_path / "a.py").write_text("x = 1\n")
    scan_id = _mk_scan()
    fake = FakeSelf(max_retries=2)
    tasks._run_scan_impl(fake, scan_id, str(tmp_path), None)
    status, error, attempts = _scan_row(scan_id)
    assert status == "failed"
    assert attempts == 1
    assert calls["n"] == 1  # exactly one attempt, no retry burned
    assert fake.retry_calls == 0
    assert "rc=125" in (error or "")


def test_missing_target_fails_without_retry(tmp_path, local_mode,
                                            monkeypatch):
    monkeypatch.setattr(tasks, "run_semgrep",
                        local_mode(ContainerError(
                            "target not a directory: /gone")))
    (tmp_path / "a.py").write_text("x = 1\n")
    scan_id = _mk_scan()
    fake = FakeSelf(max_retries=2)
    tasks._run_scan_impl(fake, scan_id, str(tmp_path), None)
    status, error, attempts = _scan_row(scan_id)
    assert status == "failed"
    assert attempts == 1
    assert fake.retry_calls == 0
    assert "target not a directory" in (error or "")


def test_transient_oom_still_retries(tmp_path, local_mode, monkeypatch):
    """rc=137 (OOM-kill): memory pressure varies, keep the retry policy."""
    monkeypatch.setattr(tasks, "run_semgrep",
                        local_mode(ContainerError(
                            "sandboxed scan failed (rc=137): OOMKilled")))
    (tmp_path / "a.py").write_text("x = 1\n")
    scan_id = _mk_scan()
    fake = FakeSelf(max_retries=2)
    with pytest.raises(FakeSelf.RetryRaised):
        tasks._run_scan_impl(fake, scan_id, str(tmp_path), None)
    assert fake.retry_calls == 1


def test_soft_time_limit_still_retries(tmp_path, local_mode, monkeypatch):
    """Timeouts are transient: a slow host may succeed on the next attempt."""
    monkeypatch.setattr(tasks, "run_semgrep",
                        local_mode(SoftTimeLimitExceeded()))
    (tmp_path / "a.py").write_text("x = 1\n")
    scan_id = _mk_scan()
    fake = FakeSelf(max_retries=2)
    with pytest.raises(FakeSelf.RetryRaised):
        tasks._run_scan_impl(fake, scan_id, str(tmp_path), None)
    assert fake.retry_calls == 1


def test_retry_exhaustion_still_fails(tmp_path, local_mode, monkeypatch):
    """Transient failure with no retries left: failed, attempt recorded."""
    monkeypatch.setattr(tasks, "run_semgrep",
                        local_mode(EngineError("boom")))
    (tmp_path / "a.py").write_text("x = 1\n")
    scan_id = _mk_scan()
    fake = FakeSelf(max_retries=0)
    tasks._run_scan_impl(fake, scan_id, str(tmp_path), None)
    status, error, attempts = _scan_row(scan_id)
    assert status == "failed"
    assert attempts == 1
    assert fake.retry_calls == 0
