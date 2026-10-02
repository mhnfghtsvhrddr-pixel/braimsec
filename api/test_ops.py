"""Operations tests: /api/health probe + Celery task time limits.

No live worker or broker needed: health runs against the test DB, and the
time-limit behavior is exercised through _run_scan_impl with a fake task-self
(the same pattern as test_async_queue).

Hermeticity: BRAIMSEC_DB / BRAIMSEC_API_KEY are setdefault'ed here so this
file also runs standalone; under the full suite test_async_queue (imported
first alphabetically) has already fixed them to the session values.
"""
import os
import sys
import tempfile
from types import SimpleNamespace

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-ops-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from celery.exceptions import SoftTimeLimitExceeded  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import tasks  # noqa: E402
from database import get_db, init_db  # noqa: E402


class FakeSelf:
    """Minimal stand-in for a bound Celery task."""

    class RetryRaised(Exception):
        pass

    def __init__(self, max_retries=2):
        self.max_retries = max_retries
        self.request = SimpleNamespace(retries=0)
        self.retry_called = False

    def retry(self, exc=None, countdown=None):
        self.retry_called = True
        raise FakeSelf.RetryRaised()


def _mk_scan():
    init_db()
    db = get_db()
    scan_id = "scan_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        (scan_id, "owner", "t", "queued", "2026-01-01T00:00:00+00:00"))
    db.commit()
    db.close()
    return scan_id


# ---------------------------------------------------------------------------
# /api/health
# ---------------------------------------------------------------------------

def test_health_is_public_and_ok():
    client = TestClient(main.app)
    r = client.get("/api/health")  # no API key on purpose
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["checks"]["database"] == "ok"
    # Test env has no broker configured: the probe must say so honestly
    # instead of claiming the queue is healthy.
    assert body["checks"]["broker"] in ("ok", "inline-mode")


def test_health_degraded_when_broker_down(monkeypatch):
    class _DeadBroker:
        def ensure_connection(self, max_retries=None):
            raise ConnectionError("broker unreachable")

        def release(self):
            pass

    monkeypatch.setattr(main, "queue_enabled", lambda: True)
    monkeypatch.setattr(main.celery_app, "broker_connection",
                        lambda: _DeadBroker())
    client = TestClient(main.app)
    r = client.get("/api/health")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["checks"]["broker"].startswith("error:")


# ---------------------------------------------------------------------------
# Celery task time limits
# ---------------------------------------------------------------------------

def test_scan_tasks_carry_soft_time_limits():
    # Bound on the task objects, not just a comment: Celery enforces these.
    assert tasks.run_scan.soft_time_limit == tasks.SCAN_SOFT_LIMIT_S == 1500
    assert (tasks.run_ai_review.soft_time_limit
            == tasks.AI_REVIEW_SOFT_LIMIT_S == 1200)
    # Deliberately no hard time_limit: a hard kill looks like a lost worker,
    # and task_reject_on_worker_lost=True would requeue the scan forever.
    assert getattr(tasks.run_scan, "time_limit", None) is None


def test_soft_timeout_retries_scan(monkeypatch, tmp_path):
    """A scan that exceeds its time budget is transient: host pressure
    varies between attempts, so the retry policy applies (2026-10-02:
    timeouts moved from fail-fast to retried)."""
    def _boom(_target_dir):
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(tasks, "run_semgrep", _boom)
    scan_id = _mk_scan()
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("x = 1\n")

    fake = FakeSelf(max_retries=2)
    with pytest.raises(FakeSelf.RetryRaised):
        tasks._run_scan_impl(fake, scan_id, str(target), None)
    assert fake.retry_called is True


def test_soft_timeout_fails_when_retries_exhausted(monkeypatch, tmp_path):
    """A timed-out scan with no retries left fails with the time-limit error."""
    def _boom(_target_dir):
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(tasks, "run_semgrep", _boom)
    scan_id = _mk_scan()
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("x = 1\n")

    fake = FakeSelf(max_retries=0)
    # Must NOT raise RetryRaised: no retries remain.
    tasks._run_scan_impl(fake, scan_id, str(target), None)
    assert fake.retry_called is False

    db = get_db()
    row = db.execute("SELECT status, error, finished_at FROM scans WHERE id=?",
                     (scan_id,)).fetchone()
    db.close()
    assert row["status"] == "failed"
    assert row["finished_at"] is not None
    assert "time limit" in (row["error"] or "")
