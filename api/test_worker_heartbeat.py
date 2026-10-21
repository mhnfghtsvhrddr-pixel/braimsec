"""Worker heartbeat tests: the braimsec.heartbeat task stamps the shared DB,
and /api/health reports worker liveness from that stamp (no SSH needed).

Hermeticity: BRAIMSEC_DB / BRAIMSEC_API_KEY are setdefault'ed here so this
file also runs standalone; under the full suite test_async_queue (imported
first alphabetically) has already fixed them to the session values.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-heartbeat-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import tasks  # noqa: E402
from database import get_db, init_db  # noqa: E402


class _FakeBrokerConn:
    def ensure_connection(self, max_retries=None):
        pass

    def release(self):
        pass


@pytest.fixture()
def client(monkeypatch):
    """Health probe with the queue path forced on and a fake live broker."""
    init_db()
    monkeypatch.setattr(main, "queue_enabled", lambda: True)
    monkeypatch.setattr(main.celery_app, "broker_connection",
                        lambda: _FakeBrokerConn())
    return TestClient(main.app)


def _stamp(age_seconds=None):
    init_db()
    db = get_db()
    ts = (datetime.now(timezone.utc)
          - timedelta(seconds=age_seconds or 0)).isoformat()
    db.execute(
        "INSERT INTO worker_heartbeat (id, last_beat_at, worker_host)"
        " VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET"
        " last_beat_at=excluded.last_beat_at,"
        " worker_host=excluded.worker_host",
        (ts, "test-host"))
    db.commit()
    db.close()


def test_heartbeat_task_stamps_db():
    init_db()
    assert tasks.heartbeat() == "ok"
    db = get_db()
    row = db.execute(
        "SELECT last_beat_at, worker_host FROM worker_heartbeat WHERE id=1"
    ).fetchone()
    db.close()
    assert row is not None
    age = (datetime.now(timezone.utc)
           - datetime.fromisoformat(row["last_beat_at"])).total_seconds()
    assert age < 60


def test_heartbeat_task_never_raises(monkeypatch):
    """A failed stamp must not poison the beat loop."""
    init_db()

    def _boom():
        raise RuntimeError("db gone")

    monkeypatch.setattr(tasks, "get_db", _boom)
    assert tasks.heartbeat() == "ok"


def test_health_worker_ok_when_fresh(client):
    _stamp(age_seconds=30)
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["checks"]["worker"] == "ok"


def test_health_worker_stale_when_old(client):
    _stamp(age_seconds=600)
    r = client.get("/api/health")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["checks"]["worker"].startswith("stale:")


def test_health_worker_unknown_when_missing(client):
    init_db()
    db = get_db()
    db.execute("DELETE FROM worker_heartbeat")
    db.commit()
    db.close()
    r = client.get("/api/health")
    # unknown = grace period (fresh deploy), must NOT flap to 503
    assert r.status_code == 200
    assert r.json()["checks"]["worker"].startswith("unknown")


def test_health_worker_inline_when_no_queue(monkeypatch):
    init_db()
    monkeypatch.setattr(main, "queue_enabled", lambda: False)
    client = TestClient(main.app)
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["checks"]["worker"] == "inline-mode"


def test_heartbeat_in_beat_schedule():
    assert "braimsec.heartbeat" in tasks.celery_app.conf.beat_schedule
    entry = tasks.celery_app.conf.beat_schedule["braimsec.heartbeat"]
    assert entry["task"] == "braimsec.heartbeat"
    assert entry["schedule"] == 60.0
