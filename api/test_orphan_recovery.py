"""Tests for orphaned-scan recovery on API startup.

A scan stuck in 'running'/'queued' across an API restart means its worker
died (crash, OOM-kill, deploy) and will never report back.
_recover_orphaned_scans() fails such scans honestly instead of letting the
client poll forever.
"""
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-orphan-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import main  # noqa: E402
from audit import read_events  # noqa: E402
from database import get_db, init_db  # noqa: E402
from main import (ORPHAN_QUEUED_GRACE_S, ORPHAN_RUNNING_GRACE_S,  # noqa: E402
                  _recover_orphaned_scans)


@pytest.fixture(scope="module", autouse=True)
def _db():
    init_db()
    yield


def _ago_iso(seconds: float) -> str:
    return (datetime.now(timezone.utc)
            - timedelta(seconds=seconds)).isoformat()


def _mk_scan(status: str, created_ago_s: float = 0,
             started_ago_s: float | None = None) -> str:
    scan_id = uuid.uuid4().hex[:12]
    started = _ago_iso(started_ago_s) if started_ago_s is not None else None
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " started_at) VALUES (?,?,?,?,?,?)",
        (scan_id, "owner", "orphan-test", status, _ago_iso(created_ago_s),
         started),
    )
    db.commit()
    db.close()
    return scan_id


def _status(scan_id: str) -> tuple[str, str | None]:
    db = get_db()
    row = db.execute("SELECT status, error FROM scans WHERE id=?",
                     (scan_id,)).fetchone()
    db.close()
    return row["status"], row["error"]


def _audit_for(scan_id: str) -> list[dict]:
    return [e for e in read_events("owner", action="scan.failed", limit=200)
            if e["resource_id"] == scan_id]


def test_running_scan_past_grace_recovered():
    sid = _mk_scan("running", created_ago_s=ORPHAN_RUNNING_GRACE_S + 3600,
                   started_ago_s=ORPHAN_RUNNING_GRACE_S + 60)
    assert _recover_orphaned_scans() >= 1
    status, error = _status(sid)
    assert status == "failed"
    assert "worker lost" in (error or "")
    events = _audit_for(sid)
    assert len(events) == 1
    assert events[0]["actor"] == "system"
    assert events[0]["detail"]["reason"] == "orphan_recovery"
    assert events[0]["detail"]["previous_status"] == "running"


def test_running_scan_within_grace_untouched():
    sid = _mk_scan("running", created_ago_s=60, started_ago_s=60)
    _recover_orphaned_scans()
    status, _ = _status(sid)
    assert status == "running"
    assert _audit_for(sid) == []


def test_queued_scan_abandoned_after_24h_recovered():
    sid = _mk_scan("queued", created_ago_s=ORPHAN_QUEUED_GRACE_S + 60)
    _recover_orphaned_scans()
    status, error = _status(sid)
    assert status == "failed"
    assert "worker lost" in (error or "")
    events = _audit_for(sid)
    assert len(events) == 1
    assert events[0]["detail"]["previous_status"] == "queued"


def test_queued_scan_recent_untouched():
    sid = _mk_scan("queued", created_ago_s=60)
    _recover_orphaned_scans()
    status, _ = _status(sid)
    assert status == "queued"
    assert _audit_for(sid) == []


def test_done_scan_untouched():
    sid = _mk_scan("done", created_ago_s=ORPHAN_QUEUED_GRACE_S + 3600,
                   started_ago_s=ORPHAN_QUEUED_GRACE_S + 3500)
    _recover_orphaned_scans()
    status, _ = _status(sid)
    assert status == "done"
    assert _audit_for(sid) == []


def test_startup_triggers_recovery(monkeypatch):
    called = []
    monkeypatch.setattr(main, "_recover_orphaned_scans",
                        lambda: called.append(1) or 0)
    main.startup()
    assert called == [1]
