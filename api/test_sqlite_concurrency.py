"""Tests for SQLite concurrency hardening (WAL + busy timeout).

The API server and Celery workers are separate processes writing to the
same SQLite file. With rollback-journal mode that meant "database is
locked" failures under concurrent writes; get_db() now enables WAL and a
30s busy timeout. The control test below proves the old settings really
failed where the new ones succeed — it is not a tautology.
"""
import os
import sqlite3
import sys
import tempfile
import threading
import time
import uuid

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-sqlite-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database  # noqa: E402

HOLD_S = 7  # longer than the old 5s default timeout, shorter than the new 30s


@pytest.fixture()
def wal_db(tmp_path, monkeypatch):
    """Isolated DB file with the production get_db() configuration."""
    import database as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "c.db"))
    dbmod.init_db()
    yield dbmod


@pytest.fixture()
def delete_db(tmp_path):
    """Isolated DB file with the OLD settings: rollback journal, 5s timeout."""
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.executescript(database.SCHEMA)
    conn.commit()
    conn.close()
    yield path


def _insert(conn, sid):
    conn.execute(
        "INSERT INTO scans (id, target_name, status, created_at)"
        " VALUES (?,?,?,?)",
        (sid, "concurrency-test", "queued", "2026-10-01T00:00:00+00:00"),
    )


def test_wal_mode_enabled(wal_db):
    db = wal_db.get_db()
    try:
        mode = db.execute("PRAGMA journal_mode").fetchone()[0]
        busy = db.execute("PRAGMA busy_timeout").fetchone()[0]
    finally:
        db.close()
    assert mode.lower() == "wal"
    assert busy == 30000


def test_concurrent_writer_waits_not_fails(wal_db):
    """A writer blocked by a 7s write transaction waits and commits.

    With the old 5s timeout this raised 'database is locked'.
    """
    holder = wal_db.get_db()
    holder.execute("BEGIN IMMEDIATE")
    _insert(holder, "holder-" + uuid.uuid4().hex[:8])

    errors = []

    def writer():
        try:
            w = wal_db.get_db()
            try:
                _insert(w, "writer-" + uuid.uuid4().hex[:8])
                w.commit()
            finally:
                w.close()
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    t = threading.Thread(target=writer)
    t.start()
    time.sleep(0.5)
    start = time.monotonic()
    time.sleep(HOLD_S)
    holder.commit()
    holder.close()
    t.join(timeout=40)
    waited = time.monotonic() - start

    assert not t.is_alive(), "writer thread hung"
    assert not errors, f"writer failed: {errors[0]!r}"
    assert waited >= 4, f"writer did not really wait (only {waited:.1f}s)"


def test_old_settings_raise_database_is_locked(delete_db):
    """Control: the pre-WAL settings fail on the same contention pattern."""
    conn = sqlite3.connect(delete_db, timeout=5.0)
    conn.execute("BEGIN IMMEDIATE")
    _insert(conn, "holder-" + uuid.uuid4().hex[:8])

    errors = []

    def writer():
        try:
            w = sqlite3.connect(delete_db, timeout=5.0)
            try:
                _insert(w, "writer-" + uuid.uuid4().hex[:8])
                w.commit()
            finally:
                w.close()
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    t = threading.Thread(target=writer)
    t.start()
    time.sleep(HOLD_S)
    conn.commit()
    conn.close()
    t.join(timeout=40)

    assert not t.is_alive(), "writer thread hung"
    assert errors, "expected 'database is locked' with old settings"
    assert "locked" in str(errors[0]).lower()


def test_readers_dont_block_writers(wal_db):
    """An open read transaction must not block a concurrent writer."""
    reader = wal_db.get_db()
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM scans").fetchall()  # holds SHARED lock

    done = threading.Event()
    errors = []

    def writer():
        try:
            w = wal_db.get_db()
            try:
                _insert(w, "writer-" + uuid.uuid4().hex[:8])
                w.commit()
            finally:
                w.close()
        except Exception as e:  # noqa: BLE001
            errors.append(e)
        finally:
            done.set()

    t = threading.Thread(target=writer)
    t.start()
    try:
        assert done.wait(timeout=10), "writer blocked by read transaction"
        assert not errors, f"writer failed: {errors[0]!r}"
    finally:
        t.join(timeout=40)
        reader.rollback()
        reader.close()
