"""Owner platform-health alerts + backup restore test.

Covers:
- scan-failure owner alert: fires on terminal failure, throttled by
  cooldown, fail-open (never raises, never breaks scans).
- backup restore test: newest tarball unpacks, DB integrity + core tables
  verified; missing/corrupt backups report failure; every run recorded.

Hermeticity: BRAIMSEC_DB / BRAIMSEC_API_KEY are setdefault'ed here so this
file also runs standalone; under the full suite test_async_queue (imported
first alphabetically) has already fixed them to the session values.
"""
import os
import sqlite3
import sys
import tarfile
import tempfile

_tmp = tempfile.mkdtemp(prefix="braimsec-test-owner-alerts-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

import tasks  # noqa: E402
from database import get_db, init_db  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_tables():
    init_db()
    yield
    # Shared-table hygiene: never leak rows into other modules.
    db = get_db()
    for tbl in ("owner_alert_throttle", "backup_restore_tests", "scans",
                "alert_emails"):
        try:
            db.execute(f"DELETE FROM {tbl}")
        except Exception:  # noqa: BLE001 - table may not exist yet
            pass
    db.commit()
    db.close()


@pytest.fixture()
def _channels(monkeypatch):
    """Capture owner-channel sends; email configured, telegram off."""
    sent = []

    def _send_email(to_addr, subject, text_body, html_body,
                    attachments=None):
        sent.append(("email", to_addr, subject, text_body))
        return (True, 1, None)

    monkeypatch.setattr("email_alerts.smtp_configured", lambda: True)
    monkeypatch.setattr("email_alerts.send_email", _send_email)
    monkeypatch.setattr("telegram_alerts.telegram_configured", lambda: False)
    db = get_db()
    db.execute("INSERT INTO alert_emails (org_id, email, created_at)"
               " VALUES (?,?,?)",
               ("owner", "owner@example.com", "2026-01-01T00:00:00+00:00"))
    db.commit()
    db.close()
    return sent


def _mk_scan(status="failed", error="boom", scan_id=None):
    sid = scan_id or ("scan_" + os.urandom(4).hex())
    db = get_db()
    db.execute("INSERT INTO scans (id, org_id, target_name, status,"
               " created_at, error) VALUES (?,?,?,?,?,?)",
               (sid, "org1", "t", status, "2026-01-01T00:00:00+00:00",
                error))
    db.commit()
    db.close()
    return sid


# --- throttle ------------------------------------------------------------

def test_throttle_first_alert_due():
    db = get_db()
    try:
        assert tasks._owner_alert_due(db, "scan.failed") is True
    finally:
        db.close()


def test_throttle_stamp_suppresses_within_cooldown():
    db = get_db()
    try:
        tasks._owner_alert_stamp(db, "scan.failed")
        db.commit()
        assert tasks._owner_alert_due(db, "scan.failed") is False
    finally:
        db.close()


def test_throttle_expires_after_cooldown(monkeypatch):
    monkeypatch.setenv("BRAIMSEC_SCAN_FAIL_ALERT_COOLDOWN_S", "0")
    db = get_db()
    try:
        tasks._owner_alert_stamp(db, "scan.failed")
        db.commit()
        assert tasks._owner_alert_due(db, "scan.failed") is True
    finally:
        db.close()


def test_throttle_events_are_independent():
    db = get_db()
    try:
        tasks._owner_alert_stamp(db, "scan.failed")
        db.commit()
        assert tasks._owner_alert_due(db, "backup.restore_test") is True
    finally:
        db.close()


# --- scan-failure owner alert ----------------------------------------------

def test_scan_failed_alert_sent_and_throttled(_channels):
    sent = _channels
    sid = _mk_scan(status="failed", error="engine exploded")
    tasks._alert_owner_scan_failed(sid)
    assert len(sent) == 1
    kind, to_addr, subject, body = sent[0]
    assert kind == "email" and to_addr == "owner@example.com"
    assert "failed" in subject.lower()
    assert "engine exploded" in body
    # Second failure inside the cooldown: no second alert.
    sid2 = _mk_scan(status="failed", error="again")
    tasks._alert_owner_scan_failed(sid2)
    assert len(sent) == 1


def test_scan_failed_alert_skips_non_failed(_channels):
    sent = _channels
    sid = _mk_scan(status="done", error=None)
    tasks._alert_owner_scan_failed(sid)
    tasks._alert_owner_scan_failed("no-such-scan")
    assert sent == []


def test_scan_failed_alert_no_channels_no_stamp():
    # Nothing configured: no send, and no throttle row (a later failure
    # after Mahmoud adds a channel must still alert).
    sid = _mk_scan(status="failed")
    tasks._alert_owner_scan_failed(sid)  # must not raise
    db = get_db()
    try:
        row = db.execute("SELECT * FROM owner_alert_throttle"
                         " WHERE event='scan.failed'").fetchone()
        assert row is None
    finally:
        db.close()


def test_scan_failed_alert_send_crash_is_fail_open(_channels, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("smtp down")
    monkeypatch.setattr("email_alerts.send_email", _boom)
    sid = _mk_scan(status="failed")
    tasks._alert_owner_scan_failed(sid)  # must not raise


# --- backup restore test ---------------------------------------------------

def _make_db(path, corrupt=False):
    if corrupt:
        with open(path, "wb") as f:
            f.write(b"this is not a sqlite database")
        return
    con = sqlite3.connect(path)
    for t in ("organizations", "scans", "findings", "api_keys",
              "subscriptions"):
        con.execute(f"CREATE TABLE {t} (id TEXT PRIMARY KEY)")
    con.execute("INSERT INTO organizations (id) VALUES ('owner')")
    con.execute("INSERT INTO scans (id) VALUES ('s1')")
    con.commit()
    con.close()


def _make_tarball(backup_dir, name="braimsec-2026-10-22.tar.gz",
                  corrupt=False, no_db_member=False):
    workdir = tempfile.mkdtemp(prefix="braimsec-test-tar-")
    db_path = os.path.join(workdir, "braimsec-backup.db")
    if no_db_member:
        other = os.path.join(workdir, "notes.txt")
        with open(other, "w") as f:
            f.write("hi")
        member, arcname = other, "notes.txt"
    else:
        _make_db(db_path, corrupt=corrupt)
        member, arcname = db_path, "braimsec-backup.db"
    tar_path = os.path.join(backup_dir, name)
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(member, arcname=arcname)
    return tar_path


@pytest.fixture()
def _backup_dir():
    d = tempfile.mkdtemp(prefix="braimsec-test-backups-")
    return d


def test_restore_ok(_backup_dir):
    tarball = _make_tarball(_backup_dir)
    status, detail, found = tasks._run_backup_restore_test(_backup_dir)
    assert status == "ok"
    assert found == tarball
    assert "integrity ok" in detail


def test_restore_corrupt_db(_backup_dir):
    _make_tarball(_backup_dir, corrupt=True)
    status, detail, _ = tasks._run_backup_restore_test(_backup_dir)
    assert status == "failed"
    assert detail


def test_restore_no_db_member(_backup_dir):
    _make_tarball(_backup_dir, no_db_member=True)
    status, _, _ = tasks._run_backup_restore_test(_backup_dir)
    assert status == "failed"


def test_restore_missing(_backup_dir):
    status, detail, found = tasks._run_backup_restore_test(_backup_dir)
    assert status == "missing"
    assert found == ""
    assert "no braimsec-*.tar.gz" in detail


def test_restore_missing_dir():
    status, _, _ = tasks._run_backup_restore_test(
        os.path.join(_tmp, "does-not-exist"))
    assert status == "missing"


def test_restore_newest_tarball_wins(_backup_dir):
    _make_tarball(_backup_dir, name="braimsec-2026-10-20.tar.gz",
                  corrupt=True)
    good = _make_tarball(_backup_dir, name="braimsec-2026-10-22.tar.gz")
    # Force mtimes apart: newest must be picked.
    os.utime(good, (1_800_000_000, 1_800_000_000))
    status, _, found = tasks._run_backup_restore_test(_backup_dir)
    assert status == "ok"
    assert found == good


def test_restore_task_records_ok_and_stays_quiet(_backup_dir, _channels,
                                                 monkeypatch):
    _make_tarball(_backup_dir)
    monkeypatch.setenv("BRAIMSEC_BACKUP_DIR", _backup_dir)
    tasks.backup_restore_test()
    assert _channels == []
    db = get_db()
    try:
        row = db.execute("SELECT status, backup_file FROM backup_restore_tests"
                         " ORDER BY id DESC LIMIT 1").fetchone()
        assert row["status"] == "ok"
        assert row["backup_file"].endswith(".tar.gz")
    finally:
        db.close()


def test_restore_task_records_failure_and_alerts(_backup_dir, _channels,
                                                 monkeypatch):
    monkeypatch.setenv("BRAIMSEC_BACKUP_DIR", _backup_dir)  # empty -> missing
    tasks.backup_restore_test()
    assert len(_channels) == 1
    assert "backup" in _channels[0][2].lower()
    db = get_db()
    try:
        row = db.execute("SELECT status FROM backup_restore_tests"
                         " ORDER BY id DESC LIMIT 1").fetchone()
        assert row["status"] == "missing"
        # Throttled: second run alerts nothing more.
        tasks.backup_restore_test()
        assert len(_channels) == 1
    finally:
        db.close()


def test_beat_schedule_has_restore_test():
    sched = tasks.celery_app.conf.beat_schedule
    assert sched["braimsec.backup-restore-test"]["task"] == \
        "braimsec.backup_restore_test"
