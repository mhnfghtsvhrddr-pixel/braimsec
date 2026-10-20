"""Tests for the on-demand scan-failure email (tasks._deliver_failure_email).

Scheduled scans alert by email through evaluate_schedule_alerts and VCS
scans through evaluate_vcs_alerts. A plain API/dashboard scan that fails
terminally must email the org's alert recipients too — and nothing else may
email: no double-send for scheduled/VCS scans, silence on success, silence
(and no crash) when the org has no recipients or SMTP is unconfigured.
"""
import os
import sys
import tempfile
import uuid

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-scanfail-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-scanfail-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import email_alerts  # noqa: E402
import tasks  # noqa: E402
from billing import create_org, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()

NOW = "2026-10-20T00:00:00+00:00"
RECIPIENT = "owner@example.com"


@pytest.fixture()
def sent(monkeypatch):
    box = []

    def fake_send(to, subject, text, html, attachments=None):
        box.append({"to": to, "subject": subject, "text": text})
        return True, 1, None

    monkeypatch.setattr(email_alerts, "send_email", fake_send)
    for var, val in (("BRAIMSEC_SMTP_HOST", "smtp.test"),
                     ("BRAIMSEC_SMTP_PORT", "587"),
                     ("BRAIMSEC_SMTP_USER", "u@test"),
                     ("BRAIMSEC_SMTP_PASS", "pw"),
                     ("BRAIMSEC_SMTP_FROM", "alerts@braimsec.world")):
        monkeypatch.setenv(var, val)
    return box


@pytest.fixture()
def org():
    oid = create_org("ScanFail Org " + uuid.uuid4().hex[:8])
    yield oid
    # Clean up shared-table rows (notifications especially: other modules
    # read it with bare fetchone() — see AGENTS.md cross-module rule).
    db = get_db()
    db.execute("DELETE FROM notifications WHERE org_id=?", (oid,))
    db.execute("DELETE FROM alert_emails WHERE org_id=?", (oid,))
    db.execute("DELETE FROM schedules WHERE org_id=?", (oid,))
    db.execute("DELETE FROM scans WHERE org_id=?", (oid,))
    db.commit()
    db.close()


def _mk_scan(org_id, *, status="failed", scheduled=False, vcs_repo_id=None,
             with_email=True, error="engine exploded"):
    db = get_db()
    sid = "scan-" + uuid.uuid4().hex[:12]
    try:
        if with_email:
            db.execute(
                "INSERT INTO alert_emails (org_id, email, enabled, created_at)"
                " VALUES (?,?,1,?)", (org_id, RECIPIENT, NOW))
        db.execute(
            "INSERT INTO scans (id, org_id, target_name, status, created_at,"
            " finished_at, error, vcs_repo_id)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (sid, org_id, "myrepo", status, NOW, NOW, error, vcs_repo_id))
        if scheduled:
            # Scheduled scans link from the schedule side (last_scan_id).
            db.execute(
                "INSERT INTO schedules (id, org_id, name, target_path,"
                " webhook_url, next_run_at, last_scan_id, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                ("sched-" + uuid.uuid4().hex[:8], org_id, "nightly", "/x",
                 "https://hooks.test/abc", NOW, sid, NOW))
        db.commit()
    finally:
        db.close()
    return sid


def _email_notifications(org_id):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM notifications WHERE org_id=? AND channel='email'",
        (org_id,)).fetchall()
    db.close()
    return rows


def test_failed_ondemand_scan_emails_org(org, sent):
    sid = _mk_scan(org)
    tasks._deliver_failure_email(sid)
    assert len(sent) == 1
    assert sent[0]["to"] == RECIPIENT
    assert "فشل الفحص" in sent[0]["subject"]
    rows = _email_notifications(org)
    assert len(rows) == 1
    assert rows[0]["event"] == "scan.failed"
    assert rows[0]["status"] == "sent"
    assert rows[0]["scan_id"] == sid


def test_failed_scheduled_scan_does_not_double_email(org, sent):
    sid = _mk_scan(org, scheduled=True)
    tasks._deliver_failure_email(sid)
    assert sent == []
    assert _email_notifications(org) == []


def test_failed_vcs_scan_does_not_double_email(org, sent):
    sid = _mk_scan(org, vcs_repo_id="vcs-1")
    tasks._deliver_failure_email(sid)
    assert sent == []
    assert _email_notifications(org) == []


def test_successful_scan_sends_no_email(org, sent):
    sid = _mk_scan(org, status="done", error=None)
    tasks._deliver_failure_email(sid)
    assert sent == []
    assert _email_notifications(org) == []


def test_no_recipients_no_email_no_crash(org, sent):
    sid = _mk_scan(org, with_email=False)
    tasks._deliver_failure_email(sid)  # must not raise
    assert sent == []


def test_unknown_scan_id_is_silent(sent):
    tasks._deliver_failure_email("scan-does-not-exist")  # must not raise
    assert sent == []
