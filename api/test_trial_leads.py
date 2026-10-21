"""Trial lead capture tests: POST /api/trial/leads stores the email for
sales follow-up after a trial scan completes. No email is sent.

Hermeticity: BRAIMSEC_DB / BRAIMSEC_API_KEY are setdefault'ed here so this
file also runs standalone; under the full suite test_async_queue (imported
first alphabetically) has already fixed them to the session values.
"""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="braimsec-test-trial-leads-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from database import get_db, init_db  # noqa: E402

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    # POST /api/trial/leads is capped at 10/hour per IP: reset between
    # tests so each test gets a fresh quota.
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


def _mk_trial_scan():
    init_db()
    db = get_db()
    scan_id = "trial_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        (scan_id, "owner", "t", "done", "2026-01-01T00:00:00+00:00"))
    db.execute(
        "INSERT INTO trial_scans (scan_id, ip, repo_url, created_at)"
        " VALUES (?,?,?,?)",
        (scan_id, "1.2.3.4", "https://github.com/o/r",
         "2026-01-01T00:00:00+00:00"))
    db.commit()
    db.close()
    return scan_id


def _leads(email):
    db = get_db()
    rows = db.execute(
        "SELECT email, scan_id FROM trial_leads WHERE email=?",
        (email,)).fetchall()
    db.close()
    return rows


def test_lead_capture_ok():
    scan_id = _mk_trial_scan()
    r = client.post("/api/trial/leads",
                    data={"email": "Founder@Example.COM ", "scan_id": scan_id})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    rows = _leads("founder@example.com")
    assert len(rows) == 1
    assert rows[0]["scan_id"] == scan_id


def test_lead_capture_idempotent():
    scan_id = _mk_trial_scan()
    for _ in range(2):
        r = client.post("/api/trial/leads",
                        data={"email": "dup@example.com", "scan_id": scan_id})
        assert r.status_code == 200
    assert len(_leads("dup@example.com")) == 1


def test_lead_capture_without_scan():
    r = client.post("/api/trial/leads", data={"email": "noref@example.com"})
    assert r.status_code == 200
    rows = _leads("noref@example.com")
    assert len(rows) == 1
    assert rows[0]["scan_id"] is None


def test_lead_rejects_bad_email():
    for bad in ["not-an-email", "a@b", "@x.com", "a@b.c" * 60]:
        r = client.post("/api/trial/leads", data={"email": bad})
        assert r.status_code == 400, bad


def test_lead_rejects_unknown_scan():
    r = client.post("/api/trial/leads",
                    data={"email": "x@example.com", "scan_id": "nope"})
    assert r.status_code == 404
    assert _leads("x@example.com") == []


def test_trial_page_contains_cta():
    r = client.get("/trial")
    assert r.status_code == 200
    assert "/api/trial/leads" in r.text
    assert "Send me the report" in r.text


def _mk_done_trial_scan_with_findings():
    init_db()
    db = get_db()
    scan_id = "trial_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " finished_at, total_findings) VALUES (?,?,?,?,?,?,?)",
        (scan_id, "owner", "github.com/o/r", "done",
         "2026-01-01T00:00:00+00:00", "2026-01-01T00:05:00+00:00", 2))
    db.execute(
        "INSERT INTO trial_scans (scan_id, ip, repo_url, created_at)"
        " VALUES (?,?,?,?)",
        (scan_id, "1.2.3.4", "https://github.com/o/r",
         "2026-01-01T00:00:00+00:00"))
    db.execute(
        "INSERT INTO findings (scan_id, tool, rule_id, severity, message,"
        " file, line) VALUES (?,?,?,?,?,?,?)",
        (scan_id, "semgrep", "python.test.rule", "error", "test issue",
         "/src/a.py", 3))
    db.commit()
    db.close()
    return scan_id


def test_lead_triggers_report_email(monkeypatch):
    import email_alerts
    scan_id = _mk_done_trial_scan_with_findings()
    sent = []
    monkeypatch.setattr(
        email_alerts, "send_email",
        lambda to, subj, text, html: sent.append((to, subj, text, html))
        or (True, 1, None))
    r = client.post("/api/trial/leads",
                    data={"email": "lead@example.com", "scan_id": scan_id})
    assert r.status_code == 200
    assert len(sent) == 1
    to, subj, text, html = sent[0]
    assert to == "lead@example.com"
    assert "python.test.rule" in text
    assert "a.py:3" in text
    db = get_db()
    row = db.execute(
        "SELECT emailed_at FROM trial_leads WHERE email=?",
        ("lead@example.com",)).fetchone()
    db.close()
    assert row["emailed_at"] is not None


def test_lead_stored_even_when_email_fails(monkeypatch):
    init_db()
    import email_alerts
    monkeypatch.setattr(
        email_alerts, "send_email",
        lambda to, subj, text, html: (False, 3, "SMTP down"))
    r = client.post("/api/trial/leads", data={"email": "fail@example.com"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    db = get_db()
    row = db.execute(
        "SELECT emailed_at FROM trial_leads WHERE email=?",
        ("fail@example.com",)).fetchone()
    db.close()
    assert row is not None
    assert row["emailed_at"] is None


def test_migration_adds_emailed_at_to_legacy_table(tmp_path):
    """DBs created before emailed_at existed get the column via init_db."""
    import sqlite3
    legacy = str(tmp_path / "legacy.db")
    db = sqlite3.connect(legacy)
    db.execute(
        "CREATE TABLE trial_leads (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " email TEXT NOT NULL, scan_id TEXT, ip TEXT NOT NULL DEFAULT '',"
        " created_at TEXT NOT NULL, UNIQUE(email, scan_id))")
    db.commit()
    db.close()
    import database
    old_path, database.DB_PATH = database.DB_PATH, legacy
    try:
        init_db()
    finally:
        database.DB_PATH = old_path
    db = sqlite3.connect(legacy)
    cols = {r[1] for r in db.execute("PRAGMA table_info(trial_leads)")}
    db.close()
    assert "emailed_at" in cols


def _mk_keys():
    from billing import (OWNER_ORG_ID, create_org, ensure_owner_org,
                         provision_key)
    init_db()
    ensure_owner_org()
    org = create_org("Leads Co")
    owner_key = provision_key(OWNER_ORG_ID, "owner-k", actor="owner",
                              role="owner")
    member_key = provision_key(org, "member-k", actor="owner", role="member")
    return owner_key, member_key


def test_list_leads_owner_only():
    owner_key, member_key = _mk_keys()
    scan_id = _mk_trial_scan()
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO trial_leads (email, scan_id, ip, created_at,"
        " emailed_at) VALUES (?,?,?, ?,?)",
        ("boss@example.com", scan_id, "9.9.9.9",
         "2026-10-21T10:00:00+00:00", "2026-10-21T10:01:00+00:00"))
    db.commit()
    db.close()
    r = client.get("/api/trial/leads",
                   headers={"X-API-Key": owner_key})
    assert r.status_code == 200
    leads = r.json()["leads"]
    assert any(l["email"] == "boss@example.com" and l["emailed"] is True
               and l["repo_url"] == "https://github.com/o/r"
               for l in leads)
    r = client.get("/api/trial/leads",
                   headers={"X-API-Key": member_key})
    assert r.status_code == 403
    r = client.get("/api/trial/leads")
    assert r.status_code == 401
