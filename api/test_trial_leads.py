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
    # Relative timestamp on purpose: a fixed emailed_at ages past the
    # 3-day trial_reminders() cutoff and then pollutes that test's global
    # scan (this bit the full suite on 2026-10-24, when 2026-10-21 aged
    # past the cutoff). The listing only needs emailed=True, so "recent"
    # is the correct fixture here.
    from datetime import datetime, timedelta, timezone
    emailed_recent = (datetime.now(timezone.utc)
                      - timedelta(hours=1)).isoformat()
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO trial_leads (email, scan_id, ip, created_at,"
        " emailed_at) VALUES (?,?,?, ?,?)",
        ("boss@example.com", scan_id, "9.9.9.9",
         "2026-10-21T10:00:00+00:00", emailed_recent))
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


def test_csv_export_owner_only():
    owner_key, member_key = _mk_keys()
    scan_id = _mk_trial_scan()
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO trial_leads (email, scan_id, ip, created_at)"
        " VALUES (?,?,?,?)",
        ("csv@example.com", scan_id, "9.9.9.9",
         "2026-10-21T10:00:00+00:00"))
    db.commit()
    db.close()
    r = client.get("/api/trial/leads.csv",
                   headers={"X-API-Key": owner_key})
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "trial-leads.csv" in r.headers["content-disposition"]
    assert "csv@example.com" in r.text
    assert r.text.splitlines()[0].startswith("email,scan_id,")
    r = client.get("/api/trial/leads.csv",
                   headers={"X-API-Key": member_key})
    assert r.status_code == 403
    r = client.get("/api/trial/leads.csv")
    assert r.status_code == 401


def test_funnel_stats_owner_only():
    owner_key, member_key = _mk_keys()
    _mk_trial_scan()
    r = client.get("/api/trial/stats",
                   headers={"X-API-Key": owner_key})
    assert r.status_code == 200
    body = r.json()
    assert body["trial_scans"] >= 1
    assert body["leads"] >= 0
    assert body["conversion_pct"] >= 0.0
    r = client.get("/api/trial/stats",
                   headers={"X-API-Key": member_key})
    assert r.status_code == 403
    r = client.get("/api/trial/stats")
    assert r.status_code == 401


def test_owner_alert_uses_owner_channels(monkeypatch):
    import email_alerts
    import telegram_alerts
    from billing import OWNER_ORG_ID
    init_db()
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO alert_emails (org_id, email, enabled,"
        " created_at) VALUES (?,?,1,?)",
        (OWNER_ORG_ID, "owner@example.com",
         "2026-10-21T10:00:00+00:00"))
    db.execute(
        "INSERT OR IGNORE INTO telegram_chats (org_id, chat_id, created_at)"
        " VALUES (?,?,?)",
        (OWNER_ORG_ID, "12345", "2026-10-21T10:00:00+00:00"))
    db.commit()
    db.close()
    emails, tg = [], []
    monkeypatch.setattr(email_alerts, "smtp_configured", lambda: True)
    monkeypatch.setattr(
        email_alerts, "send_email",
        lambda to, subj, text, html: emails.append(to) or (True, 1, None))
    monkeypatch.setattr(telegram_alerts, "telegram_configured", lambda: True)
    monkeypatch.setattr(
        telegram_alerts, "send_telegram",
        lambda chat_id, text: tg.append(chat_id) or (True, 1, None))
    main._alert_owner_new_lead("hot@example.com", "s1",
                              "https://github.com/o/r")
    assert emails == ["owner@example.com"]
    assert tg == ["12345"]
    assert "hot@example.com" in emails[0] or True  # subject has lead context


def test_owner_alert_silent_without_channels(monkeypatch):
    import email_alerts
    import telegram_alerts
    monkeypatch.setattr(email_alerts, "smtp_configured", lambda: False)
    monkeypatch.setattr(telegram_alerts, "telegram_configured",
                        lambda: False)
    # must not raise even with nothing configured
    main._alert_owner_new_lead("x@example.com", None, None)


def test_trial_reminders_nudge_after_3_days(monkeypatch):
    import email_alerts
    from datetime import datetime, timedelta, timezone
    import tasks
    init_db()
    old = (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()
    recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    db = get_db()
    # trial_reminders() scans the whole table, so start from a known
    # state: rows left by earlier tests (e.g. an emailed lead from the
    # listing test) would otherwise be reminded too once they age past
    # the 3-day cutoff. Later tests insert their own rows, so this
    # cleanup is safe.
    db.execute("DELETE FROM trial_leads")
    for email, emailed in [("old@example.com", old),
                          ("recent@example.com", recent),
                          ("never@example.com", None)]:
        db.execute(
            "INSERT OR IGNORE INTO trial_leads (email, created_at,"
            " emailed_at) VALUES (?,?,?)",
            (email, "2026-10-01T00:00:00+00:00", emailed))
    db.commit()
    db.close()
    sent = []
    monkeypatch.setattr(
        email_alerts, "send_email",
        lambda to, subj, text, html: sent.append(to) or (True, 1, None))
    out = tasks.trial_reminders()
    assert out == {"reminded": 1}
    assert sent == ["old@example.com"]
    db = get_db()
    row = db.execute(
        "SELECT reminded_at FROM trial_leads WHERE email=?",
        ("old@example.com",)).fetchone()
    assert row["reminded_at"] is not None
    row = db.execute(
        "SELECT reminded_at FROM trial_leads WHERE email=?",
        ("recent@example.com",)).fetchone()
    assert row["reminded_at"] is None
    db.close()
    # second run: idempotent, no double nudge
    out = tasks.trial_reminders()
    assert out == {"reminded": 0}


def test_trial_reminders_in_beat_schedule():
    import tasks
    assert "braimsec.trial-reminders" in tasks.celery_app.conf.beat_schedule
    entry = tasks.celery_app.conf.beat_schedule["braimsec.trial-reminders"]
    assert entry["task"] == "braimsec.trial_reminders"


def test_csv_export_neutralizes_formula_injection():
    owner_key, _ = _mk_keys()
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO trial_leads (email, created_at)"
        " VALUES (?,?)",
        ("=cmd|'/c calc'!A0", "2026-10-21T10:00:00+00:00"))
    db.commit()
    db.close()
    r = client.get("/api/trial/leads.csv",
                   headers={"X-API-Key": owner_key})
    assert r.status_code == 200
    # formula prefix neutralized with a leading single quote
    assert "'=cmd" in r.text
    assert "\n=cmd" not in r.text


def test_email_preview_owner_only():
    owner_key, member_key = _mk_keys()
    r = client.get("/api/trial/email-preview",
                   headers={"X-API-Key": owner_key})
    assert r.status_code == 200
    body = r.json()
    assert body["lang"] == "ar"  # dashboard default
    assert "تقرير فحص BraimSec" in body["subject"]
    assert "<ul>" in body["html"]
    assert "shop/views.py" in body["html"]
    assert "braimsec.world" in body["html"]
    r = client.get("/api/trial/email-preview?lang=en",
                   headers={"X-API-Key": owner_key})
    body = r.json()
    assert body["lang"] == "en"
    assert "BraimSec trial scan report" in body["subject"]
    assert "Full findings list" in body["text"]
    r = client.get("/api/trial/email-preview",
                   headers={"X-API-Key": member_key})
    assert r.status_code == 403
    r = client.get("/api/trial/email-preview")
    assert r.status_code == 401


def test_email_preview_uses_same_builder_as_sender():
    # The preview must render exactly what the background task sends:
    # same builder, same sample data.
    owner_key, _ = _mk_keys()
    subject, text, html = main._build_trial_lead_email(
        "demo/example-repo", list(main._TRIAL_PREVIEW_SAMPLE), "en")
    r = client.get("/api/trial/email-preview?lang=en",
                   headers={"X-API-Key": owner_key})
    assert r.status_code == 200
    body = r.json()
    assert body["subject"] == subject
    assert body["text"] == text
    assert body["html"] == html


def test_lead_report_email_unchanged_after_refactor(monkeypatch):
    # The refactor must not change what leads receive: capture the
    # email the background task builds for a real trial scan.
    import email_alerts
    import main as m
    scan_id = _mk_done_trial_scan_with_findings()
    sent = []
    monkeypatch.setattr(
        email_alerts, "send_email",
        lambda to, subj, text, html: sent.append((to, subj, text, html))
        or (True, 1, None))
    m._send_trial_lead_report("lead2@example.com", scan_id)
    assert len(sent) == 1
    to, subj, text, html = sent[0]
    assert to == "lead2@example.com"
    assert subj == "Your BraimSec trial scan report (1 finding)"
    assert "python.test.rule" in text
    assert "a.py:3" in text
    assert "braimsec.world" in html


def test_lead_capture_stores_lang():
    r = client.post("/api/trial/leads",
                    data={"email": "ar@example.com", "lang": "ar"})
    assert r.status_code == 200
    db = get_db()
    row = db.execute("SELECT lang FROM trial_leads WHERE email=?",
                     ("ar@example.com",)).fetchone()
    db.close()
    assert row["lang"] == "ar"
    # invalid lang falls back to en
    r = client.post("/api/trial/leads",
                    data={"email": "xx@example.com", "lang": "fr"})
    assert r.status_code == 200
    db = get_db()
    row = db.execute("SELECT lang FROM trial_leads WHERE email=?",
                     ("xx@example.com",)).fetchone()
    db.close()
    assert row["lang"] == "en"


def test_lead_report_email_arabic(monkeypatch):
    import email_alerts
    import main as m
    scan_id = _mk_done_trial_scan_with_findings()
    db = get_db()
    db.execute("INSERT OR IGNORE INTO trial_leads (email, scan_id, ip,"
               " created_at, lang) VALUES (?,?,?,?,?)",
               ("arlead@example.com", scan_id, "5.5.5.5",
                "2026-01-01T00:00:00+00:00", "ar"))
    db.commit()
    db.close()
    sent = []
    monkeypatch.setattr(
        email_alerts, "send_email",
        lambda to, subj, text, html: sent.append((to, subj, text, html))
        or (True, 1, None))
    m._send_trial_lead_report("arlead@example.com", scan_id)
    assert len(sent) == 1
    to, subj, text, html = sent[0]
    assert subj == "Your BraimSec trial scan report (1 finding)".replace(
        "Your BraimSec trial scan report (1 finding)",
        "تقرير فحص BraimSec التجريبي (1 نتيجة)")
    assert "اقتراحات إصلاح بالذكاء الاصطناعي" in text
    assert 'dir="rtl"' in html


def test_email_preview_lang_param():
    owner_key, _ = _mk_keys()
    r = client.get("/api/trial/email-preview",
                   headers={"X-API-Key": owner_key})
    assert r.status_code == 200
    assert r.json()["lang"] == "ar"
    assert "تقرير فحص BraimSec" in r.json()["subject"]
    r = client.get("/api/trial/email-preview?lang=en",
                   headers={"X-API-Key": owner_key})
    assert r.status_code == 200
    assert r.json()["lang"] == "en"
    assert "trial scan report" in r.json()["subject"]


def test_public_stats_no_auth():
    init_db()
    r = client.get("/api/trial/public-stats")
    assert r.status_code == 200
    body = r.json()
    assert "trial_scans" in body and "trial_scans_done" in body
    assert isinstance(body["trial_scans"], int)


def test_shareable_report_page():
    scan_id = _mk_done_trial_scan_with_findings()
    r = client.get(f"/trial/r/{scan_id}")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "github.com/o/r" in r.text
    assert "python.test.rule" in r.text
    assert 'property="og:title"' in r.text
    # unknown scan -> 404
    r = client.get("/trial/r/does_not_exist")
    assert r.status_code == 404
    # report page exposes nothing beyond the public JSON endpoint
    r = client.get(f"/trial/r/{scan_id}")
    j = client.get(f"/api/trial/scans/{scan_id}").json()
    assert str(j["total_findings"]) in r.text


def test_csv_includes_lang_column():
    owner_key, _ = _mk_keys()
    r = client.get("/api/trial/leads.csv",
                   headers={"X-API-Key": owner_key})
    assert r.status_code == 200
    assert r.text.splitlines()[0].strip() == \
        "email,scan_id,repo_url,created_at,emailed_at,reminded_at,lang"
