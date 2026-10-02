"""Tests for scheduled executive reports (emailed PDFs).

- pure logic: compute_next_report_run (weekly delegation, monthly math,
  invalid specs)
- HTTP: report-schedule CRUD, validation, RBAC, org isolation,
  project scoping, manual run, notifications filter
- driver: run_report_scheduler_once claims due schedules exactly once,
  generates the executive PDF and emails it with attachment; skipped when
  SMTP is off; skipped when the scope has no completed scans yet
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-repsched-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-repsched-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import email_alerts  # noqa: E402
import main  # noqa: E402
import scheduled_reports as sr  # noqa: E402
import tasks  # noqa: E402
from billing import (create_org, create_project, ensure_owner_org,  # noqa: E402
                     provision_key, seed_plans)
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()
MASTER = os.environ["BRAIMSEC_API_KEY"]


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(email_alerts.time, "sleep", lambda s: None)


@pytest.fixture(autouse=True)
def _clean_smtp_env(monkeypatch):
    for v in ("BRAIMSEC_SMTP_HOST", "BRAIMSEC_SMTP_PORT",
              "BRAIMSEC_SMTP_USER", "BRAIMSEC_SMTP_PASS",
              "BRAIMSEC_SMTP_FROM", "BRAIMSEC_SMTP_TLS"):
        monkeypatch.delenv(v, raising=False)
    FakeSMTP.sent = []
    FakeSMTP.failures_left = 0


@pytest.fixture()
def ctx():
    # Billing helpers FIRST (own connections), raw inserts after — see
    # AGENTS.md fixture write-lock trap.
    ensure_owner_org()
    org = create_org("RepSchedCo", plan="free")
    other = create_org("RepSchedOther", plan="free")
    admin = provision_key(org, "r-admin", actor="owner", role="admin")
    member = provision_key(org, "r-member", actor="owner", role="member")
    viewer = provision_key(org, "r-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "ro-member", actor="owner", role="member")
    proj = create_project(org, "RepProj", actor="owner")
    db = get_db()
    try:
        # Seed ids are fixed ("rscan1"/"rsched1") but each test makes a new
        # org, so stale seeds from earlier tests must go by id pattern.
        db.execute("DELETE FROM findings WHERE scan_id LIKE 'rscan%'")
        db.execute("DELETE FROM scans WHERE id LIKE 'rscan%'"
                   " OR org_id IN (?,?)", (org, other))
        db.execute("DELETE FROM report_schedules WHERE id LIKE 'rsched%'"
                   " OR org_id IN (?,?)", (org, other))
        db.execute("DELETE FROM notifications WHERE report_schedule_id"
                   " LIKE 'rsched%' OR org_id IN (?,?)", (org, other))
        db.execute("DELETE FROM alert_emails WHERE org_id IN (?,?)",
                   (org, other))
        db.commit()
    finally:
        db.close()
    return {"org": org, "other": other, "admin": admin, "member": member,
            "viewer": viewer, "o_member": o_member, "proj": proj}


@pytest.fixture()
def smtp(monkeypatch):
    monkeypatch.setenv("BRAIMSEC_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("BRAIMSEC_SMTP_USER", "bot@test")
    monkeypatch.setenv("BRAIMSEC_SMTP_PASS", "s3cret")
    monkeypatch.setenv("BRAIMSEC_SMTP_FROM", "braimsec@test")
    monkeypatch.setattr(email_alerts, "SMTP", FakeSMTP)
    FakeSMTP.sent = []
    FakeSMTP.failures_left = 0
    return FakeSMTP


class FakeSMTP:
    """Stand-in for smtplib.SMTP (mirrors test_email_alerts.py)."""
    sent = []
    failures_left = 0

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port

    def starttls(self):
        pass

    def login(self, user, password):
        self._user = user

    def send_message(self, msg):
        if FakeSMTP.failures_left > 0:
            FakeSMTP.failures_left -= 1
            raise ConnectionError("smtp down")
        FakeSMTP.sent.append(msg)

    def quit(self):
        pass


def _h(key):
    return {"X-API-Key": key}


def _client():
    return TestClient(main.app)


def _seed_scan(org_id, scan_id="rscan1", project_id=None, n_findings=3,
               created_days_ago=1):
    """One completed scan + findings, committed. Raw insert AFTER billing
    helpers (AGENTS.md write-lock lesson)."""
    created = (datetime.now(timezone.utc)
               - timedelta(days=created_days_ago)).isoformat()
    finished = (datetime.now(timezone.utc)
                - timedelta(days=created_days_ago, hours=-1)).isoformat()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO scans (id, org_id, target_name, status, created_at,"
            " finished_at, total_findings, project_id)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, org_id, "shop-api", "done", created, finished,
             n_findings, project_id))
        for i in range(n_findings):
            sev = "error" if i == 0 else ("warning" if i == 1 else "note")
            db.execute(
                "INSERT INTO findings (scan_id, tool, rule_id, severity,"
                " message, file, line) VALUES (?,?,?,?,?,?,?)",
                (scan_id, "semgrep", "braimsec-sqli-tainted", sev,
                 f"tainted SQL query {i}", "app/db.py", 10 + i))
        db.execute("INSERT INTO alert_emails (org_id, email, enabled,"
                   " created_at) VALUES (?,?,1,?)",
                   (org_id, "cto@example.com", created))
        db.commit()
    finally:
        db.close()


def _seed_due_schedule(org_id, sid="rsched1", frequency="weekly",
                       weekday=0, day_of_month=None, project_id=None,
                       days=90):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO report_schedules (id, org_id, name, frequency,"
            " run_time, weekday, day_of_month, timezone, project_id, days,"
            " enabled, next_run_at, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, org_id, "Weekly exec", frequency, "08:00", weekday,
             day_of_month, "UTC", project_id, days, 1,
             "2020-01-01T00:00:00+00:00",
             datetime.now(timezone.utc).isoformat()))
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# compute_next_report_run (pure)
# ---------------------------------------------------------------------------

def test_monthly_next_run_same_month():
    # 2026-10-01 12:00 UTC; monthly day 15 08:00 -> 2026-10-15
    after = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    nxt = sr.compute_next_report_run("monthly", "08:00", None, 15, "UTC",
                                     after)
    assert nxt.startswith("2026-10-15T08:00")


def test_monthly_next_run_rolls_to_next_month():
    # 2026-10-20; monthly day 15 -> 2026-11-15
    after = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
    nxt = sr.compute_next_report_run("monthly", "08:00", None, 15, "UTC",
                                     after)
    assert nxt.startswith("2026-11-15T08:00")


def test_monthly_next_run_year_rollover():
    # 2026-12-20; monthly day 15 -> 2027-01-15
    after = datetime(2026, 12, 20, 12, 0, tzinfo=timezone.utc)
    nxt = sr.compute_next_report_run("monthly", "08:00", None, 15, "UTC",
                                     after)
    assert nxt.startswith("2027-01-15T08:00")


def test_monthly_same_day_after_time_rolls():
    # 2026-10-15 09:00; monthly day 15 08:00 -> 2026-11-15
    after = datetime(2026, 10, 15, 9, 0, tzinfo=timezone.utc)
    nxt = sr.compute_next_report_run("monthly", "08:00", None, 15, "UTC",
                                     after)
    assert nxt.startswith("2026-11-15T08:00")


def test_weekly_delegates_to_scan_math():
    # 2026-10-01 is a Thursday; next Monday 09:00 -> 2026-10-05
    after = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    nxt = sr.compute_next_report_run("weekly", "09:00", 0, None, "UTC",
                                     after)
    assert nxt.startswith("2026-10-05T09:00")


def test_next_run_invalid_specs():
    after = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        sr.compute_next_report_run("daily", "08:00", None, None, "UTC",
                                   after)
    with pytest.raises(ValueError):
        sr.compute_next_report_run("monthly", "08:00", None, None, "UTC",
                                   after)
    with pytest.raises(ValueError):
        sr.compute_next_report_run("monthly", "08:00", None, 29, "UTC",
                                   after)
    with pytest.raises(ValueError):
        sr.compute_next_report_run("monthly", "25:00", None, 15, "UTC",
                                   after)
    with pytest.raises(ValueError):
        sr.compute_next_report_run("weekly", "08:00", None, None,
                                   "No/Such-TZ", after)


# ---------------------------------------------------------------------------
# HTTP: CRUD + validation
# ---------------------------------------------------------------------------

def _weekly_body(**kw):
    body = {"name": "Weekly exec", "frequency": "weekly", "run_time": "08:00",
            "weekday": 0, "timezone": "UTC"}
    body.update(kw)
    return body


def test_create_weekly_and_monthly(ctx):
    c = _client()
    r = c.post("/api/report-schedules", headers=_h(ctx["member"]),
               json=_weekly_body())
    assert r.status_code == 200, r.text
    sid = r.json()["report_schedule_id"]
    assert r.json()["next_run_at"] > datetime.now(timezone.utc).isoformat()
    r = c.post("/api/report-schedules", headers=_h(ctx["member"]),
               json={"name": "Monthly exec", "frequency": "monthly",
                     "run_time": "09:30", "day_of_month": 15,
                     "timezone": "UTC"})
    assert r.status_code == 200, r.text
    rows = c.get("/api/report-schedules",
                 headers=_h(ctx["member"])).json()
    assert {x["id"] for x in rows} >= {sid, r.json()["report_schedule_id"]}


def test_create_validation(ctx):
    c = _client()
    h = _h(ctx["member"])
    # bad frequency
    r = c.post("/api/report-schedules", headers=h,
               json=_weekly_body(frequency="daily"))
    assert r.status_code == 400
    # weekly without weekday
    r = c.post("/api/report-schedules", headers=h,
               json=_weekly_body(weekday=None))
    assert r.status_code == 400
    # monthly without day_of_month
    r = c.post("/api/report-schedules", headers=h,
               json={"name": "M", "frequency": "monthly", "run_time": "08:00",
                     "timezone": "UTC"})
    assert r.status_code == 400
    # day_of_month out of range
    r = c.post("/api/report-schedules", headers=h,
               json={"name": "M", "frequency": "monthly", "run_time": "08:00",
                     "day_of_month": 31, "timezone": "UTC"})
    assert r.status_code == 400
    # unknown project
    r = c.post("/api/report-schedules", headers=h,
               json=_weekly_body(project_id="proj_nope"))
    assert r.status_code == 404
    # missing name
    r = c.post("/api/report-schedules", headers=h,
               json=_weekly_body(name=""))
    assert r.status_code == 400
    # bad timezone
    r = c.post("/api/report-schedules", headers=h,
               json=_weekly_body(timezone="Mars/Olympus"))
    assert r.status_code == 400
    # negative days
    r = c.post("/api/report-schedules", headers=h,
               json=_weekly_body(days=-1))
    assert r.status_code == 400


def test_create_rbac(ctx):
    c = _client()
    # viewer cannot create
    r = c.post("/api/report-schedules", headers=_h(ctx["viewer"]),
               json=_weekly_body())
    assert r.status_code == 403
    # no key at all
    r = c.post("/api/report-schedules", json=_weekly_body())
    assert r.status_code == 401


def test_org_isolation(ctx):
    c = _client()
    r = c.post("/api/report-schedules", headers=_h(ctx["member"]),
               json=_weekly_body(name="A-only"))
    sid = r.json()["report_schedule_id"]
    # other org sees nothing
    rows = c.get("/api/report-schedules",
                 headers=_h(ctx["o_member"])).json()
    assert all(x["id"] != sid for x in rows)
    # other org cannot fetch / patch / delete / run
    assert c.get(f"/api/report-schedules/{sid}",
                 headers=_h(ctx["o_member"])).status_code == 404
    assert c.patch(f"/api/report-schedules/{sid}",
                   headers=_h(ctx["o_member"]),
                   json={"name": "hijack"}).status_code == 404
    assert c.delete(f"/api/report-schedules/{sid}",
                    headers=_h(ctx["o_member"])).status_code == 404
    assert c.post(f"/api/report-schedules/{sid}/run",
                  headers=_h(ctx["o_member"])).status_code == 404


def test_project_scoping(ctx):
    c = _client()
    # other org's project -> 404
    o_proj = create_project(ctx["other"], "OProj", actor="owner")
    r = c.post("/api/report-schedules", headers=_h(ctx["member"]),
               json=_weekly_body(project_id=o_proj))
    assert r.status_code == 404
    # own project works
    r = c.post("/api/report-schedules", headers=_h(ctx["member"]),
               json=_weekly_body(name="Proj report",
                                 project_id=ctx["proj"]))
    assert r.status_code == 200, r.text
    sid = r.json()["report_schedule_id"]
    got = c.get(f"/api/report-schedules/{sid}",
                headers=_h(ctx["member"])).json()
    assert got["project_id"] == ctx["proj"]


def test_project_scoped_key_rejected(ctx):
    # Project-scoped keys cannot touch org-level surfaces — same rule as
    # /api/schedules (require_org_scope).
    c = _client()
    pkey = provision_key(ctx["org"], "r-projkey", actor="owner",
                         role="member", project_id=ctx["proj"])
    assert c.post("/api/report-schedules", headers=_h(pkey),
                  json=_weekly_body()).status_code == 403
    assert c.get("/api/report-schedules",
                 headers=_h(pkey)).status_code == 403


def test_update_recomputes_next_run(ctx):
    c = _client()
    r = c.post("/api/report-schedules", headers=_h(ctx["member"]),
               json=_weekly_body())
    sid = r.json()["report_schedule_id"]
    before = c.get(f"/api/report-schedules/{sid}",
                   headers=_h(ctx["member"])).json()["next_run_at"]
    r = c.patch(f"/api/report-schedules/{sid}", headers=_h(ctx["member"]),
                json={"frequency": "monthly", "day_of_month": 20})
    assert r.status_code == 200, r.text
    upd = r.json()
    assert upd["frequency"] == "monthly" and upd["day_of_month"] == 20
    assert upd["next_run_at"] != before
    # incoherent change rejected
    r = c.patch(f"/api/report-schedules/{sid}", headers=_h(ctx["member"]),
                json={"frequency": "weekly", "weekday": None})
    assert r.status_code == 400


def test_delete_removes_schedule_and_history(ctx, smtp):
    c = _client()
    _seed_scan(ctx["org"])
    _seed_due_schedule(ctx["org"])
    out = sr.deliver_scheduled_report("rsched1")
    assert out["delivered"] is True
    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM notifications WHERE"
                   " report_schedule_id=?", ("rsched1",)).fetchone()["c"]
    db.close()
    assert n >= 1
    r = c.delete("/api/report-schedules/rsched1",
                 headers=_h(ctx["member"]))
    assert r.status_code == 200
    assert c.get("/api/report-schedules/rsched1",
                 headers=_h(ctx["member"])).status_code == 404
    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM notifications WHERE"
                   " report_schedule_id=?", ("rsched1",)).fetchone()["c"]
    db.close()
    assert n == 0


def test_audit_logged(ctx):
    c = _client()
    r = c.post("/api/report-schedules", headers=_h(ctx["admin"]),
               json=_weekly_body(name="Audited"))
    sid = r.json()["report_schedule_id"]
    db = get_db()
    row = db.execute("SELECT action FROM audit_log WHERE org_id=? AND"
                     " resource_type='report_schedule' AND resource_id=?"
                     " ORDER BY id DESC LIMIT 1",
                     (ctx["org"], sid)).fetchone()
    db.close()
    assert row and row["action"] == "report_schedule.created"


# ---------------------------------------------------------------------------
# Driver: delivery
# ---------------------------------------------------------------------------

def test_driver_delivers_pdf_with_attachment(ctx, smtp):
    _seed_scan(ctx["org"])
    _seed_due_schedule(ctx["org"])
    out = sr.run_report_scheduler_once()
    assert len(out["ran"]) == 1
    assert out["ran"][0]["delivered"] is True
    # one email with the PDF attached
    assert len(smtp.sent) == 1
    msg = smtp.sent[0]
    assert msg["To"] == "cto@example.com"
    atts = list(msg.iter_attachments())
    assert len(atts) == 1
    assert atts[0].get_filename() == "braimsec-executive-report.pdf"
    assert atts[0].get_content_type() == "application/pdf"
    assert atts[0].get_content()[:4] == b"%PDF"
    # notifications recorded
    db = get_db()
    rows = db.execute(
        "SELECT channel, recipient, status, report_schedule_id FROM"
        " notifications WHERE report_schedule_id=?", ("rsched1",)).fetchall()
    db.close()
    assert len(rows) == 1
    assert rows[0]["channel"] == "email_report"
    assert rows[0]["recipient"] == "cto@example.com"
    assert rows[0]["status"] == "sent"
    # next run advanced: weekly Monday 08:00 in the future
    db = get_db()
    nxt = db.execute("SELECT next_run_at FROM report_schedules WHERE id=?",
                     ("rsched1",)).fetchone()["next_run_at"]
    db.close()
    assert nxt > datetime.now(timezone.utc).isoformat()
    assert datetime.fromisoformat(nxt).weekday() == 0


def test_driver_monthly_advances_a_month(ctx, smtp):
    _seed_scan(ctx["org"])
    _seed_due_schedule(ctx["org"], sid="rschedM", frequency="monthly",
                       weekday=None, day_of_month=15)
    out = sr.run_report_scheduler_once()
    by_id = {r["id"]: r for r in out["ran"]}
    assert by_id["rschedM"]["delivered"] is True
    db = get_db()
    nxt = db.execute("SELECT next_run_at FROM report_schedules WHERE id=?",
                     ("rschedM",)).fetchone()["next_run_at"]
    db.close()
    dt = datetime.fromisoformat(nxt)
    assert dt > datetime.now(timezone.utc)
    assert dt.day == 15 and dt.hour == 8


def test_driver_exactly_once(ctx, smtp):
    _seed_scan(ctx["org"])
    _seed_due_schedule(ctx["org"])
    sr.run_report_scheduler_once()
    # second beat tick: nothing due anymore
    out = sr.run_report_scheduler_once()
    assert out["ran"] == [] and out["skipped"] == []
    assert len(smtp.sent) == 1  # no double-send


def test_driver_skipped_without_smtp(ctx):
    _seed_scan(ctx["org"])
    _seed_due_schedule(ctx["org"])
    out = sr.deliver_scheduled_report("rsched1")
    assert out["delivered"] is False
    assert out["reason"] == "smtp not configured"
    assert smtp_not_used()
    db = get_db()
    rows = db.execute(
        "SELECT status, error FROM notifications WHERE"
        " report_schedule_id=?", ("rsched1",)).fetchall()
    db.close()
    assert len(rows) == 1 and rows[0]["status"] == "skipped"
    assert "SMTP" in (rows[0]["error"] or "")


def smtp_not_used():
    # called in tests without SMTP configured: any send would be a bug
    return len(FakeSMTP.sent) == 0


def test_driver_skipped_without_scans(ctx, smtp):
    # recipients exist (seeded) but no completed scans in scope
    db = get_db()
    try:
        db.execute("INSERT INTO alert_emails (org_id, email, enabled,"
                   " created_at) VALUES (?,?,1,?)",
                   (ctx["org"], "cto@example.com",
                    datetime.now(timezone.utc).isoformat()))
        db.commit()
    finally:
        db.close()
    _seed_due_schedule(ctx["org"])
    out = sr.deliver_scheduled_report("rsched1")
    assert out["delivered"] is False
    assert "no completed scans" in out["reason"]
    assert smtp_not_used()
    db = get_db()
    row = db.execute("SELECT status, channel FROM notifications WHERE"
                     " report_schedule_id=?", ("rsched1",)).fetchone()
    last_err = db.execute("SELECT last_error FROM report_schedules"
                          " WHERE id=?", ("rsched1",)).fetchone()["last_error"]
    db.close()
    assert row["status"] == "skipped" and row["channel"] == "email_report"
    assert "no completed scans" in (last_err or "")


def test_driver_no_recipients(ctx, smtp):
    _seed_scan(ctx["org"])
    db = get_db()
    try:
        db.execute("DELETE FROM alert_emails WHERE org_id=?", (ctx["org"],))
        db.commit()
    finally:
        db.close()
    _seed_due_schedule(ctx["org"])
    out = sr.deliver_scheduled_report("rsched1")
    assert out["delivered"] is False
    assert out["reason"] == "no recipients"
    assert smtp_not_used()


def test_run_now_endpoint(ctx, smtp):
    c = _client()
    _seed_scan(ctx["org"])
    _seed_due_schedule(ctx["org"])
    r = c.post("/api/report-schedules/rsched1/run",
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    assert r.json()["delivered"] is True
    assert len(smtp.sent) == 1
    # manual run does not shift the cadence
    db = get_db()
    nxt = db.execute("SELECT next_run_at FROM report_schedules WHERE id=?",
                     ("rsched1",)).fetchone()["next_run_at"]
    db.close()
    assert nxt == "2020-01-01T00:00:00+00:00"
    # viewer cannot trigger
    r = c.post("/api/report-schedules/rsched1/run",
               headers=_h(ctx["viewer"]))
    assert r.status_code == 403


def test_run_now_disabled(ctx):
    c = _client()
    _seed_scan(ctx["org"])
    _seed_due_schedule(ctx["org"])
    db = get_db()
    try:
        db.execute("UPDATE report_schedules SET enabled=0 WHERE id=?",
                   ("rsched1",))
        db.commit()
    finally:
        db.close()
    r = c.post("/api/report-schedules/rsched1/run",
               headers=_h(ctx["member"]))
    assert r.status_code == 400


def test_notifications_filter(ctx, smtp):
    c = _client()
    _seed_scan(ctx["org"])
    _seed_due_schedule(ctx["org"])
    sr.deliver_scheduled_report("rsched1")
    rows = c.get("/api/notifications?report_schedule_id=rsched1",
                 headers=_h(ctx["member"])).json()
    assert len(rows) == 1 and rows[0]["channel"] == "email_report"
    # other org cannot see them
    rows = c.get("/api/notifications?report_schedule_id=rsched1",
                 headers=_h(ctx["o_member"])).json()
    assert rows == []


def test_beat_task_wires_reports(monkeypatch):
    seen = {}

    def fake_scans():
        seen["scans"] = True
        return {"ran": []}

    def fake_reports():
        seen["reports"] = True
        return {"ran": []}

    def fake_certs():
        seen["certs"] = True
        return {"checked": 0}

    def fake_uptime():
        seen["uptime"] = True
        return {"checked": 0}

    def fake_digests():
        seen["digests"] = True
        return {"sent": 0}

    import scheduler
    import cert_monitor
    import uptime_monitor
    import uptime_digest
    monkeypatch.setattr(scheduler, "run_scheduler_once", fake_scans)
    monkeypatch.setattr(sr, "run_report_scheduler_once", fake_reports)
    monkeypatch.setattr(cert_monitor, "run_cert_checks_once", fake_certs)
    monkeypatch.setattr(uptime_monitor, "run_uptime_checks_once", fake_uptime)
    monkeypatch.setattr(uptime_digest, "run_digests_once", fake_digests)
    out = tasks.check_schedules.__wrapped__()
    assert seen == {"scans": True, "reports": True, "certs": True,
                    "uptime": True, "digests": True}
    assert set(out) == {"scans", "reports", "certs", "uptime", "digests"}


def test_smtp_retry_then_success(ctx, smtp):
    _seed_scan(ctx["org"])
    _seed_due_schedule(ctx["org"])
    smtp.failures_left = 2  # 2 failures, 3rd attempt succeeds
    out = sr.deliver_scheduled_report("rsched1")
    assert out["delivered"] is True
    assert len(smtp.sent) == 1
    db = get_db()
    row = db.execute("SELECT status, attempts FROM notifications WHERE"
                     " report_schedule_id=?", ("rsched1",)).fetchone()
    db.close()
    assert row["status"] == "sent" and row["attempts"] == 3
