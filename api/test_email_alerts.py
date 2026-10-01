"""Tests for email alerts (SMTP) — the twin channel of webhook alerts.

- pure logic: validate_email, smtp_settings/configured, build_email
- HTTP: alert-emails CRUD (validation, RBAC, org isolation, audit)
- driver: evaluate_schedule_alerts / evaluate_vcs_alerts send email on the
  same trigger as webhooks (new findings >= threshold), stay silent on
  baseline / no-change / below-threshold, record skipped when SMTP is off
- delivery: send_email retries with backoff; notifications rows carry
  channel='email' and the recipient address
"""
import os
import sys
import tempfile

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-email-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-email-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import email_alerts  # noqa: E402
import main  # noqa: E402
import scheduler  # noqa: E402
import vcs  # noqa: E402
from billing import create_org, ensure_owner_org, provision_key, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()
MASTER = os.environ["BRAIMSEC_API_KEY"]
WEBHOOK = "https://hooks.test/services/abc"  # .test: no DNS, passes SSRF check


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
    for v in ("BRAIMSEC_SMTP_HOST", "BRAIMSEC_SMTP_PORT", "BRAIMSEC_SMTP_USER",
              "BRAIMSEC_SMTP_PASS", "BRAIMSEC_SMTP_FROM", "BRAIMSEC_SMTP_TLS"):
        monkeypatch.delenv(v, raising=False)


class FakeSMTP:
    """Stand-in for smtplib.SMTP. Class-level script controls failures."""
    sent = []
    failures_left = 0

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port

    def starttls(self):
        pass

    def login(self, user, password):
        # The password must never be observable here in a failure message;
        # assert the test double simply doesn't record it.
        self._user = user

    def send_message(self, msg):
        if FakeSMTP.failures_left > 0:
            FakeSMTP.failures_left -= 1
            raise ConnectionError("smtp down")
        FakeSMTP.sent.append(msg)

    def quit(self):
        pass


@pytest.fixture()
def _smtp(monkeypatch):
    FakeSMTP.sent = []
    FakeSMTP.failures_left = 0
    monkeypatch.setattr(email_alerts, "SMTP", FakeSMTP)
    monkeypatch.setenv("BRAIMSEC_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("BRAIMSEC_SMTP_USER", "bot@test")
    monkeypatch.setenv("BRAIMSEC_SMTP_PASS", "s3cret")
    return FakeSMTP


@pytest.fixture()
def ctx():
    ensure_owner_org()
    org = create_org("EmailTestCo", plan="free")
    other = create_org("EmailOtherCo", plan="free")
    admin = provision_key(org, "e-admin", actor="owner", role="admin")
    member = provision_key(org, "e-member", actor="owner", role="member")
    viewer = provision_key(org, "e-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "o-member", actor="owner", role="member")
    return {"org": org, "admin": admin, "member": member, "viewer": viewer,
            "o_member": o_member}


def _h(key):
    return {"X-API-Key": key}


def _uid():
    import uuid as _u
    return _u.uuid4().hex[:8]


def _mk_scan(db, org, scan_id, status, findings, vcs_repo_id=None):
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " total_findings, target_dir, vcs_repo_id) VALUES (?,?,?,?,?,?,?,?)",
        (scan_id, org, "api", status, "2026-10-01T00:00:00+00:00",
         len(findings), "/x", vcs_repo_id))
    for f in findings:
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, f["tool"], f["rule_id"], f["severity"], f["message"],
             f["file"], f["line"], 1))
    db.commit()


def _mk_sched(db, org, last_scan, prev_scan, webhook_url=WEBHOOK):
    sid = "esched_" + _uid()
    db.execute(
        "INSERT INTO schedules (id, org_id, name, target_path, frequency,"
        " run_time, timezone, alert_severity, webhook_url, enabled,"
        " next_run_at, created_at, last_scan_id, prev_scan_id)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, org, "Nightly", "/x", "daily", "02:00", "UTC", "warning",
         webhook_url, 1, "2026-10-02T02:00:00+00:00",
         "2026-10-01T00:00:00+00:00", last_scan, prev_scan))
    db.commit()
    return sid


def _mk_repo(db, org, last_scan, prev_scan, webhook_url=WEBHOOK):
    rid = "erepo_" + _uid()
    db.execute(
        "INSERT INTO vcs_repos (id, org_id, provider, repo_url, full_name,"
        " branch, webhook_secret_hash, webhook_url, alert_severity, enabled,"
        " last_scan_id, prev_scan_id, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rid, org, "github", "https://github.com/acme/app", "acme/app",
         "main", "h", webhook_url, "warning", 1, last_scan, prev_scan,
         "2026-10-01T00:00:00+00:00"))
    db.commit()
    return rid


def _add_recipient(db, org, email, enabled=1):
    db.execute("INSERT INTO alert_emails (org_id, email, enabled, created_at)"
               " VALUES (?,?,?,?)",
               (org, email, enabled, "2026-10-01T00:00:00+00:00"))
    db.commit()


# ---------------------------------------------------------------------------
# Pure logic: validation, config, message building
# ---------------------------------------------------------------------------

def test_validate_email_accepts():
    assert email_alerts.validate_email("  Team@Example.COM ") == \
        "team@example.com"
    assert email_alerts.validate_email("a.b+tag@sub.domain.co") == \
        "a.b+tag@sub.domain.co"


def test_validate_email_rejects():
    for bad in ("", "plain", "a@b", "@x.com", "a b@c.com", "a@b..com",
                ".a@b.com", "a.@b.com", "a..b@c.com", "a@b.c",
                "x" * 250 + "@b.com", "a<b>@c.com"):
        with pytest.raises(ValueError):
            email_alerts.validate_email(bad)


def test_smtp_configured(monkeypatch):
    assert email_alerts.smtp_configured() is False
    monkeypatch.setenv("BRAIMSEC_SMTP_HOST", "smtp.test")
    cfg = email_alerts.smtp_settings()
    assert cfg["host"] == "smtp.test" and cfg["port"] == 587
    assert cfg["tls"] is True and cfg["from_addr"] == ""
    monkeypatch.setenv("BRAIMSEC_SMTP_USER", "bot@test")
    assert email_alerts.smtp_settings()["from_addr"] == "bot@test"
    monkeypatch.setenv("BRAIMSEC_SMTP_TLS", "0")
    assert email_alerts.smtp_settings()["tls"] is False
    assert email_alerts.smtp_configured() is True


def test_build_email_arabic_and_safe():
    findings = [{"severity": "error", "rule_id": "braimsec.taint.sql",
                 "file": "a.py", "line": 3, "message": "tainted <script>"}]
    subject, text, html = email_alerts.build_email(
        "schedule.alert", "فحص مجدول: Nightly", "الهدف: api",
        findings, "error", "https://dash.test")
    assert "نتائج جديدة" in subject and "حرجة" in subject
    assert 'dir="rtl"' in html and 'lang="ar"' in html
    assert "<script>" not in html  # escaped
    assert "&lt;script&gt;" in html
    # No secrets in the message
    assert "s3cret" not in text + html
    # Header injection is neutralized
    s2, _, _ = email_alerts.build_email(
        "schedule.alert", "x\ny: injected", "", findings, "error", "")
    assert "\n" not in s2

    # Failure events get their own template
    fs, ft, fh = email_alerts.build_email(
        "vcs.failed", "المستودع acme/app", "فرع main — boom", [], "error",
        "")
    assert "فشل الفحص" in fs and "boom" in ft and "boom" in fh


# ---------------------------------------------------------------------------
# HTTP: recipient CRUD — validation, RBAC, org isolation, audit
# ---------------------------------------------------------------------------

def test_email_crud_and_rbac(ctx):
    c = TestClient(main.app)
    # viewer can list, cannot add
    r = c.get("/api/alert-emails", headers=_h(ctx["viewer"]))
    assert r.status_code == 200 and r.json()["emails"] == []
    r = c.post("/api/alert-emails", json={"email": "v@x.com"},
               headers=_h(ctx["viewer"]))
    assert r.status_code == 403
    # invalid address
    r = c.post("/api/alert-emails", json={"email": "not-an-email"},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    # missing address
    r = c.post("/api/alert-emails", json={}, headers=_h(ctx["member"]))
    assert r.status_code == 400
    # member adds
    r = c.post("/api/alert-emails", json={"email": " Team@Example.com "},
               headers=_h(ctx["member"]))
    assert r.status_code == 200
    eid = r.json()["id"]
    assert r.json()["email"] == "team@example.com"
    # duplicate (case-insensitive after normalization)
    r = c.post("/api/alert-emails", json={"email": "team@example.com"},
               headers=_h(ctx["member"]))
    assert r.status_code == 409
    # other org cannot see or touch it
    r = c.get("/api/alert-emails", headers=_h(ctx["o_member"]))
    assert r.json()["emails"] == []
    for meth, kw in (("patch", {"json": {"enabled": 0}}),
                     ("delete", {})):
        rr = getattr(c, meth)(f"/api/alert-emails/{eid}",
                              headers=_h(ctx["o_member"]), **kw)
        assert rr.status_code == 404, (meth, rr.text)
    # toggle + delete
    r = c.patch(f"/api/alert-emails/{eid}", json={"enabled": 0},
                headers=_h(ctx["member"]))
    assert r.json()["enabled"] is False
    r = c.patch(f"/api/alert-emails/{eid}", json={},
                headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.delete(f"/api/alert-emails/{eid}", headers=_h(ctx["member"]))
    assert r.json()["deleted"] is True
    r = c.get("/api/alert-emails", headers=_h(ctx["member"]))
    assert r.json()["emails"] == []


def test_email_list_reports_smtp_status(ctx, monkeypatch):
    c = TestClient(main.app)
    r = c.get("/api/alert-emails", headers=_h(ctx["member"]))
    assert r.json()["smtp_configured"] is False
    monkeypatch.setenv("BRAIMSEC_SMTP_HOST", "smtp.test")
    r = c.get("/api/alert-emails", headers=_h(ctx["member"]))
    assert r.json()["smtp_configured"] is True


def test_email_crud_audited(ctx):
    c = TestClient(main.app)
    r = c.post("/api/alert-emails", json={"email": "audit@x.com"},
               headers=_h(ctx["member"]))
    eid = r.json()["id"]
    c.delete(f"/api/alert-emails/{eid}", headers=_h(ctx["member"]))
    db = get_db()
    acts = {row["action"] for row in db.execute(
        "SELECT action FROM audit_log WHERE org_id=? AND action LIKE"
        " 'alert_email.%'", (ctx["org"],)).fetchall()}
    db.close()
    assert {"alert_email.added", "alert_email.removed"} <= acts


# ---------------------------------------------------------------------------
# Driver: same trigger as webhooks, per-channel recording
# ---------------------------------------------------------------------------

def _new_finding_pair():
    old = [{"tool": "semgrep", "rule_id": "r.a", "severity": "warning",
            "message": "old issue", "file": "a.py", "line": 1}]
    new = old + [{"tool": "gitleaks", "rule_id": "aws", "severity": "error",
                  "message": "new secret", "file": "k.py", "line": 5}]
    return old, new


def test_email_sent_on_new_findings(ctx, _smtp, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_recipient(db, ctx["org"], "a@x.com")
    _add_recipient(db, ctx["org"], "b@x.com")
    old, new = _new_finding_pair()
    so, sn = "es_old_" + _uid(), "es_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is True
    assert out["email"]["emailed"] is True
    assert out["email"]["sent"] == 2
    # One message per recipient (no address leaks into another's headers)
    assert len(FakeSMTP.sent) == 2
    tos = sorted(m["To"] for m in FakeSMTP.sent)
    assert tos == ["a@x.com", "b@x.com"]
    assert "نتائج جديدة" in FakeSMTP.sent[0]["Subject"]

    db = get_db()
    rows = db.execute(
        "SELECT channel, recipient, status, event FROM notifications"
        " WHERE scan_id=? ORDER BY id", (sn,)).fetchall()
    db.close()
    kinds = {(r["channel"], r["recipient"], r["status"], r["event"])
             for r in rows}
    assert ("webhook", "", "sent", "schedule.alert") in kinds
    assert ("email", "a@x.com", "sent", "schedule.alert") in kinds
    assert ("email", "b@x.com", "sent", "schedule.alert") in kinds


def test_email_only_schedule_no_webhook(ctx, _smtp, monkeypatch):
    """Empty webhook_url disables the webhook channel; email still fires."""
    db = get_db()
    _add_recipient(db, ctx["org"], "solo@x.com")
    old, new = _new_finding_pair()
    so, sn = "eo_old_" + _uid(), "eo_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so, webhook_url="")
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is True  # email counts as an alert
    assert out["email"]["sent"] == 1
    db = get_db()
    rows = db.execute(
        "SELECT channel FROM notifications WHERE scan_id=?", (sn,)).fetchall()
    db.close()
    assert [r["channel"] for r in rows] == ["email"]


def test_no_recipients_no_email_rows(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: captured.append(payload) or (True, 1, 200, None))
    db = get_db()
    old, new = _new_finding_pair()
    so, sn = "en_old_" + _uid(), "en_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is True and out["email"]["emailed"] is False
    assert out["email"]["reason"] == "no recipients"
    assert captured  # webhook still fired
    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM notifications WHERE scan_id=?",
                   (sn,)).fetchone()["c"]
    db.close()
    assert n == 1  # webhook row only


def test_email_skipped_without_smtp(ctx, monkeypatch):
    """Recipients exist but SMTP is off: recorded as skipped, no crash."""
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_recipient(db, ctx["org"], "wait@x.com")
    old, new = _new_finding_pair()
    so, sn = "ek_old_" + _uid(), "ek_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["email"]["emailed"] is False
    assert out["email"]["reason"] == "smtp not configured"
    db = get_db()
    row = db.execute(
        "SELECT channel, recipient, status, error FROM notifications"
        " WHERE scan_id=? AND channel='email'", (sn,)).fetchone()
    db.close()
    assert row["status"] == "skipped" and row["recipient"] == "wait@x.com"
    assert "BRAIMSEC_SMTP_HOST" in row["error"]


def test_email_silent_without_new_findings(ctx, _smtp, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_recipient(db, ctx["org"], "q@x.com")
    same = [{"tool": "semgrep", "rule_id": "r.a", "severity": "warning",
             "message": "same", "file": "a.py", "line": 1}]
    so, sn = "eq_old_" + _uid(), "eq_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", same)
    _mk_scan(db, ctx["org"], sn, "done", same)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is False
    assert FakeSMTP.sent == []
    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM notifications WHERE scan_id=?",
                   (sn,)).fetchone()["c"]
    db.close()
    assert n == 0


def test_email_respects_threshold(ctx, _smtp, monkeypatch):
    db = get_db()
    _add_recipient(db, ctx["org"], "t@x.com")
    new = [{"tool": "semgrep", "rule_id": "r.a", "severity": "note",
            "message": "minor", "file": "a.py", "line": 2}]
    so, sn = "et_old_" + _uid(), "et_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", [])
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)  # threshold=warning
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is False and FakeSMTP.sent == []


def test_disabled_recipient_not_emailed(ctx, _smtp, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_recipient(db, ctx["org"], "off@x.com", enabled=0)
    _add_recipient(db, ctx["org"], "on@x.com", enabled=1)
    old, new = _new_finding_pair()
    so, sn = "ed_old_" + _uid(), "ed_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["email"]["sent"] == 1
    assert [m["To"] for m in FakeSMTP.sent] == ["on@x.com"]


def test_email_retry_then_success(ctx, _smtp, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    FakeSMTP.failures_left = 2  # two failures, third attempt succeeds
    db = get_db()
    _add_recipient(db, ctx["org"], "r@x.com")
    old, new = _new_finding_pair()
    so, sn = "er_old_" + _uid(), "er_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["email"]["emailed"] is True
    db = get_db()
    row = db.execute(
        "SELECT status, attempts FROM notifications WHERE scan_id=?"
        " AND channel='email'", (sn,)).fetchone()
    db.close()
    assert (row["status"], row["attempts"]) == ("sent", 3)


def test_email_records_failure(ctx, _smtp, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    FakeSMTP.failures_left = 99  # always fails
    db = get_db()
    _add_recipient(db, ctx["org"], "f@x.com")
    old, new = _new_finding_pair()
    so, sn = "ef_old_" + _uid(), "ef_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["email"]["emailed"] is False
    db = get_db()
    row = db.execute(
        "SELECT status, attempts, error FROM notifications WHERE scan_id=?"
        " AND channel='email'", (sn,)).fetchone()
    db.close()
    assert row["status"] == "failed" and row["attempts"] == 3
    assert row["error"]  # recorded, and contains no password
    assert "s3cret" not in row["error"]


def test_failed_scan_emails(ctx, _smtp, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_recipient(db, ctx["org"], "ops@x.com")
    sb = "sbad_" + _uid()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " target_dir, error) VALUES (?,?,?,?,?,?,?)",
        (sb, ctx["org"], "api", "failed",
         "2026-10-01T00:00:00+00:00", "/x", "boom"))
    db.commit()
    _mk_sched(db, ctx["org"], sb, "scan_old_z_" + _uid())
    db.close()

    out = scheduler.evaluate_schedule_alerts(sb)
    assert out["alerted"] is True and out["event"] == "schedule.failed"
    assert out["email"]["sent"] == 1
    assert "فشل الفحص" in FakeSMTP.sent[0]["Subject"]
    db = get_db()
    row = db.execute(
        "SELECT event, channel, status FROM notifications WHERE scan_id=?"
        " AND channel='email'", (sb,)).fetchone()
    db.close()
    assert (row["event"], row["status"]) == ("schedule.failed", "sent")


# ---------------------------------------------------------------------------
# VCS path: same trigger, repo context in the message
# ---------------------------------------------------------------------------

def test_vcs_email_alert(ctx, _smtp, monkeypatch):
    monkeypatch.setattr(
        vcs, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_recipient(db, ctx["org"], "dev@x.com")
    old, new = _new_finding_pair()
    rid = _mk_repo(db, ctx["org"], None, None)  # placeholder links
    so, sn = "ev_old_" + _uid(), "ev_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old, vcs_repo_id=rid)
    _mk_scan(db, ctx["org"], sn, "done", new, vcs_repo_id=rid)
    db.execute("UPDATE vcs_repos SET last_scan_id=?, prev_scan_id=?"
               " WHERE id=?", (sn, so, rid))
    db.commit()
    db.close()

    out = vcs.evaluate_vcs_alerts(sn)
    assert out["alerted"] is True
    assert out["email"]["sent"] == 1
    assert "acme/app" in FakeSMTP.sent[0]["Subject"]
    db = get_db()
    row = db.execute(
        "SELECT event, channel, recipient, status FROM notifications"
        " WHERE scan_id=? AND channel='email'", (sn,)).fetchone()
    db.close()
    assert (row["event"], row["recipient"],
            row["status"]) == ("vcs.alert", "dev@x.com", "sent")


def test_vcs_email_org_isolation(ctx, _smtp, monkeypatch):
    """Recipients of another org never get this org's alerts."""
    monkeypatch.setattr(
        vcs, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_recipient(db, ctx["org"], "mine@x.com")  # not the alerting org
    other = create_org("EmailStrangerCo", plan="free")
    rid = _mk_repo(db, other, None, None)
    old, new = _new_finding_pair()
    so, sn = "ex_old_" + _uid(), "ex_new_" + _uid()
    _mk_scan(db, other, so, "done", old, vcs_repo_id=rid)
    _mk_scan(db, other, sn, "done", new, vcs_repo_id=rid)
    db.execute("UPDATE vcs_repos SET last_scan_id=?, prev_scan_id=?"
               " WHERE id=?", (sn, so, rid))
    db.commit()
    db.close()

    out = vcs.evaluate_vcs_alerts(sn)
    assert out["email"]["emailed"] is False
    assert FakeSMTP.sent == []
