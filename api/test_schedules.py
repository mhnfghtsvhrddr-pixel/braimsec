"""Tests for scheduled scans + new-findings alerts (webhooks).

- pure logic: compute_next_run, finding_fingerprint, build_alert_payload
- HTTP: schedule CRUD, validation, RBAC, manual run, notifications log
- driver: run_scheduler_once claims due schedules exactly once
- alerts: evaluate_schedule_alerts diffs new vs previous findings and
  notifies (first run = silent baseline; no new findings = quiet)
- delivery: send_alert retries with backoff, records outcomes
"""
import os
import sys
import tempfile
from datetime import datetime, timezone

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-sched-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-sched-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import scheduler  # noqa: E402
import tasks  # noqa: E402
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
    monkeypatch.setattr(scheduler.time, "sleep", lambda s: None)


@pytest.fixture()
def _mock_engines(monkeypatch):
    monkeypatch.setattr(tasks, "run_semgrep", lambda d, scope=None: [])
    monkeypatch.setattr(tasks, "run_gitleaks", lambda d: [])
    monkeypatch.setattr(tasks, "run_sca", lambda d: [])
    monkeypatch.setattr(tasks.time, "sleep", lambda s: None)
    monkeypatch.setattr(scheduler.time, "sleep", lambda s: None)


@pytest.fixture()
def ctx():
    ensure_owner_org()
    org = create_org("SchedTestCo", plan="free")
    other = create_org("SchedOtherCo", plan="free")
    admin = provision_key(org, "s-admin", actor="owner", role="admin")
    member = provision_key(org, "s-member", actor="owner", role="member")
    viewer = provision_key(org, "s-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "o-member", actor="owner", role="member")
    return {"org": org, "admin": admin, "member": member, "viewer": viewer,
            "o_member": o_member}


@pytest.fixture()
def target(tmp_path):
    d = os.path.join(main.SCAN_ROOT, f"pytest-sched-{tmp_path.name}")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "app.py"), "w") as f:
        f.write("x = 1\n")
    return d


def _h(key):
    return {"X-API-Key": key}


# ---------------------------------------------------------------------------
# compute_next_run
# ---------------------------------------------------------------------------

def test_next_run_daily_before_time():
    after = datetime(2026, 10, 1, 1, 0, tzinfo=timezone.utc)
    nxt = scheduler.compute_next_run("daily", "02:00", None, "UTC", after)
    assert nxt.startswith("2026-10-01T02:00")


def test_next_run_daily_after_time_rolls():
    after = datetime(2026, 10, 1, 3, 0, tzinfo=timezone.utc)
    nxt = scheduler.compute_next_run("daily", "02:00", None, "UTC", after)
    assert nxt.startswith("2026-10-02T02:00")


def test_next_run_weekly():
    # 2026-10-01 is a Thursday; next Monday 09:00 -> 2026-10-05
    after = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    nxt = scheduler.compute_next_run("weekly", "09:00", 0, "UTC", after)
    assert nxt.startswith("2026-10-05T09:00")
    # Same Monday 08:00 -> today 09:00
    after2 = datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc)
    nxt2 = scheduler.compute_next_run("weekly", "09:00", 0, "UTC", after2)
    assert nxt2.startswith("2026-10-05T09:00")


def test_next_run_timezone_beirut():
    # 02:00 Asia/Beirut on Oct 1 (UTC+3); 22:00 UTC Sep 30 is past it
    after = datetime(2026, 9, 30, 22, 0, tzinfo=timezone.utc)
    nxt = scheduler.compute_next_run("daily", "02:00", None, "Asia/Beirut",
                                     after)
    assert nxt.startswith("2026-10-01T02:00")


def test_next_run_invalid():
    with pytest.raises(ValueError):
        scheduler.compute_next_run("hourly", "02:00", None, "UTC")
    with pytest.raises(ValueError):
        scheduler.compute_next_run("daily", "25:00", None, "UTC")
    with pytest.raises(ValueError):
        scheduler.compute_next_run("weekly", "02:00", None, "UTC")
    with pytest.raises(ValueError):
        scheduler.compute_next_run("daily", "02:00", None, "No/SuchZone")


# ---------------------------------------------------------------------------
# finding_fingerprint + build_alert_payload
# ---------------------------------------------------------------------------

def test_fingerprint_ignores_line_numbers():
    a = scheduler.finding_fingerprint("semgrep", "r1", "a.py", "msg")
    b = scheduler.finding_fingerprint("semgrep", "r1", "a.py", "msg")
    assert a == b
    c = scheduler.finding_fingerprint("semgrep", "r1", "a.py", "other")
    assert a != c
    d = scheduler.finding_fingerprint("gitleaks", "r1", "a.py", "msg")
    assert a != d


def test_build_alert_payload():
    sched = {"id": "s1", "name": "Nightly"}
    scan = {"id": "sc1", "target_name": "api"}
    findings = [
        {"severity": "warning", "tool": "semgrep", "rule_id": "r.x",
         "file": "a.py", "line": 3, "message": "m1"},
        {"severity": "error", "tool": "gitleaks", "rule_id": "aws",
         "file": "k.py", "line": 9, "message": "m2"},
    ]
    p = scheduler.build_alert_payload(sched, scan, findings)
    assert p["event"] == "schedule.alert"
    assert p["new_findings"] == 2
    assert p["highest_severity"] == "error"
    assert "text" in p and "content" in p  # Slack + Discord compat
    assert len(p["findings"]) == 2
    big = findings * 8
    p2 = scheduler.build_alert_payload(sched, scan, big)
    assert p2["truncated"] is True
    assert len(p2["findings"]) == scheduler.MAX_ALERT_FINDINGS


# ---------------------------------------------------------------------------
# HTTP: CRUD + validation + RBAC
# ---------------------------------------------------------------------------

def _create(client, key, **kw):
    body = {"name": "Nightly", "target_path": kw.pop("target_path", None)
            or os.path.join(main.SCAN_ROOT, "pytest-sched-x"),
            "frequency": "daily", "run_time": "02:00",
            "timezone": "UTC", "alert_severity": "warning",
            "webhook_url": WEBHOOK}
    body.update(kw)
    return client.post("/api/schedules", json=body, headers=_h(key))


def test_crud_flow(ctx, target):
    c = TestClient(main.app)
    r = _create(c, ctx["member"], target_path=target)
    assert r.status_code == 200, r.text
    sid = r.json()["schedule_id"]
    assert r.json()["next_run_at"]

    r = c.get("/api/schedules", headers=_h(ctx["member"]))
    assert r.status_code == 200 and len(r.json()) >= 1

    r = c.get(f"/api/schedules/{sid}", headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["name"] == "Nightly"

    r = c.patch(f"/api/schedules/{sid}", json={"enabled": 0},
                headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["enabled"] == 0

    # weekly without weekday is rejected
    r = c.patch(f"/api/schedules/{sid}",
                json={"frequency": "weekly", "run_time": "03:00"},
                headers=_h(ctx["member"]))
    assert r.status_code == 400

    r = c.patch(f"/api/schedules/{sid}",
                json={"frequency": "weekly", "weekday": 0},
                headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["weekday"] == 0

    r = c.delete(f"/api/schedules/{sid}", headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["deleted"] is True
    r = c.get(f"/api/schedules/{sid}", headers=_h(ctx["member"]))
    assert r.status_code == 404


def test_create_validation(ctx, target):
    c = TestClient(main.app)
    # target outside the sandbox -> 403
    r = _create(c, ctx["member"], target_path="/etc")
    assert r.status_code in (400, 403)
    # private webhook target -> 400
    r = _create(c, ctx["member"], target_path=target,
                webhook_url="http://127.0.0.1/hook")
    assert r.status_code == 400
    # missing webhook -> 200 (email-only schedule; webhook alerts disabled)
    r = _create(c, ctx["member"], target_path=target, webhook_url="")
    assert r.status_code == 200
    assert r.json()["schedule_id"]
    c.delete(f"/api/schedules/{r.json()['schedule_id']}",
             headers=_h(ctx["member"]))
    # bad severity -> 400
    r = _create(c, ctx["member"], target_path=target, alert_severity="crit")
    assert r.status_code == 400
    # bad timezone -> 400
    r = _create(c, ctx["member"], target_path=target, timezone="Mars/Olympus")
    assert r.status_code == 400


def test_rbac_and_org_isolation(ctx, target):
    c = TestClient(main.app)
    # viewer cannot create
    r = _create(c, ctx["viewer"], target_path=target)
    assert r.status_code == 403
    # viewer can list
    r = c.get("/api/schedules", headers=_h(ctx["viewer"]))
    assert r.status_code == 200
    # member creates; other org's member cannot see or touch it
    r = _create(c, ctx["member"], target_path=target)
    sid = r.json()["schedule_id"]
    for meth in ("get", "patch", "delete"):
        rr = getattr(c, meth)(f"/api/schedules/{sid}",
                              headers=_h(ctx["o_member"]))
        assert rr.status_code in (403, 404), (meth, rr.text)
    r = c.post(f"/api/schedules/{sid}/run", headers=_h(ctx["o_member"]))
    assert r.status_code in (403, 404)


def test_manual_run_disabled(ctx, target, _mock_engines):
    c = TestClient(main.app)
    r = _create(c, ctx["member"], target_path=target)
    sid = r.json()["schedule_id"]
    c.patch(f"/api/schedules/{sid}", json={"enabled": 0},
            headers=_h(ctx["member"]))
    r = c.post(f"/api/schedules/{sid}/run", headers=_h(ctx["member"]))
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Driver: due claim is atomic
# ---------------------------------------------------------------------------

def test_run_scheduler_once_claims_and_advances(ctx, target, _mock_engines,
                                               monkeypatch):
    # Mirror the real _create_scheduled_scan contract: it links the
    # schedule to the new scan BEFORE enqueue (the worker alert hook
    # resolves the schedule through that link).
    created = []

    def rec(db, sched):
        created.append(sched["id"])
        db.execute(
            "UPDATE schedules SET prev_scan_id=last_scan_id, last_scan_id=?,"
            " last_run_at=? WHERE id=?",
            ("scX", "2026-10-01T12:00:00+00:00", sched["id"]))
        db.commit()
        return "scX"

    monkeypatch.setattr(scheduler, "_create_scheduled_scan", rec)
    db = get_db()
    past = "2020-01-01T00:00:00+00:00"
    db.execute(
        "INSERT INTO schedules (id, org_id, name, target_path, frequency,"
        " run_time, timezone, alert_severity, webhook_url, enabled,"
        " next_run_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("sched_due", ctx["org"], "Due", target, "daily", "02:00", "UTC",
         "warning", WEBHOOK, 1, past, past))
    db.commit()
    db.close()

    out = scheduler.run_scheduler_once("2026-10-01T12:00:00+00:00")
    assert [r["id"] for r in out["ran"]] == ["sched_due"]
    assert created == ["sched_due"]

    db = get_db()
    row = db.execute("SELECT next_run_at, last_run_at, last_scan_id"
                     " FROM schedules WHERE id='sched_due'").fetchone()
    db.close()
    assert row["next_run_at"].startswith("2026-10-02T02:00")
    assert row["last_run_at"] == "2026-10-01T12:00:00+00:00"
    assert row["last_scan_id"] == "scX"

    # Second tick: nothing due anymore.
    out2 = scheduler.run_scheduler_once("2026-10-01T12:01:00+00:00")
    assert out2["ran"] == [] and out2["skipped"] == []


# ---------------------------------------------------------------------------
# Alerts: diff, baseline silence, failure
# ---------------------------------------------------------------------------

def _uid():
    import uuid as _u
    return _u.uuid4().hex[:8]


def _mk_scan(db, org, scan_id, status, findings):
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " total_findings, target_dir) VALUES (?,?,?,?,?,?,?)",
        (scan_id, org, "api", status, "2026-10-01T00:00:00+00:00",
         len(findings), "/x"))
    for f in findings:
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, f["tool"], f["rule_id"], f["severity"], f["message"],
             f["file"], f["line"], 1))
    db.commit()


def _mk_sched(db, org, last_scan, prev_scan):
    sid = "sched_" + _uid()
    db.execute(
        "INSERT INTO schedules (id, org_id, name, target_path, frequency,"
        " run_time, timezone, alert_severity, webhook_url, enabled,"
        " next_run_at, created_at, last_scan_id, prev_scan_id)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, org, "Nightly", "/x", "daily", "02:00", "UTC", "warning",
         WEBHOOK, 1, "2026-10-02T02:00:00+00:00",
         "2026-10-01T00:00:00+00:00", last_scan, prev_scan))
    db.commit()
    return sid


def test_alert_on_new_findings(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: captured.append((url, payload)) or (True, 1, 200, None))
    db = get_db()
    old = [{"tool": "semgrep", "rule_id": "r.a", "severity": "warning",
            "message": "old issue", "file": "a.py", "line": 1}]
    new = old + [{"tool": "gitleaks", "rule_id": "aws", "severity": "error",
                  "message": "new secret", "file": "k.py", "line": 5}]
    so, sn = "scan_old_" + _uid(), "scan_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is True and out["new_count"] == 1
    url, payload = captured[0]
    assert url == WEBHOOK
    assert payload["event"] == "schedule.alert"
    assert payload["highest_severity"] == "error"
    assert payload["findings"][0]["message"] == "new secret"

    db = get_db()
    n = db.execute("SELECT status, attempts, new_count, severity"
                   " FROM notifications").fetchone()
    db.close()
    assert (n["status"], n["attempts"], n["new_count"],
            n["severity"]) == ("sent", 1, 1, "error")


def test_alert_respects_threshold(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: captured.append(payload) or (True, 1, 200, None))
    db = get_db()
    old = []
    new = [{"tool": "semgrep", "rule_id": "r.a", "severity": "note",
            "message": "minor", "file": "a.py", "line": 2}]
    so, sn = "scan_o2_" + _uid(), "scan_n2_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    sched_id = _mk_sched(db, ctx["org"], sn, so)  # threshold=warning
    db.close()
    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is False and captured == []
    db = get_db()
    c0 = db.execute("SELECT COUNT(*) c FROM notifications"
                    " WHERE schedule_id=?", (sched_id,)).fetchone()["c"]
    assert c0 == 0
    db.close()


def test_first_run_is_silent_baseline(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: captured.append(payload) or (True, 1, 200, None))
    db = get_db()
    new = [{"tool": "semgrep", "rule_id": "r.a", "severity": "error",
            "message": "everything is new", "file": "a.py", "line": 1}]
    sf = "scan_first_" + _uid()
    _mk_scan(db, ctx["org"], sf, "done", new)
    _mk_sched(db, ctx["org"], sf, None)
    db.close()
    out = scheduler.evaluate_schedule_alerts(sf)
    assert out["alerted"] is False
    assert out["reason"] == "first run: baseline set"
    assert captured == []


def test_failed_scan_alerts(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: captured.append(payload) or (True, 1, 200, None))
    db = get_db()
    sb = "scan_bad_" + _uid()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " target_dir, error) VALUES (?,?,?,?,?,?,?)",
        (sb, ctx["org"], "api", "failed",
         "2026-10-01T00:00:00+00:00", "/x", "boom"))
    db.commit()
    _mk_sched(db, ctx["org"], sb, "scan_old_x_" + _uid())
    db.close()
    out = scheduler.evaluate_schedule_alerts(sb)
    assert out["alerted"] is True and out["event"] == "schedule.failed"
    assert captured[0]["event"] == "schedule.failed"


def test_moved_finding_is_not_new(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: captured.append(payload) or (True, 1, 200, None))
    db = get_db()
    old = [{"tool": "semgrep", "rule_id": "r.a", "severity": "error",
            "message": "same bug", "file": "a.py", "line": 10}]
    new = [{"tool": "semgrep", "rule_id": "r.a", "severity": "error",
            "message": "same bug", "file": "a.py", "line": 42}]
    so, sn = "scan_mo_" + _uid(), "scan_mn_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()
    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is False and captured == []


# ---------------------------------------------------------------------------
# Regression: inline-mode end-to-end (the worker alert hook must see the
# schedule link — it fires inside _new_scan, before any later UPDATE)
# ---------------------------------------------------------------------------

def test_inline_end_to_end_alert(ctx, target, monkeypatch):
    captured = []
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: captured.append((url, payload)) or (True, 1, 200, None))
    findings_now = []

    # Isolate from earlier tests: the DB file is shared, and their
    # schedules stay enabled with a past next_run_at — run_scheduler_once
    # would otherwise claim them too.
    _db0 = get_db()
    _db0.execute("DELETE FROM schedules")
    _db0.commit()
    _db0.close()

    def fake_semgrep(d, scope=None):
        return [dict(f) for f in findings_now]

    monkeypatch.setattr(tasks, "run_semgrep", fake_semgrep)
    monkeypatch.setattr(tasks, "run_gitleaks", lambda d, scope=None: [])
    monkeypatch.setattr(tasks, "run_sca", lambda d, scope=None: [])

    # Own target dir (uid-suffixed): the shared `target` fixture dir can
    # carry files from earlier pytest invocations, which would corrupt
    # the incremental fingerprint diff.
    etarget = os.path.join(target, "e2e_" + _uid())
    os.makedirs(etarget, exist_ok=True)
    with open(os.path.join(etarget, "app.py"), "w") as f:
        f.write("x = 1\n")

    db = get_db()
    db.execute(
        "INSERT INTO schedules (id, org_id, name, target_path, frequency,"
        " run_time, timezone, alert_severity, webhook_url, enabled,"
        " next_run_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("sched_e2e_" + _uid(), ctx["org"], "E2E", etarget, "daily", "02:00",
         "UTC", "warning", WEBHOOK, 1,
         "2020-01-01T00:00:00+00:00", "2020-01-01T00:00:00+00:00"))
    db.commit()
    db.close()

    # Run 1: clean — becomes the silent baseline.
    out1 = scheduler.run_scheduler_once("2026-10-01T12:00:00+00:00")
    assert len(out1["ran"]) == 1 and captured == []

    # Run 2: a new error-severity finding appears.
    findings_now.append({
        "tool": "semgrep", "rule_id": "r.e2e", "severity": "error",
        "message": "e2e vuln", "file": os.path.join(etarget, "app.py"),
        "line": 1, "col": 1})
    with open(os.path.join(etarget, "newmod.py"), "w") as f:
        f.write("y = 2\n")
    out2 = scheduler.run_scheduler_once("2026-10-02T12:00:00+00:00")
    assert len(out2["ran"]) == 1

    assert len(captured) == 1
    url, payload = captured[0]
    assert url == WEBHOOK
    assert payload["event"] == "schedule.alert"
    assert payload["new_findings"] == 1
    assert payload["highest_severity"] == "error"

    db = get_db()
    n = db.execute("SELECT status, event, new_count FROM notifications"
                   ).fetchone()
    db.close()
    assert (n["status"], n["event"], n["new_count"]) == ("sent", "schedule.alert", 1)


# ---------------------------------------------------------------------------
# send_alert retry behavior
# ---------------------------------------------------------------------------

def test_send_alert_retries_then_succeeds(monkeypatch):
    calls = []

    def fake_post(url, body, headers, timeout):
        calls.append(url)
        if len(calls) < 3:
            raise ConnectionError("down")
        return 200

    monkeypatch.setattr(scheduler, "safe_webhook_post", fake_post)
    ok, attempts, code, err = scheduler.send_alert(WEBHOOK, {"event": "x"})
    assert (ok, attempts, code, err) == (True, 3, 200, None)


def test_send_alert_gives_up(monkeypatch):
    monkeypatch.setattr(scheduler, "safe_webhook_post",
                        lambda *a: (_ for _ in ()).throw(
                            ConnectionError("down")))
    ok, attempts, code, err = scheduler.send_alert(WEBHOOK, {"event": "x"})
    assert ok is False and attempts == 3 and code is None
    assert "down" in err


def test_notifications_log_endpoint(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: captured.append(payload) or (True, 1, 200, None))
    db = get_db()
    so, sn = "scan_lo_" + _uid(), "scan_ln_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", [])
    _mk_scan(db, ctx["org"], sn, "done",
             [{"tool": "semgrep", "rule_id": "r.a", "severity": "error",
               "message": "m", "file": "a.py", "line": 1}])
    sched_id = _mk_sched(db, ctx["org"], sn, so)
    db.close()
    scheduler.evaluate_schedule_alerts(sn)
    c = TestClient(main.app)
    r = c.get("/api/notifications", headers=_h(ctx["member"]))
    assert r.status_code == 200 and len(r.json()) == 1
    r = c.get(f"/api/notifications?schedule_id={sched_id}",
              headers=_h(ctx["member"]))
    assert r.status_code == 200 and len(r.json()) == 1
    r = c.get("/api/notifications", headers=_h(ctx["viewer"]))
    assert r.status_code == 200
