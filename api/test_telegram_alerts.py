"""Tests for Telegram alerts (Bot API) — the third alert channel.

- pure logic: validate_chat_id, bot_token/configured, build_telegram_message
- HTTP: telegram-chats CRUD (validation, dup, RBAC, org isolation, audit)
- driver: evaluate_schedule_alerts / evaluate_vcs_alerts send telegram on
  the same trigger as webhooks/email, stay silent on baseline / no-change,
  record skipped when the bot token is off
- delivery: send_telegram retries with backoff; notifications rows carry
  channel='telegram' and the chat id; the token never appears in logs or
  stored errors
"""
import io
import json
import logging
import os
import sys
import tempfile

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-telegram-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-telegram-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import scheduler  # noqa: E402
import telegram_alerts  # noqa: E402
import vcs  # noqa: E402
from billing import create_org, ensure_owner_org, provision_key, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()
MASTER = os.environ["BRAIMSEC_API_KEY"]
WEBHOOK = "https://hooks.test/services/abc"  # .test: no DNS, passes SSRF check
TOKEN = "123456:TEST-token-for-unit-tests-only-aaaa"


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(telegram_alerts.time, "sleep", lambda s: None)


@pytest.fixture(autouse=True)
def _clean_tg_env(monkeypatch):
    monkeypatch.delenv("BRAIMSEC_TELEGRAM_BOT_TOKEN", raising=False)


class FakeResp:
    def __init__(self, payload: dict):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeUrlopen:
    """Stand-in for urllib.request.urlopen. Class-level script."""
    calls = []          # list of (url, body_dict)
    failures_left = 0   # ConnectionError failures before success
    api_ok = True       # when False, Bot API answers {"ok": false, ...}
    raise_text = None   # when set, raise RuntimeError(raise_text) instead

    def __call__(self, req, timeout=None):
        body = json.loads(req.data.decode())
        FakeUrlopen.calls.append((req.full_url, body))
        if FakeUrlopen.raise_text is not None:
            raise RuntimeError(FakeUrlopen.raise_text)
        if FakeUrlopen.failures_left > 0:
            FakeUrlopen.failures_left -= 1
            raise ConnectionError("tg down")
        if not FakeUrlopen.api_ok:
            return FakeResp({"ok": False, "description": "Bad Request: chat not found"})
        return FakeResp({"ok": True, "result": {"message_id": 7}})


@pytest.fixture()
def _tg(monkeypatch):
    FakeUrlopen.calls = []
    FakeUrlopen.failures_left = 0
    FakeUrlopen.api_ok = True
    FakeUrlopen.raise_text = None
    monkeypatch.setattr(telegram_alerts, "urlopen", FakeUrlopen())
    monkeypatch.setenv("BRAIMSEC_TELEGRAM_BOT_TOKEN", TOKEN)
    return FakeUrlopen


@pytest.fixture()
def ctx():
    ensure_owner_org()
    org = create_org("TgTestCo", plan="free")
    other = create_org("TgOtherCo", plan="free")
    admin = provision_key(org, "t-admin", actor="owner", role="admin")
    member = provision_key(org, "t-member", actor="owner", role="member")
    viewer = provision_key(org, "t-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "o-member", actor="owner", role="member")
    return {"org": org, "other": other, "admin": admin, "member": member,
            "viewer": viewer, "o_member": o_member}


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
    sid = "tsched_" + _uid()
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
    rid = "trepo_" + _uid()
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


def _add_chat(db, org, chat_id, label="ops"):
    db.execute("INSERT INTO telegram_chats (org_id, chat_id, label, created_at)"
               " VALUES (?,?,?,?)",
               (org, chat_id, label, "2026-10-01T00:00:00+00:00"))
    db.commit()


def _new_finding_pair():
    old = [{"tool": "semgrep", "rule_id": "r.a", "severity": "warning",
            "message": "old issue", "file": "a.py", "line": 1}]
    new = old + [{"tool": "gitleaks", "rule_id": "aws", "severity": "error",
                  "message": "new secret", "file": "k.py", "line": 5}]
    return old, new


# ---------------------------------------------------------------------------
# Pure logic: validation, config, message building
# ---------------------------------------------------------------------------

def test_validate_chat_id_accepts():
    assert telegram_alerts.validate_chat_id("123456789") == "123456789"
    assert telegram_alerts.validate_chat_id("  42 ") == "42"
    assert telegram_alerts.validate_chat_id("-1001234567890") == "-1001234567890"
    assert telegram_alerts.validate_chat_id(987) == "987"


def test_validate_chat_id_rejects():
    for bad in ("", "abc", "12.5", "+123", "12 34", "0x10", "007",
                "1" * 21, "--5", "chat_1"):
        with pytest.raises(ValueError):
            telegram_alerts.validate_chat_id(bad)


def test_telegram_configured(monkeypatch):
    assert telegram_alerts.telegram_configured() is False
    monkeypatch.setenv("BRAIMSEC_TELEGRAM_BOT_TOKEN", "  " + TOKEN + "  ")
    assert telegram_alerts.telegram_configured() is True
    assert telegram_alerts.bot_token() == TOKEN


def test_build_telegram_message_arabic():
    old, new = _new_finding_pair()
    slim = [{"severity": f["severity"], "rule_id": f["rule_id"],
             "file": f["file"], "line": f["line"], "message": f["message"]}
            for f in new]
    text = telegram_alerts.build_telegram_message(
        "schedule.alert", "فحص مجدول: Nightly", "الهدف: api",
        slim, "error", "https://dash.test")
    assert "2 نتيجة جديدة" in text
    assert "حرجة" in text
    assert "k.py:5" in text
    assert len(text) <= telegram_alerts.MAX_MESSAGE_CHARS


def test_build_telegram_message_failed_event():
    text = telegram_alerts.build_telegram_message(
        "schedule.failed", "Nightly", "boom", [], "error", "")
    assert "فشل الفحص" in text


def test_build_telegram_message_truncates():
    many = [{"severity": "error", "rule_id": f"r{i}", "file": "a.py",
             "line": i, "message": "x" * 500} for i in range(50)]
    text = telegram_alerts.build_telegram_message(
        "schedule.alert", "H", "S", many, "error", "https://dash.test/l" * 50)
    assert len(text) <= telegram_alerts.MAX_MESSAGE_CHARS


# ---------------------------------------------------------------------------
# HTTP: telegram-chats CRUD (validation, RBAC, org isolation, audit)
# ---------------------------------------------------------------------------

def test_telegram_crud_and_rbac(ctx):
    c = TestClient(main.app)
    # viewer may list but not add
    r = c.get("/api/telegram-chats", headers=_h(ctx["viewer"]))
    assert r.status_code == 200 and r.json()["chats"] == []
    r = c.post("/api/telegram-chats", json={"chat_id": "111"},
               headers=_h(ctx["viewer"]))
    assert r.status_code == 403
    # member adds
    r = c.post("/api/telegram-chats",
               json={"chat_id": "111", "label": "on-call"},
               headers=_h(ctx["member"]))
    assert r.status_code == 200
    row_id = r.json()["id"]
    assert r.json()["chat_id"] == "111"
    # duplicate -> 409
    r = c.post("/api/telegram-chats", json={"chat_id": "111"},
               headers=_h(ctx["member"]))
    assert r.status_code == 409
    # invalid -> 400
    r = c.post("/api/telegram-chats", json={"chat_id": "nope"},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post("/api/telegram-chats", json={}, headers=_h(ctx["member"]))
    assert r.status_code == 400
    # list shows it
    r = c.get("/api/telegram-chats", headers=_h(ctx["member"]))
    assert [ch["chat_id"] for ch in r.json()["chats"]] == ["111"]
    # other org: isolated (cannot see, cannot delete)
    r = c.get("/api/telegram-chats", headers=_h(ctx["o_member"]))
    assert r.json()["chats"] == []
    r = c.delete(f"/api/telegram-chats/{row_id}", headers=_h(ctx["o_member"]))
    assert r.status_code == 404
    # no key -> 401
    r = c.get("/api/telegram-chats")
    assert r.status_code == 401
    # owner org deletes
    r = c.delete(f"/api/telegram-chats/{row_id}", headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["deleted"] is True
    r = c.delete(f"/api/telegram-chats/{row_id}", headers=_h(ctx["member"]))
    assert r.status_code == 404


def test_telegram_list_reports_config_status(ctx, monkeypatch):
    c = TestClient(main.app)
    r = c.get("/api/telegram-chats", headers=_h(ctx["member"]))
    assert r.json()["telegram_configured"] is False
    monkeypatch.setenv("BRAIMSEC_TELEGRAM_BOT_TOKEN", TOKEN)
    r = c.get("/api/telegram-chats", headers=_h(ctx["member"]))
    assert r.json()["telegram_configured"] is True


def test_telegram_crud_audited(ctx):
    c = TestClient(main.app)
    r = c.post("/api/telegram-chats", json={"chat_id": "222"},
               headers=_h(ctx["member"]))
    cid = r.json()["id"]
    c.delete(f"/api/telegram-chats/{cid}", headers=_h(ctx["member"]))
    db = get_db()
    acts = {row["action"] for row in db.execute(
        "SELECT action FROM audit_log WHERE org_id=? AND action LIKE"
        " 'telegram_chat.%'", (ctx["org"],)).fetchall()}
    db.close()
    assert {"telegram_chat.added", "telegram_chat.removed"} <= acts


# ---------------------------------------------------------------------------
# Driver: same trigger as webhooks/email, per-channel recording
# ---------------------------------------------------------------------------

def test_telegram_sent_on_new_findings(ctx, _tg, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_chat(db, ctx["org"], "111")
    _add_chat(db, ctx["org"], "-222")
    old, new = _new_finding_pair()
    so, sn = "ts_old_" + _uid(), "ts_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is True
    assert out["telegram"]["telegrammed"] is True
    assert out["telegram"]["sent"] == 2
    # One HTTP call per chat; token in URL (Bot API auth), never in body
    assert len(FakeUrlopen.calls) == 2
    for url, body in FakeUrlopen.calls:
        assert TOKEN in url
        assert TOKEN not in json.dumps(body)
    bodies = sorted(c[1]["chat_id"] for c in FakeUrlopen.calls)
    assert bodies == [-222, 111]
    assert "نتيجة جديدة" in FakeUrlopen.calls[0][1]["text"]

    db = get_db()
    rows = db.execute(
        "SELECT channel, recipient, status, event FROM notifications"
        " WHERE scan_id=? ORDER BY id", (sn,)).fetchall()
    db.close()
    kinds = {(r["channel"], r["recipient"], r["status"], r["event"])
             for r in rows}
    assert ("webhook", "", "sent", "schedule.alert") in kinds
    assert ("telegram", "111", "sent", "schedule.alert") in kinds
    assert ("telegram", "-222", "sent", "schedule.alert") in kinds


def test_no_chats_no_telegram_rows(ctx, _tg, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    old, new = _new_finding_pair()
    so, sn = "tn_old_" + _uid(), "tn_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["telegram"]["telegrammed"] is False
    assert FakeUrlopen.calls == []
    db = get_db()
    chans = {r["channel"] for r in db.execute(
        "SELECT channel FROM notifications WHERE scan_id=?", (sn,))}
    db.close()
    assert "telegram" not in chans


def test_telegram_skipped_without_token(ctx, monkeypatch):
    db = get_db()
    _add_chat(db, ctx["org"], "333")
    old, new = _new_finding_pair()
    so, sn = "tk_old_" + _uid(), "tk_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", new)
    _mk_sched(db, ctx["org"], sn, so, webhook_url="")
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    # telegram counts nothing as alerted; email has no recipients either
    assert out["telegram"]["telegrammed"] is False
    assert out["telegram"]["reason"] == "telegram not configured"
    db = get_db()
    row = db.execute(
        "SELECT channel, status, error FROM notifications WHERE scan_id=?",
        (sn,)).fetchone()
    db.close()
    assert row["channel"] == "telegram" and row["status"] == "skipped"
    assert "BRAIMSEC_TELEGRAM_BOT_TOKEN" in row["error"]


def test_telegram_silent_without_new_findings(ctx, _tg, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_chat(db, ctx["org"], "444")
    old, _ = _new_finding_pair()
    so, sn = "tq_old_" + _uid(), "tq_new_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old)
    _mk_scan(db, ctx["org"], sn, "done", list(old))
    _mk_sched(db, ctx["org"], sn, so)
    db.close()

    out = scheduler.evaluate_schedule_alerts(sn)
    assert out["alerted"] is False
    assert FakeUrlopen.calls == []


def test_telegram_retry_then_success(ctx, _tg):
    FakeUrlopen.failures_left = 2
    ok, attempts, err = telegram_alerts.send_telegram("555", "hello")
    assert ok is True and attempts == 3 and err is None
    assert len(FakeUrlopen.calls) == 3


def test_telegram_records_failure(ctx, _tg):
    FakeUrlopen.api_ok = False
    ok, attempts, err = telegram_alerts.send_telegram("666", "hello")
    assert ok is False and attempts == 3
    assert err and "chat not found" in err
    assert TOKEN not in err


def test_token_never_in_logs_or_errors(ctx, _tg, caplog):
    evil = "boom " + TOKEN + " leaked?"
    FakeUrlopen.raise_text = evil
    with caplog.at_level(logging.WARNING, logger="braimsec.telegram_alerts"):
        ok, attempts, err = telegram_alerts.send_telegram("777", "hi")
    assert ok is False
    assert TOKEN not in (err or "")
    assert "[redacted]" in (err or "")
    for rec in caplog.records:
        assert TOKEN not in rec.getMessage()


def test_failed_scan_telegram(ctx, _tg, monkeypatch):
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_chat(db, ctx["org"], "888")
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
    assert out["telegram"]["sent"] == 1
    assert "فشل الفحص" in FakeUrlopen.calls[0][1]["text"]
    db = get_db()
    row = db.execute(
        "SELECT event, channel, status FROM notifications WHERE scan_id=?"
        " AND channel='telegram'", (sb,)).fetchone()
    db.close()
    assert (row["event"], row["status"]) == ("schedule.failed", "sent")


# ---------------------------------------------------------------------------
# VCS path: same trigger, repo context in the message
# ---------------------------------------------------------------------------

def test_vcs_telegram_alert(ctx, _tg, monkeypatch):
    monkeypatch.setattr(
        vcs, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_chat(db, ctx["org"], "999")
    old, new = _new_finding_pair()
    so, sn = "tv_old_" + _uid(), "tv_new_" + _uid()
    rid = _mk_repo(db, ctx["org"], sn, so)
    _mk_scan(db, ctx["org"], so, "done", old, vcs_repo_id=rid)
    _mk_scan(db, ctx["org"], sn, "done", new, vcs_repo_id=rid)
    db.close()

    out = vcs.evaluate_vcs_alerts(sn)
    assert out["alerted"] is True
    assert out["telegram"]["sent"] == 1
    assert "نتيجة جديدة" in FakeUrlopen.calls[0][1]["text"]
    db = get_db()
    row = db.execute(
        "SELECT event, channel, status FROM notifications WHERE scan_id=?"
        " AND channel='telegram'", (sn,)).fetchone()
    db.close()
    assert (row["event"], row["status"]) == ("vcs.alert", "sent")


def test_vcs_telegram_org_isolation(ctx, _tg, monkeypatch):
    """A chat registered under org A never fires for org B's scans."""
    monkeypatch.setattr(
        vcs, "send_alert",
        lambda url, payload, org_id=None: (True, 1, 200, None))
    db = get_db()
    _add_chat(db, ctx["org"], "1010")  # only the first org has a chat
    old, new = _new_finding_pair()
    so, sn = "ti_old_" + _uid(), "ti_new_" + _uid()
    rid = _mk_repo(db, ctx["other"], sn, so)
    _mk_scan(db, ctx["other"], so, "done", old, vcs_repo_id=rid)
    _mk_scan(db, ctx["other"], sn, "done", new, vcs_repo_id=rid)
    db.close()

    out = vcs.evaluate_vcs_alerts(sn)
    assert out["alerted"] is True  # webhook still fires
    assert out["telegram"]["telegrammed"] is False
    assert out["telegram"]["reason"] == "no chats"
    assert FakeUrlopen.calls == []
    db = get_db()
    chans = {r["channel"] for r in db.execute(
        "SELECT channel FROM notifications WHERE scan_id=?", (sn,))}
    db.close()
    assert "telegram" not in chans
