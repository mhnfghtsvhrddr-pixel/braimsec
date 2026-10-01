"""Tests for HTTP(S) uptime monitoring.

- target validation
- probe logic against a faked http.client stack (no real network)
- CRUD endpoints: RBAC, validation, org isolation, audit
- down alert only after 2 consecutive failures (anti-flap); recovered alert
- anti-spam: no down re-alert inside the repeat window
- sweep honors per-target check intervals
- resend rebuilds monitor messages (cert + uptime) from the stored payload
"""
import http.client
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-uptime-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-uptime-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import uptime_monitor  # noqa: E402
import cert_monitor  # noqa: E402
import scheduler  # noqa: E402
import telegram_alerts  # noqa: E402
import email_alerts  # noqa: E402
import resend_alerts  # noqa: E402
from billing import (create_org, ensure_owner_org, provision_key,  # noqa: E402
                     seed_plans)
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = os.urandom(4).hex()
    org = create_org(f"UpCo_{uid}", plan="free")
    other = create_org(f"UpOther_{uid}", plan="free")
    member = provision_key(org, f"up-member-{uid}", actor="owner",
                           role="member")
    viewer = provision_key(org, f"up-viewer-{uid}", actor="owner",
                           role="viewer")
    o_member = provision_key(other, f"up-o-member-{uid}", actor="owner",
                             role="member")
    db = get_db()
    db.execute("INSERT INTO telegram_chats (org_id, chat_id, label,"
               " created_at) VALUES (?,?,?,?)",
               (org, "888000", "ops", "2026-10-02T00:00:00+00:00"))
    db.execute("INSERT INTO alert_emails (org_id, email, enabled,"
               " created_at) VALUES (?,?,1,?)",
               (org, f"ops-{uid}@example.com", "2026-10-02T00:00:00+00:00"))
    db.commit()
    db.close()
    return {"org": org, "other": other, "member": member, "viewer": viewer,
            "o_member": o_member, "uid": uid}


@pytest.fixture(autouse=True)
def _clean_uptime_state(ctx):
    yield
    db = get_db()
    db.execute("DELETE FROM notifications WHERE event LIKE 'uptime.%'")
    db.execute("DELETE FROM uptime_targets WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.commit()
    db.close()


def _h(key):
    return {"X-API-Key": key}


def _row(tid):
    db = get_db()
    r = dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                        (tid,)).fetchone())
    db.close()
    return r


def _notifs(org, event):
    db = get_db()
    rows = [dict(r) for r in db.execute(
        "SELECT * FROM notifications WHERE org_id=? AND event=?",
        (org, event)).fetchall()]
    db.close()
    return rows


# ------------------------------------------------------------ faked HTTP

class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, n=-1):
        return self._body


class _FakeConn:
    instances = []

    def __init__(self, host, port, timeout=None, status=200, body=b"ok",
                 boom=None):
        self.host, self.port = host, port
        self._status, self._body, self._boom = status, body, boom
        _FakeConn.instances.append(self)

    def request(self, method, path, headers=None):
        self.method, self.path = method, path
        if self._boom:
            raise self._boom

    def getresponse(self):
        if self._boom:
            raise self._boom
        return _FakeResp(self._status, self._body)

    def close(self):
        pass


@pytest.fixture()
def fake_http(monkeypatch):
    _FakeConn.instances.clear()
    monkeypatch.setattr(cert_monitor, "_public_ip_or_raise",
                        lambda host: "93.184.216.34")
    state = {"status": 200, "body": b"ok", "boom": None}

    def _conn(host, port, timeout=None):
        return _FakeConn(host, port, timeout, state["status"], state["body"],
                         state["boom"])

    monkeypatch.setattr(http.client, "HTTPSConnection", _conn)
    monkeypatch.setattr(http.client, "HTTPConnection", _conn)
    return state


def _target(**kw):
    base = {"hostname": "example.com", "port": 443, "path": "/",
            "use_https": 1, "expected_status": None, "keyword": ""}
    base.update(kw)
    return base


# ------------------------------------------------------------------ probe

def test_probe_up(fake_http):
    fake_http["body"] = b"welcome home"
    res = uptime_monitor.probe(_target(keyword="welcome"))
    assert res["ok"] and res["http_status"] == 200
    assert res["latency_ms"] is not None and res["latency_ms"] >= 0
    conn = _FakeConn.instances[-1]
    assert (conn.host, conn.port, conn.path) == ("example.com", 443, "/")


def test_probe_down_cases(fake_http):
    fake_http["status"] = 503
    assert not uptime_monitor.probe(_target())["ok"]

    fake_http["status"] = 200
    fake_http["body"] = b"hello"
    assert not uptime_monitor.probe(_target(keyword="missing"))["ok"]

    r = uptime_monitor.probe(_target(expected_status=201))
    assert not r["ok"] and "expected 201" in r["error"]

    fake_http["boom"] = ConnectionRefusedError("nope")
    r = uptime_monitor.probe(_target())
    assert not r["ok"] and "ConnectionRefusedError" in r["error"]


def test_probe_config_error_on_private_ip(monkeypatch):
    monkeypatch.setattr(cert_monitor, "_public_ip_or_raise",
                        lambda host: (_ for _ in ()).throw(
                            ValueError("refusing non-public address")))
    r = uptime_monitor.probe(_target())
    assert r["config_error"] is True and not r["ok"]


def test_validate_target():
    with pytest.raises(ValueError):
        uptime_monitor.validate_target("http://x.com", 443, "/", 300, None,
                                       "")
    with pytest.raises(ValueError):
        uptime_monitor.validate_target("example.com", 0, "/", 300, None, "")
    with pytest.raises(ValueError):
        uptime_monitor.validate_target("example.com", 443, "/", 10, None,
                                       "")
    with pytest.raises(ValueError):
        uptime_monitor.validate_target("example.com", 443, "/", 300, 99,
                                       "")
    with pytest.raises(ValueError):
        uptime_monitor.validate_target("example.com", 443, "/", 300, None,
                                       "k" * 201)
    h, p, path, iv = uptime_monitor.validate_target(
        "Example.COM", 8443, "health", 600, 200, "ok")
    assert (h, p, path, iv) == ("example.com", 8443, "/health", 600)


# ------------------------------------------------------------------- CRUD

def _probe_up(target):
    return {"ok": True, "http_status": 200, "latency_ms": 42, "error": None,
            "keyword_ok": True}


def test_crud_and_rbac(ctx, monkeypatch):
    c = TestClient(main.app)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_up)
    r = c.post("/api/uptime-targets",
               json={"hostname": "Example.COM.", "path": "/health",
                     "keyword": "ok",
                     "webhook_url": "https://hooks.x/up"},
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    t = r.json()
    assert t["hostname"] == "example.com" and t["path"] == "/health"
    assert t["_live"]["status"] == "up"
    tid = t["id"]

    r = c.post("/api/uptime-targets", json={"hostname": "b.example.com"},
               headers=_h(ctx["viewer"]))
    assert r.status_code == 403

    r = c.post("/api/uptime-targets", json={"hostname": "http://x.com"},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post("/api/uptime-targets",
               json={"hostname": "example.com", "path": "/health"},
               headers=_h(ctx["member"]))
    assert r.status_code == 400  # duplicate

    r = c.get("/api/uptime-targets", headers=_h(ctx["viewer"]))
    assert r.status_code == 200 and any(x["id"] == tid for x in r.json())
    r = c.get("/api/uptime-targets", headers=_h(ctx["o_member"]))
    assert r.status_code == 200 and r.json() == []
    r = c.patch(f"/api/uptime-targets/{tid}", json={"keyword": "up"},
                headers=_h(ctx["o_member"]))
    assert r.status_code == 404

    r = c.patch(f"/api/uptime-targets/{tid}",
                json={"keyword": "up!", "check_interval_s": 600,
                      "enabled": False},
                headers=_h(ctx["member"]))
    assert r.status_code == 200
    assert r.json()["keyword"] == "up!" and r.json()["enabled"] == 0
    r = c.patch(f"/api/uptime-targets/{tid}", json={},
                headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.patch(f"/api/uptime-targets/{tid}",
                json={"check_interval_s": 5}, headers=_h(ctx["member"]))
    assert r.status_code == 400

    db = get_db()
    acts = {x["action"] for x in db.execute(
        "SELECT action FROM audit_log WHERE org_id=?", (ctx["org"],))}
    db.close()
    assert {"uptime_target.added", "uptime_target.updated"} <= acts

    r = c.delete(f"/api/uptime-targets/{tid}", headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["deleted"] == tid
    r = c.delete(f"/api/uptime-targets/{tid}", headers=_h(ctx["member"]))
    assert r.status_code == 404


# ------------------------------------------------------------------ alerts

def _patch_senders(monkeypatch, calls):
    monkeypatch.setattr(scheduler, "send_alert",
                        lambda url, payload, org_id=None:
                        (calls.append(("webhook", url)) or
                         (True, 1, 200, None)))
    monkeypatch.setattr(telegram_alerts, "send_telegram",
                        lambda chat_id, text:
                        (calls.append(("telegram", chat_id, text)) or
                         (True, 1, None)))
    monkeypatch.setattr(email_alerts, "send_email",
                        lambda to, subj, txt, html=None:
                        (calls.append(("email", to, subj)) or (True, 1, None)))


def _probe_down(target):
    return {"ok": False, "http_status": 503, "latency_ms": 9000,
            "error": "HTTP 503", "keyword_ok": True}


def test_down_alert_after_two_failures(ctx, monkeypatch):
    c = TestClient(main.app)
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_down)

    r = c.post("/api/uptime-targets",
               json={"hostname": "down.example.com",
                     "webhook_url": "https://hooks.x/down"},
               headers=_h(ctx["member"]))
    tid = r.json()["id"]
    # first failure: recorded, no alert (anti-flap)
    assert r.json()["_live"]["status"] == "down"
    assert _row(tid)["consecutive_failures"] == 1
    assert _notifs(ctx["org"], "uptime.down") == []

    # second consecutive failure: alert fires on all configured channels
    c.post(f"/api/uptime-targets/{tid}/check", headers=_h(ctx["member"]))
    rows = _notifs(ctx["org"], "uptime.down")
    assert {x["channel"] for x in rows} == {"webhook", "telegram", "email"}
    assert all(x["status"] == "sent" for x in rows)
    assert all(x["severity"] == "critical" for x in rows)
    chans = {ch for ch, *_ in calls}
    assert {"webhook", "telegram", "email"} <= chans
    tg_text = [c[2] for c in calls if c[0] == "telegram"][0]
    assert "down.example.com" in tg_text and "503" in tg_text
    assert _row(tid)["last_alert_event"] == "uptime.down"

    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM audit_log WHERE org_id=?"
                   " AND action='uptime_target.down'",
                   (ctx["org"],)).fetchone()["c"]
    db.close()
    assert n == 1

    # third failure inside the repeat window: no new alert
    c.post(f"/api/uptime-targets/{tid}/check", headers=_h(ctx["member"]))
    assert len(_notifs(ctx["org"], "uptime.down")) == 3


def test_recovered_alert(ctx, monkeypatch):
    c = TestClient(main.app)
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_down)
    r = c.post("/api/uptime-targets", json={"hostname": "flap.example.com"},
               headers=_h(ctx["member"]))
    tid = r.json()["id"]
    c.post(f"/api/uptime-targets/{tid}/check", headers=_h(ctx["member"]))
    assert _notifs(ctx["org"], "uptime.down")

    # recovery -> recovered alert
    monkeypatch.setattr(uptime_monitor, "probe", _probe_up)
    r = c.post(f"/api/uptime-targets/{tid}/check", headers=_h(ctx["member"]))
    assert r.json()["_live"]["status"] == "up"
    rows = _notifs(ctx["org"], "uptime.recovered")
    assert {x["channel"] for x in rows} == {"telegram", "email"}
    assert all(x["severity"] == "info" for x in rows)
    tg_text = [c[2] for c in calls
               if c[0] == "telegram"][-1]
    assert "flap.example.com" in tg_text

    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM audit_log WHERE org_id=?"
                   " AND action='uptime_target.recovered'",
                   (ctx["org"],)).fetchone()["c"]
    db.close()
    assert n == 1


def test_single_flap_never_alerts(ctx, monkeypatch):
    c = TestClient(main.app)
    _patch_senders(monkeypatch, [])
    monkeypatch.setattr(uptime_monitor, "probe", _probe_down)
    r = c.post("/api/uptime-targets", json={"hostname": "blip.example.com"},
               headers=_h(ctx["member"]))
    tid = r.json()["id"]
    # one failure then immediate recovery: no down alert, so no recovered
    monkeypatch.setattr(uptime_monitor, "probe", _probe_up)
    c.post(f"/api/uptime-targets/{tid}/check", headers=_h(ctx["member"]))
    assert _notifs(ctx["org"], "uptime.down") == []
    assert _notifs(ctx["org"], "uptime.recovered") == []


def test_sweep_honors_interval(ctx, monkeypatch):
    c = TestClient(main.app)
    calls = []
    monkeypatch.setattr(uptime_monitor, "probe",
                        lambda t: calls.append(t["hostname"]) or _probe_up(t))
    r = c.post("/api/uptime-targets", json={"hostname": "s1.example.com"},
               headers=_h(ctx["member"]))
    tid = r.json()["id"]
    n_calls = len(calls)

    out = uptime_monitor.run_uptime_checks_once()
    assert out["checked"] == 0 and len(calls) == n_calls

    db = get_db()
    db.execute("UPDATE uptime_targets SET last_checked_at=?"
               " WHERE id=?", ("2020-01-01T00:00:00+00:00", tid))
    db.commit()
    db.close()
    out = uptime_monitor.run_uptime_checks_once()
    assert out["checked"] == 1 and len(calls) == n_calls + 1


def test_notifications_filter_uptime_events(ctx, monkeypatch):
    c = TestClient(main.app)
    _patch_senders(monkeypatch, [])
    monkeypatch.setattr(uptime_monitor, "probe", _probe_down)
    r = c.post("/api/uptime-targets", json={"hostname": "fil.example.com"},
               headers=_h(ctx["member"]))
    tid = r.json()["id"]
    c.post(f"/api/uptime-targets/{tid}/check", headers=_h(ctx["member"]))
    r = c.get("/api/notifications?event=uptime.down",
              headers=_h(ctx["member"]))
    assert r.status_code == 200 and len(r.json()) == 2
    r = c.get("/api/notifications?event=uptime.recovered",
              headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json() == []


# ------------------------------------------------------------------ resend

def _failed_notif(db, org, channel, event, payload, recipient="777000"):
    cur = db.execute(
        "INSERT INTO notifications (org_id, scan_id, event, severity,"
        " new_count, webhook_url, channel, recipient, status, attempts,"
        " response_code, error, payload, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (org, "cert:9", event, "high", 4, "", channel, recipient, "failed",
         1, 500, "boom", json.dumps(payload, ensure_ascii=False),
         "2026-10-02T00:00:00+00:00"))
    db.commit()
    return cur.lastrowid


def test_resend_rebuilds_monitor_text_from_payload(ctx, monkeypatch):
    c = TestClient(main.app)
    sent = []
    monkeypatch.setattr(telegram_alerts, "send_telegram",
                        lambda chat_id, text:
                        (sent.append((chat_id, text)) or (True, 1, None)))
    monkeypatch.setattr(email_alerts, "send_email",
                        lambda to, subj, txt, html=None:
                        (sent.append((to, subj)) or (True, 1, None)))
    db = get_db()
    nid = _failed_notif(db, ctx["org"], "telegram", "cert.expiry",
                        {"hostname": "soon.example.com", "port": 443,
                         "days_left": 4,
                         "expires_at": "2026-10-06T00:00:00+00:00"})
    nid_up = _failed_notif(db, ctx["org"], "email", "uptime.down",
                           {"hostname": "down.example.com", "port": 443,
                            "path": "/", "use_https": True,
                            "http_status": 503, "latency_ms": 9000,
                            "error": "HTTP 503", "failures": 2},
                           recipient="ops@example.com")
    db.close()

    r = c.post(f"/api/notifications/{nid}/resend",
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    assert sent[0][0] == "777000"
    assert "soon.example.com" in sent[0][1] and "4 يوم" in sent[0][1]

    r = c.post(f"/api/notifications/{nid_up}/resend",
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    assert sent[1][0] == "ops@example.com"
    assert "down.example.com" in sent[1][1]  # email subject
