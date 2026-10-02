"""Tests for latency-degradation alerts (uptime.slow / uptime.fast).

- threshold validation (100..120000 ms, null clears)
- POST/PATCH wiring, RBAC
- uptime.slow fires on a slow-but-successful probe (warning), with
  anti-spam repeat window; uptime.fast on the first probe back under
- no alerts without a threshold; no incident auto-opens for slowness
- suppression during maintenance windows; silent fast after suppressed slow
- resend rebuilds the slow/fast messages from the stored payload
"""
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-latency-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-latency-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import uptime_monitor  # noqa: E402
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
    org = create_org(f"LtCo_{uid}", plan="free")
    other = create_org(f"LtOther_{uid}", plan="free")
    member = provision_key(org, f"lt-member-{uid}", actor="owner",
                           role="member")
    viewer = provision_key(org, f"lt-viewer-{uid}", actor="owner",
                           role="viewer")
    o_member = provision_key(other, f"lt-o-member-{uid}", actor="owner",
                             role="member")
    db = get_db()
    db.execute("INSERT INTO telegram_chats (org_id, chat_id, label,"
               " created_at) VALUES (?,?,?,?)",
               (org, "666001", "ops", "2026-10-02T00:00:00+00:00"))
    db.execute("INSERT INTO alert_emails (org_id, email, enabled,"
               " created_at) VALUES (?,?,1,?)",
               (org, f"ops-{uid}@example.com", "2026-10-02T00:00:00+00:00"))
    db.commit()
    db.close()
    return {"org": org, "other": other, "member": member,
            "viewer": viewer, "o_member": o_member, "uid": uid}


@pytest.fixture(autouse=True)
def _clean_latency_state(ctx):
    yield
    db = get_db()
    db.execute("DELETE FROM notifications WHERE event LIKE 'uptime.%'")
    db.execute("DELETE FROM uptime_daily WHERE target_id IN "
               "(SELECT id FROM uptime_targets WHERE org_id IN (?,?))",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM incident_updates WHERE incident_id IN "
               "(SELECT id FROM incidents WHERE org_id IN (?,?))",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM incidents WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM maintenance_windows WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM uptime_targets WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM telegram_chats WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM alert_emails WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.commit()
    db.close()


def _h(key):
    return {"X-API-Key": key}


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


def _probe_with_latency(ms):
    def _p(target):
        return {"ok": True, "http_status": 200, "latency_ms": ms,
                "error": None, "keyword_ok": True}
    return _p


def _notifs(org, event):
    db = get_db()
    rows = [dict(r) for r in db.execute(
        "SELECT * FROM notifications WHERE org_id=? AND event=?",
        (org, event)).fetchall()]
    db.close()
    return rows


def _refresh(tid):
    db = get_db()
    r = dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                        (tid,)).fetchone())
    db.close()
    return r


def _check(db, tid):
    uptime_monitor.check_target(db, _refresh(tid))


# -------------------------------------------------------------- validation

def test_validate_latency_warn_ms():
    assert uptime_monitor.validate_latency_warn_ms(None) is None
    assert uptime_monitor.validate_latency_warn_ms(100) == 100
    assert uptime_monitor.validate_latency_warn_ms(120000) == 120000
    for bad in (99, 120001, 0, -5):
        with pytest.raises(ValueError):
            uptime_monitor.validate_latency_warn_ms(bad)


def test_threshold_crud(ctx):
    c = TestClient(main.app)
    r = c.post("/api/uptime-targets",
               json={"hostname": "lat.example.com",
                     "latency_warn_ms": 50},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post("/api/uptime-targets",
               json={"hostname": "lat.example.com",
                     "latency_warn_ms": 2000},
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    tid = r.json()["id"]
    assert r.json()["latency_warn_ms"] == 2000

    r = c.patch(f"/api/uptime-targets/{tid}",
                json={"latency_warn_ms": 10},
                headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.patch(f"/api/uptime-targets/{tid}",
                json={"latency_warn_ms": 5000},
                headers=_h(ctx["viewer"]))
    assert r.status_code == 403
    r = c.patch(f"/api/uptime-targets/{tid}",
                json={"latency_warn_ms": 5000},
                headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["latency_warn_ms"] == 5000
    # null clears the threshold
    r = c.patch(f"/api/uptime-targets/{tid}",
                json={"latency_warn_ms": None},
                headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["latency_warn_ms"] is None
    # other org cannot touch it
    r = c.patch(f"/api/uptime-targets/{tid}",
                json={"latency_warn_ms": 1000},
                headers=_h(ctx["o_member"]))
    assert r.status_code == 404


# ------------------------------------------------------------------ alerts

def test_slow_and_fast_alerts(ctx, monkeypatch):
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_with_latency(5000))
    db = get_db()
    t = uptime_monitor.add_target(db, ctx["org"], "slow.example.com",
                                  latency_warn_ms=1000)
    db.close()

    db = get_db()
    _check(db, t["id"])
    db.close()
    slow = _notifs(ctx["org"], "uptime.slow")
    assert len(slow) == 2  # telegram + email
    assert all(n["severity"] == "warning" for n in slow)
    assert all(n["status"] == "sent" for n in slow)
    assert "5000" in slow[0]["payload"]  # latency in stored payload
    # slowness never opens an incident
    db = get_db()
    assert db.execute("SELECT COUNT(*) c FROM incidents WHERE org_id=?",
                      (ctx["org"],)).fetchone()["c"] == 0
    db.close()
    # audit trail
    db = get_db()
    acts = {x["action"] for x in db.execute(
        "SELECT action FROM audit_log WHERE org_id=?", (ctx["org"],))}
    db.close()
    assert "uptime_target.slow" in acts

    # still slow: no re-alert inside the repeat window
    db = get_db()
    _check(db, t["id"])
    db.close()
    assert len(_notifs(ctx["org"], "uptime.slow")) == 2

    # back under the threshold: uptime.fast (info), once
    monkeypatch.setattr(uptime_monitor, "probe", _probe_with_latency(120))
    db = get_db()
    _check(db, t["id"])
    db.close()
    fast = _notifs(ctx["org"], "uptime.fast")
    assert len(fast) == 2 and all(n["severity"] == "info" for n in fast)
    db = get_db()
    _check(db, t["id"])
    db.close()
    assert len(_notifs(ctx["org"], "uptime.fast")) == 2


def test_no_threshold_no_slow_alert(ctx, monkeypatch):
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_with_latency(30000))
    db = get_db()
    t = uptime_monitor.add_target(db, ctx["org"], "nothr.example.com")
    db.close()
    db = get_db()
    _check(db, t["id"])
    db.close()
    assert _notifs(ctx["org"], "uptime.slow") == []
    assert _notifs(ctx["org"], "uptime.fast") == []


def test_slow_suppressed_during_maintenance(ctx, monkeypatch):
    from datetime import datetime, timedelta, timezone  # noqa: E402
    import maintenance  # noqa: E402
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_with_latency(8000))
    db = get_db()
    t = uptime_monitor.add_target(db, ctx["org"], "mslow.example.com",
                                  latency_warn_ms=1000)
    now = datetime.now(timezone.utc)
    maintenance.create_window(
        db, ctx["org"], "صيانة",
        (now - timedelta(hours=1)).isoformat(timespec="seconds"),
        (now + timedelta(hours=1)).isoformat(timespec="seconds"))
    db.close()

    db = get_db()
    _check(db, t["id"])
    db.close()
    supp = [n for n in _notifs(ctx["org"], "uptime.slow")
            if n["status"] == "suppressed"]
    assert len(supp) == 1 and supp[0]["channel"] == "maintenance"
    assert calls == []

    # fast after a suppressed slow stays silent
    monkeypatch.setattr(uptime_monitor, "probe", _probe_with_latency(100))
    db = get_db()
    _check(db, t["id"])
    db.close()
    assert _notifs(ctx["org"], "uptime.fast") == []


def test_resend_rebuilds_slow_message(ctx, monkeypatch):
    import json  # noqa: E402
    sent = []
    monkeypatch.setattr(telegram_alerts, "send_telegram",
                        lambda chat_id, text:
                        (sent.append((chat_id, text)) or (True, 1, None)))
    db = get_db()
    payload = {"event": "uptime.slow", "hostname": "rs.example.com",
               "port": 443, "path": "/", "use_https": True,
               "http_status": 200, "latency_ms": 7000,
               "threshold_ms": 1000, "error": None, "failures": 0}
    cur = db.execute(
        "INSERT INTO notifications (org_id, scan_id, event, severity,"
        " new_count, webhook_url, channel, recipient, status, attempts,"
        " response_code, error, payload, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ctx["org"], "uptime:9", "uptime.slow", "warning", 0, "",
         "telegram", "666001", "failed", 1, 500, "boom",
         json.dumps(payload, ensure_ascii=False),
         "2026-10-02T00:00:00+00:00"))
    nid = cur.lastrowid
    db.commit()
    db.close()
    c = TestClient(main.app)
    r = c.post(f"/api/notifications/{nid}/resend",
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    assert sent[0][0] == "666001"
    assert "rs.example.com" in sent[0][1] and "7000" in sent[0][1]
