"""Tests for scheduled maintenance windows.

- derived status from the clock (scheduled/active/completed/cancelled)
- CRUD: validation, RBAC, org isolation, audit
- down-alert suppression while a window is active (logged as
  'suppressed', never sent, no auto-incident); silent recovery;
  real alert + incident once the window is cancelled
- scoped windows cover only their targets
- public status summary lists active/upcoming windows
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-maint-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-maint-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import maintenance  # noqa: E402
import uptime_monitor  # noqa: E402
import scheduler  # noqa: E402
import telegram_alerts  # noqa: E402
import email_alerts  # noqa: E402
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
    org = create_org(f"MnCo_{uid}", plan="free")
    other = create_org(f"MnOther_{uid}", plan="free")
    member = provision_key(org, f"mn-member-{uid}", actor="owner",
                           role="member")
    viewer = provision_key(org, f"mn-viewer-{uid}", actor="owner",
                           role="viewer")
    o_member = provision_key(other, f"mn-o-member-{uid}", actor="owner",
                             role="member")
    db = get_db()
    db.execute("INSERT INTO telegram_chats (org_id, chat_id, label,"
               " created_at) VALUES (?,?,?,?)",
               (org, "777001", "ops", "2026-10-02T00:00:00+00:00"))
    db.execute("INSERT INTO alert_emails (org_id, email, enabled,"
               " created_at) VALUES (?,?,1,?)",
               (org, f"ops-{uid}@example.com", "2026-10-02T00:00:00+00:00"))
    db.commit()
    db.close()
    return {"org": org, "other": other, "member": member,
            "viewer": viewer, "o_member": o_member, "uid": uid}


@pytest.fixture(autouse=True)
def _clean_maint_state(ctx):
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
    db.execute("DELETE FROM telegram_chats WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM alert_emails WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM status_pages WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM uptime_targets WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.commit()
    db.close()


def _h(key):
    return {"X-API-Key": key}


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _window(start_delta_h, end_delta_h):
    now = datetime.now(timezone.utc)
    return {"title": "ترقية", "description": "صيانة دورية",
            "starts_at": _iso(now + timedelta(hours=start_delta_h)),
            "ends_at": _iso(now + timedelta(hours=end_delta_h)),
            "target_ids": []}


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


def _probe_up(target):
    return {"ok": True, "http_status": 200, "latency_ms": 42,
            "error": None, "keyword_ok": True}


def _refresh(tid):
    db = get_db()
    r = dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                        (tid,)).fetchone())
    db.close()
    return r


# ------------------------------------------------------------ derived status

def test_derived_status():
    now = datetime.now(timezone.utc)
    mk = lambda s, e, st="scheduled": {"starts_at": _iso(s),
                                      "ends_at": _iso(e), "status": st}
    assert maintenance.derived_status(
        mk(now + timedelta(hours=1), now + timedelta(hours=2))) == "scheduled"
    assert maintenance.derived_status(
        mk(now - timedelta(hours=1), now + timedelta(hours=1))) == "active"
    assert maintenance.derived_status(
        mk(now - timedelta(hours=2), now - timedelta(hours=1))) == "completed"
    assert maintenance.derived_status(
        mk(now - timedelta(hours=1), now + timedelta(hours=1),
           "cancelled")) == "cancelled"


# --------------------------------------------------------------------- CRUD

def test_window_crud_validation_rbac(ctx):
    c = TestClient(main.app)
    r = c.post("/api/maintenance", json=_window(1, 3),
               headers=_h(ctx["viewer"]))
    assert r.status_code == 403
    bad = _window(3, 1)
    r = c.post("/api/maintenance", json=bad, headers=_h(ctx["member"]))
    assert r.status_code == 400  # ends before starts
    bad = _window(1, 24 * 31)
    r = c.post("/api/maintenance", json=bad, headers=_h(ctx["member"]))
    assert r.status_code == 400  # too long
    bad = _window(1, 3)
    bad["target_ids"] = [999999]
    r = c.post("/api/maintenance", json=bad, headers=_h(ctx["member"]))
    assert r.status_code == 400  # unknown target
    bad = _window(1, 3)
    bad["title"] = ""
    r = c.post("/api/maintenance", json=bad, headers=_h(ctx["member"]))
    assert r.status_code == 400

    r = c.post("/api/maintenance", json=_window(1, 3),
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    w = r.json()
    assert w["status"] == "scheduled" and w["target_ids"] == []
    wid = w["id"]

    r = c.get("/api/maintenance", headers=_h(ctx["viewer"]))
    assert r.status_code == 200 and [x["id"] for x in r.json()] == [wid]
    r = c.get("/api/maintenance", headers=_h(ctx["o_member"]))
    assert r.json() == []
    r = c.get(f"/api/maintenance/{wid}", headers=_h(ctx["o_member"]))
    assert r.status_code == 404

    # edit while scheduled: ok
    r = c.patch(f"/api/maintenance/{wid}", json={"title": "ترقية DB"},
                headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["title"] == "ترقية DB"
    r = c.patch(f"/api/maintenance/{wid}", json={},
                headers=_h(ctx["member"]))
    assert r.status_code == 400

    db = get_db()
    acts = {x["action"] for x in db.execute(
        "SELECT action FROM audit_log WHERE org_id=?", (ctx["org"],))}
    db.close()
    assert {"maintenance.created", "maintenance.updated"} <= acts

    # cancel
    r = c.post(f"/api/maintenance/{wid}/cancel",
               headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    r = c.post(f"/api/maintenance/{wid}/cancel",
               headers=_h(ctx["member"]))
    assert r.status_code == 400  # already cancelled
    # cannot edit a cancelled window
    r = c.patch(f"/api/maintenance/{wid}", json={"title": "x"},
                headers=_h(ctx["member"]))
    assert r.status_code == 400

    r = c.delete(f"/api/maintenance/{wid}", headers=_h(ctx["member"]))
    assert r.status_code == 200
    r = c.get(f"/api/maintenance/{wid}", headers=_h(ctx["member"]))
    assert r.status_code == 404


def test_cannot_edit_active_window(ctx):
    c = TestClient(main.app)
    r = c.post("/api/maintenance", json=_window(-1, 2),
               headers=_h(ctx["member"]))
    wid = r.json()["id"]
    assert r.json()["status"] == "active"
    r = c.patch(f"/api/maintenance/{wid}", json={"title": "x"},
                headers=_h(ctx["member"]))
    assert r.status_code == 400


# --------------------------------------------------------------- suppression

def _notifs(org, event, status=None):
    db = get_db()
    q = ("SELECT * FROM notifications WHERE org_id=? AND event=?")
    args = [org, event]
    if status:
        q += " AND status=?"
        args.append(status)
    rows = [dict(r) for r in db.execute(q, args).fetchall()]
    db.close()
    return rows


def _incidents(org):
    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM incidents WHERE org_id=?",
                   (org,)).fetchone()["c"]
    db.close()
    return n


def test_down_suppressed_during_maintenance(ctx, monkeypatch):
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_down)
    c = TestClient(main.app)

    db = get_db()
    t = uptime_monitor.add_target(db, ctx["org"], "mnt.example.com")
    db.close()
    r = c.post("/api/maintenance", json=_window(-1, 2),
               headers=_h(ctx["member"]))
    assert r.status_code == 200
    wid = r.json()["id"]

    t = _refresh(t["id"])
    db = get_db()
    uptime_monitor.check_target(db, t)  # failure 1: no alert
    db.close()
    db = get_db()
    t = dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                        (t["id"],)).fetchone())
    db.close()
    db = get_db()
    uptime_monitor.check_target(db, t)  # failure 2: suppressed
    db.close()

    supp = _notifs(ctx["org"], "uptime.down", "suppressed")
    assert len(supp) == 1
    assert supp[0]["channel"] == "maintenance"
    assert _notifs(ctx["org"], "uptime.down") == supp  # nothing was sent
    assert calls == []
    assert _incidents(ctx["org"]) == 0
    db = get_db()
    acts = {x["action"] for x in db.execute(
        "SELECT action FROM audit_log WHERE org_id=?", (ctx["org"],))}
    db.close()
    assert "maintenance.alert_suppressed" in acts

    # recovery during maintenance: silent (no recovered fan-out)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_up)
    db = get_db()
    uptime_monitor.check_target(db, _refresh(t["id"]))
    db.close()
    assert _notifs(ctx["org"], "uptime.recovered") == []

    # cancel the window: the next outage alerts for real + opens incident
    r = c.post(f"/api/maintenance/{wid}/cancel",
               headers=_h(ctx["member"]))
    assert r.status_code == 200
    monkeypatch.setattr(uptime_monitor, "probe", _probe_down)
    db = get_db()
    db.execute("UPDATE uptime_targets SET last_alerted_at=NULL,"
               " last_alert_event=NULL, consecutive_failures=0,"
               " last_status='never' WHERE id=?", (t["id"],))
    db.commit()
    db.close()
    db = get_db()
    uptime_monitor.check_target(db, _refresh(t["id"]))
    db.close()
    db = get_db()
    uptime_monitor.check_target(db, _refresh(t["id"]))
    db.close()
    real = [n for n in _notifs(ctx["org"], "uptime.down")
            if n["status"] != "suppressed"]
    assert {n["channel"] for n in real} == {"telegram", "email"}
    assert all(n["status"] == "sent" for n in real)
    assert calls != []
    assert _incidents(ctx["org"]) == 1


def test_scoped_window_only_covers_its_targets(ctx, monkeypatch):
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_down)
    c = TestClient(main.app)
    db = get_db()
    a = uptime_monitor.add_target(db, ctx["org"], "a.example.com")
    b = uptime_monitor.add_target(db, ctx["org"], "b.example.com")
    db.close()
    w = _window(-1, 2)
    w["target_ids"] = [a["id"]]
    r = c.post("/api/maintenance", json=w, headers=_h(ctx["member"]))
    assert r.status_code == 200

    for tgt in (a, b):
        db = get_db()
        uptime_monitor.check_target(db, _refresh(tgt["id"]))
        db.close()
    for tgt in (a, b):
        db = get_db()
        uptime_monitor.check_target(db, _refresh(tgt["id"]))
        db.close()
    supp = _notifs(ctx["org"], "uptime.down", "suppressed")
    assert len(supp) == 1  # only target a suppressed
    assert _incidents(ctx["org"]) == 1  # target b opened an incident


# ------------------------------------------------------------ public listing

def test_public_summary_lists_maintenance(ctx):
    c = TestClient(main.app)
    c.post("/api/status-pages", json={"title": "حالة", "slug": "mnt-st"},
           headers=_h(ctx["member"]))
    c.post("/api/maintenance", json=_window(2, 4),
           headers=_h(ctx["member"]))
    c.post("/api/maintenance", json=_window(-1, 2),
           headers=_h(ctx["member"]))
    r = c.get("/api/status/mnt-st")
    assert r.status_code == 200, r.text
    mnt = r.json()["maintenance"]
    assert len(mnt) == 2
    assert {m["status"] for m in mnt} == {"scheduled", "active"}
    assert all("target_ids" not in m for m in mnt)  # no internals leak
    r = c.get("/status/mnt-st")
    assert r.status_code == 200 and "🛠️ صيانة مجدولة" in r.text
