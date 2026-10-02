"""Tests for public status pages + incident log.

- slug validation, page CRUD, org isolation, RBAC, audit
- public JSON/HTML: enabled only, read-only, no auth, no private data
- manual incident lifecycle: create/update/resolve/reopen/delete
- automatic incidents: down alert opens one incident per target
  (idempotent); recovered alert auto-resolves it
- daily aggregates + 90-day uptime bars in the public summary
- prune_daily drops rows older than the retention window
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-status-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-status-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import status_page  # noqa: E402
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
    org = create_org(f"StCo_{uid}", plan="free")
    other = create_org(f"StOther_{uid}", plan="free")
    member = provision_key(org, f"st-member-{uid}", actor="owner",
                           role="member")
    viewer = provision_key(org, f"st-viewer-{uid}", actor="owner",
                           role="viewer")
    o_member = provision_key(other, f"st-o-member-{uid}", actor="owner",
                             role="member")
    return {"org": org, "other": other, "member": member,
            "viewer": viewer, "o_member": o_member, "uid": uid}


@pytest.fixture(autouse=True)
def _clean_status_state(ctx):
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
    db.execute("DELETE FROM status_pages WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM cert_domains WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM uptime_targets WHERE org_id IN (?,?)",
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


def _probe_down(target):
    return {"ok": False, "http_status": 503, "latency_ms": 9000,
            "error": "HTTP 503", "keyword_ok": True}


def _probe_up(target):
    return {"ok": True, "http_status": 200, "latency_ms": 42,
            "error": None, "keyword_ok": True}


def _audit_actions(org):
    db = get_db()
    acts = {x["action"] for x in db.execute(
        "SELECT action FROM audit_log WHERE org_id=?", (org,))}
    db.close()
    return acts


# ------------------------------------------------------------- slug/pages

def test_slug_validation():
    assert status_page.validate_slug("acme-1") == "acme-1"
    assert status_page.validate_slug("ACME") == "acme"  # lowercased
    for bad in ["", "ab", "a c", "a/b", "-abc", "abc-",
                "x" * 61, "slug_1"]:
        with pytest.raises(ValueError):
            status_page.validate_slug(bad)


def test_page_crud_rbac_and_isolation(ctx):
    c = TestClient(main.app)
    r = c.post("/api/status-pages",
               json={"title": "حالة خدماتنا", "slug": "acme-st",
                     "headline": "نتابع هنا"},
               headers=_h(ctx["viewer"]))
    assert r.status_code == 403
    r = c.post("/api/status-pages",
               json={"title": "حالة خدماتنا", "slug": "BAD SLUG"},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post("/api/status-pages",
               json={"title": "", "slug": "acme-st"},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post("/api/status-pages",
               json={"title": "حالة خدماتنا", "slug": "acme-st",
                     "headline": "نتابع هنا"},
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["slug"] == "acme-st" and p["enabled"] == 1
    pid = p["id"]

    # duplicate slug, even from another org
    r = c.post("/api/status-pages",
               json={"title": "أخرى", "slug": "acme-st"},
               headers=_h(ctx["o_member"]))
    assert r.status_code == 400

    r = c.get("/api/status-pages", headers=_h(ctx["viewer"]))
    assert r.status_code == 200 and [x["id"] for x in r.json()] == [pid]
    r = c.get("/api/status-pages", headers=_h(ctx["o_member"]))
    assert r.json() == []

    r = c.patch(f"/api/status-pages/{pid}", json={"enabled": False},
                headers=_h(ctx["o_member"]))
    assert r.status_code == 404
    r = c.patch(f"/api/status-pages/{pid}",
                json={"title": "جديد", "enabled": False},
                headers=_h(ctx["member"]))
    assert r.status_code == 200
    assert r.json()["title"] == "جديد" and r.json()["enabled"] == 0
    r = c.patch(f"/api/status-pages/{pid}", json={},
                headers=_h(ctx["member"]))
    assert r.status_code == 400

    assert {"status_page.created", "status_page.updated"} <= \
        _audit_actions(ctx["org"])

    r = c.delete(f"/api/status-pages/{pid}", headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["deleted"] == pid
    r = c.delete(f"/api/status-pages/{pid}", headers=_h(ctx["member"]))
    assert r.status_code == 404


# -------------------------------------------------------------- incidents

def test_incident_lifecycle(ctx):
    c = TestClient(main.app)
    r = c.post("/api/incidents", json={"title": ""},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post("/api/incidents",
               json={"title": "خ", "status": "nope"},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post("/api/incidents",
               json={"title": "تعطل قاعدة البيانات", "status": "identified",
                     "impact": "major", "message": "الأساسية لا تستجيب"},
               headers=_h(ctx["viewer"]))
    assert r.status_code == 403
    r = c.post("/api/incidents",
               json={"title": "تعطل قاعدة البيانات", "status": "identified",
                     "impact": "major", "message": "الأساسية لا تستجيب"},
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    inc = r.json()
    assert inc["status"] == "identified" and inc["impact"] == "major"
    assert len(inc["updates"]) == 1
    iid = inc["id"]

    r = c.get(f"/api/incidents/{iid}", headers=_h(ctx["o_member"]))
    assert r.status_code == 404
    r = c.get(f"/api/incidents/{iid}", headers=_h(ctx["viewer"]))
    assert r.status_code == 200 and r.json()["id"] == iid

    r = c.post(f"/api/incidents/{iid}/updates", json={},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post(f"/api/incidents/{iid}/updates",
               json={"message": "تم التحويل للاحتياطية",
                     "status": "monitoring"},
               headers=_h(ctx["member"]))
    assert r.status_code == 200
    assert r.json()["status"] == "monitoring"
    assert len(r.json()["updates"]) == 2

    r = c.get("/api/incidents?status=open", headers=_h(ctx["member"]))
    assert r.status_code == 200 and any(x["id"] == iid for x in r.json())

    r = c.post(f"/api/incidents/{iid}/resolve",
               json={"message": "عاد كل شيء"},
               headers=_h(ctx["member"]))
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"
    assert r.json()["resolved_at"] is not None

    # idempotent re-resolve
    r = c.post(f"/api/incidents/{iid}/resolve", json={},
               headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["status"] == "resolved"

    # reopen via PATCH clears resolved_at
    r = c.patch(f"/api/incidents/{iid}", json={"status": "monitoring"},
                headers=_h(ctx["member"]))
    assert r.status_code == 200
    assert r.json()["status"] == "monitoring"
    assert r.json()["resolved_at"] is None

    assert {"incident.created", "incident.resolved",
            "incident_update.added"} <= _audit_actions(ctx["org"])

    r = c.delete(f"/api/incidents/{iid}", headers=_h(ctx["member"]))
    assert r.status_code == 200
    r = c.get(f"/api/incidents/{iid}", headers=_h(ctx["member"]))
    assert r.status_code == 404


# ------------------------------------------------------- automatic incidents

def test_auto_incident_on_down_and_recovery(ctx, monkeypatch):
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_down)
    db = get_db()
    t = uptime_monitor.add_target(db, ctx["org"], "auto.example.com")
    db.close()

    db = get_db()
    # first failure: no alert yet (anti-flap) -> no incident
    uptime_monitor.check_target(db, t)
    assert db.execute("SELECT COUNT(*) c FROM incidents WHERE org_id=?",
                      (ctx["org"],)).fetchone()["c"] == 0
    t = dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                        (t["id"],)).fetchone())
    # second failure: down alert -> one incident opens automatically
    uptime_monitor.check_target(db, t)
    incs = [dict(r) for r in db.execute(
        "SELECT * FROM incidents WHERE org_id=?", (ctx["org"],)).fetchall()]
    assert len(incs) == 1
    inc = incs[0]
    assert inc["target_id"] == t["id"]
    assert inc["status"] == "investigating"
    assert inc["impact"] == "critical"
    assert inc["created_by"] == "system"
    assert inc["public_visible"] == 1
    upd = db.execute("SELECT * FROM incident_updates WHERE incident_id=?",
                     (inc["id"],)).fetchall()
    assert len(upd) == 1 and "auto.example.com" in upd[0]["message"]
    # third failure (still down): no duplicate incident
    t = dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                        (t["id"],)).fetchone())
    db.execute("UPDATE uptime_targets SET last_alerted_at=NULL WHERE id=?",
               (t["id"],))
    db.commit()
    t = dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                        (t["id"],)).fetchone())
    uptime_monitor.check_target(db, t)
    n = db.execute("SELECT COUNT(*) c FROM incidents WHERE org_id=?",
                   (ctx["org"],)).fetchone()["c"]
    assert n == 1
    db.close()

    # recovery: incident auto-resolves with a closing update
    monkeypatch.setattr(uptime_monitor, "probe", _probe_up)
    db = get_db()
    t = dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                        (t["id"],)).fetchone())
    uptime_monitor.check_target(db, t)
    inc = dict(db.execute("SELECT * FROM incidents WHERE org_id=?",
                          (ctx["org"],)).fetchone())
    assert inc["status"] == "resolved" and inc["resolved_at"] is not None
    upd = db.execute("SELECT * FROM incident_updates WHERE incident_id=?"
                     " ORDER BY id", (inc["id"],)).fetchall()
    assert len(upd) == 2 and "system" == upd[-1]["created_by"]
    db.close()


# ------------------------------------------------------------ daily rollup

def test_daily_aggregate_and_public_summary(ctx, monkeypatch):
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_down)
    c = TestClient(main.app)
    r = c.post("/api/status-pages",
               json={"title": "حالة", "slug": "daily-st"},
               headers=_h(ctx["member"]))
    assert r.status_code == 200

    db = get_db()
    t = uptime_monitor.add_target(db, ctx["org"], "bars.example.com")
    db.close()
    db = get_db()
    uptime_monitor.check_target(db, t)
    t = dict(db.execute("SELECT * FROM uptime_targets WHERE id=?",
                        (t["id"],)).fetchone())
    uptime_monitor.check_target(db, t)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    row = db.execute("SELECT * FROM uptime_daily WHERE target_id=?"
                     " AND day=?", (t["id"], today)).fetchone()
    assert row is not None
    assert row["checks_down"] == 2 and row["checks_up"] == 0
    db.close()

    # public JSON: no auth, outage overall, 90-day bars present
    r = c.get("/api/status/daily-st")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["overall"] == "outage"
    assert len(data["targets"]) == 1
    tgt = data["targets"][0]
    assert len(tgt["history"]) == 90
    assert tgt["history"][-1]["uptime"] == 0.0
    assert tgt["uptime_90d"] == 0.0
    assert "id" not in tgt  # no internal ids leak
    assert len(data["incidents"]) == 1  # the auto incident is public
    assert data["incidents"][0]["status"] == "investigating"
    assert len(data["incidents"][0]["updates"]) == 1

    # unknown slug -> 404, disabled page -> 404
    assert c.get("/api/status/nope-st").status_code == 404
    r = c.get("/api/status-pages", headers=_h(ctx["member"]))
    pid = r.json()[0]["id"]
    c.patch(f"/api/status-pages/{pid}", json={"enabled": False},
            headers=_h(ctx["member"]))
    assert c.get("/api/status/daily-st").status_code == 404
    c.patch(f"/api/status-pages/{pid}", json={"enabled": True},
            headers=_h(ctx["member"]))

    # public HTML page renders, Arabic RTL, no auth
    r = c.get("/status/daily-st")
    assert r.status_code == 200
    assert 'dir="rtl"' in r.text and "حالة" in r.text
    assert "bars.example.com" in r.text
    assert c.get("/status/nope-st").status_code == 404


def test_public_summary_degraded_and_private_incidents(ctx, monkeypatch):
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(uptime_monitor, "probe", _probe_up)
    c = TestClient(main.app)
    c.post("/api/status-pages", json={"title": "حالة", "slug": "deg-st"},
           headers=_h(ctx["member"]))
    # up target -> operational ...
    db = get_db()
    t = uptime_monitor.add_target(db, ctx["org"], "fine.example.com")
    db.close()
    db = get_db()
    uptime_monitor.check_target(db, t)
    db.close()
    r = c.get("/api/status/deg-st")
    assert r.json()["overall"] == "operational"
    assert r.json()["targets"][0]["uptime_90d"] == 1.0

    # ... until a manual open incident degrades it; private ones stay hidden
    c.post("/api/incidents",
           json={"title": "صيانة مخططة", "impact": "minor",
                 "public_visible": False},
           headers=_h(ctx["member"]))
    r = c.get("/api/status/deg-st")
    assert r.json()["overall"] == "operational"
    assert r.json()["incidents"] == []
    c.post("/api/incidents",
           json={"title": "تدهور جزئي", "impact": "major"},
           headers=_h(ctx["member"]))
    r = c.get("/api/status/deg-st")
    assert r.json()["overall"] == "degraded"
    assert len(r.json()["incidents"]) == 1


def test_prune_daily():
    db = get_db()
    old = (datetime.now(timezone.utc) - timedelta(days=200)).strftime("%Y-%m-%d")
    db.execute("INSERT INTO uptime_daily (target_id, day, checks_up)"
               " VALUES (?,?,?)", (424242, old, 5))
    db.commit()
    status_page.prune_daily(db)
    assert db.execute("SELECT COUNT(*) c FROM uptime_daily"
                      " WHERE target_id=424242").fetchone()["c"] == 0
    db.close()


def test_delete_target_cleans_daily(ctx):
    c = TestClient(main.app)
    db = get_db()
    t = uptime_monitor.add_target(db, ctx["org"], "gone.example.com")
    status_page.record_check(db, t["id"], "up", 10)
    db.close()
    r = c.delete(f"/api/uptime-targets/{t['id']}",
                 headers=_h(ctx["member"]))
    assert r.status_code == 200
    db = get_db()
    assert db.execute("SELECT COUNT(*) c FROM uptime_daily"
                      " WHERE target_id=?", (t["id"],)).fetchone()["c"] == 0
    db.close()


# -------------------------------------------------- certificates on status

def _add_cert(org, hostname, days_left, status, enabled=1):
    db = get_db()
    db.execute(
        "INSERT INTO cert_domains (org_id, hostname, port, warn_days,"
        " enabled, last_checked_at, last_expires_at, last_days_left,"
        " last_status, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (org, hostname, 443, 14, enabled,
         "2026-10-02T00:00:00+00:00",
         "2026-12-31T00:00:00+00:00" if days_left and days_left > 0 else None,
         days_left, status, "2026-10-02T00:00:00+00:00"))
    db.commit()
    db.close()


def test_public_summary_certificates(ctx):
    c = TestClient(main.app)
    c.post("/api/status-pages", json={"title": "حالة", "slug": "cert-st"},
           headers=_h(ctx["member"]))
    _add_cert(ctx["org"], "good.example.com", 90, "ok")
    _add_cert(ctx["org"], "soon.example.com", 5, "expiring")

    r = c.get("/api/status/cert-st")
    assert r.status_code == 200, r.text
    data = r.json()
    certs = data["certificates"]
    assert len(certs) == 2
    by_host = {x["hostname"]: x for x in certs}
    assert by_host["good.example.com"]["last_days_left"] == 90
    assert by_host["soon.example.com"]["last_status"] == "expiring"
    # no internal ids leak
    assert all("id" not in x for x in certs)
    # an expiring (not yet expired) cert is informational only
    assert data["overall"] == "operational"

    # an expired certificate counts as an outage
    _add_cert(ctx["org"], "dead.example.com", 0, "expiring")
    r = c.get("/api/status/cert-st")
    assert r.json()["overall"] == "outage"

    # disabled domains are hidden
    _add_cert(ctx["org"], "hidden.example.com", 90, "ok", enabled=0)
    r = c.get("/api/status/cert-st")
    assert len(r.json()["certificates"]) == 3

    # HTML renders the certificate states
    r = c.get("/status/cert-st")
    assert r.status_code == 200
    assert "🔒 شهادات TLS" in r.text
    assert "good.example.com" in r.text
    assert "منتهية" in r.text
