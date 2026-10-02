"""Tests for the scheduled uptime digest.

- config validation + CRUD + RBAC + org isolation + audit
- digest_due: weekly/monthly clock logic, no double-send in one period
- build_digest: uptime % / avg latency from uptime_daily, incidents,
  expiring certs
- send_digest: mocked SMTP, no-recipients skip, SMTP-unconfigured skip
- run_digests_once: only due configs send, last_sent_at advances
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-digest-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-digest-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import uptime_digest as dg  # noqa: E402
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
    org = create_org(f"DgCo_{uid}", plan="free")
    other = create_org(f"DgOther_{uid}", plan="free")
    member = provision_key(org, f"dg-member-{uid}", actor="owner",
                           role="member")
    viewer = provision_key(org, f"dg-viewer-{uid}", actor="owner",
                           role="viewer")
    o_member = provision_key(other, f"dg-o-member-{uid}", actor="owner",
                             role="member")
    db = get_db()
    db.execute("INSERT INTO alert_emails (org_id, email, enabled,"
               " created_at) VALUES (?,?,1,?)",
               (org, f"ops-{uid}@example.com", "2026-10-02T00:00:00+00:00"))
    db.commit()
    db.close()
    return {"org": org, "other": other, "member": member,
            "viewer": viewer, "o_member": o_member, "uid": uid}


@pytest.fixture(autouse=True)
def _clean_digest_state(ctx):
    yield
    db = get_db()
    db.execute("DELETE FROM uptime_digests WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM uptime_daily WHERE target_id IN "
               "(SELECT id FROM uptime_targets WHERE org_id IN (?,?))",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM incident_updates WHERE incident_id IN "
               "(SELECT id FROM incidents WHERE org_id IN (?,?))",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM incidents WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM cert_domains WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM uptime_targets WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.execute("DELETE FROM alert_emails WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.commit()
    db.close()


def _h(key):
    return {"X-API-Key": key}


def _cfg(**kw):
    base = {"org_id": "x", "enabled": 1, "frequency": "weekly",
            "day_of_week": 0, "day_of_month": 1, "hour": 8,
            "last_sent_at": None}
    base.update(kw)
    return base


# -------------------------------------------------------------- validation

def test_validate_config():
    c = dg.validate_config("weekly", 0, 99, 8)
    assert c == {"frequency": "weekly", "day_of_week": 0,
                 "day_of_month": 1, "hour": 8}
    c = dg.validate_config("monthly", 3, 15, 23)
    assert c["day_of_month"] == 15 and c["day_of_week"] == 0
    for bad in [("daily", 0, 1, 8), ("weekly", 7, 1, 8),
                ("weekly", 0, 1, 24), ("monthly", 0, 29, 8),
                ("monthly", 0, 0, 8)]:
        with pytest.raises(ValueError):
            dg.validate_config(*bad)


def test_config_crud_rbac(ctx):
    c = TestClient(main.app)
    r = c.get("/api/uptime-digest/config", headers=_h(ctx["viewer"]))
    assert r.status_code == 200 and r.json()["enabled"] == 0  # defaults

    r = c.put("/api/uptime-digest/config",
              json={"enabled": True, "frequency": "weekly",
                    "day_of_week": 0, "hour": 8},
              headers=_h(ctx["viewer"]))
    assert r.status_code == 403
    r = c.put("/api/uptime-digest/config",
              json={"enabled": True, "frequency": "daily"},
              headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.put("/api/uptime-digest/config",
              json={"enabled": True, "frequency": "weekly",
                    "day_of_week": 0, "hour": 8},
              headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    assert r.json()["frequency"] == "weekly"

    r = c.get("/api/uptime-digest/config", headers=_h(ctx["o_member"]))
    assert r.json()["enabled"] == 0  # org isolation: other's defaults

    db = get_db()
    acts = {x["action"] for x in db.execute(
        "SELECT action FROM audit_log WHERE org_id=?", (ctx["org"],))}
    db.close()
    assert "uptime_digest.configured" in acts


# -------------------------------------------------------------------- due

def test_digest_due_weekly():
    # Monday 2026-10-05 09:00 UTC
    now = datetime(2026, 10, 5, 9, 0, tzinfo=timezone.utc)
    assert dg.digest_due(_cfg(), now) is True
    assert dg.digest_due(_cfg(hour=10), now) is False  # hour not reached
    assert dg.digest_due(_cfg(day_of_week=1), now) is False  # Tuesday
    assert dg.digest_due(_cfg(enabled=0), now) is False
    # sent 2 days ago: still inside the weekly period -> not due
    sent = (now - timedelta(days=2)).isoformat()
    assert dg.digest_due(_cfg(last_sent_at=sent), now) is False
    # sent 8 days ago: new period -> due
    sent = (now - timedelta(days=8)).isoformat()
    assert dg.digest_due(_cfg(last_sent_at=sent), now) is True


def test_digest_due_monthly():
    now = datetime(2026, 10, 15, 9, 0, tzinfo=timezone.utc)
    cfg = _cfg(frequency="monthly", day_of_month=15, hour=8)
    assert dg.digest_due(cfg, now) is True
    assert dg.digest_due(_cfg(frequency="monthly", day_of_month=16,
                              hour=8), now) is False
    sent = (now - timedelta(days=10)).isoformat()
    assert dg.digest_due(_cfg(frequency="monthly", day_of_month=15,
                              hour=8, last_sent_at=sent), now) is False


# ------------------------------------------------------------------- build

def _seed_daily(org):
    db = get_db()
    cur = db.execute(
        "INSERT INTO uptime_targets (org_id, hostname, port, path,"
        " use_https, enabled, last_status, created_at)"
        " VALUES (?,?,?,?,'1',1,'up',?)",
        (org, "d.example.com", 443, "/", "2026-10-02T00:00:00+00:00"))
    tid = cur.lastrowid
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    db.execute("INSERT INTO uptime_daily (target_id, day, checks_up,"
               " checks_down, latency_sum_ms, latency_n)"
               " VALUES (?,?,?,?,?,?)",
               (tid, today, 90, 10, 9000, 90))
    db.execute("INSERT INTO incidents (org_id, title, status, impact,"
               " public_visible, started_at, created_at)"
               " VALUES (?,?,?,?,?,?,?)",
               (org, "حادث", "resolved", "minor", 1,
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "2026-10-02T00:00:00+00:00"))
    db.execute("INSERT INTO cert_domains (org_id, hostname, warn_days,"
               " enabled, last_days_left, last_status, created_at)"
               " VALUES (?,?,?,?,?,?,?)",
               (org, "d.example.com", 14, 1, 3, "expiring",
                "2026-10-02T00:00:00+00:00"))
    db.commit()
    db.close()


def test_build_digest(ctx):
    _seed_daily(ctx["org"])
    db = get_db()
    d = dg.build_digest(db, ctx["org"], days=7)
    db.close()
    assert d["days"] == 7
    assert len(d["targets"]) == 1
    t = d["targets"][0]
    assert t["uptime_pct"] == 90.0
    assert t["avg_latency_ms"] == 100
    assert t["checks"] == 100 and t["down_checks"] == 10
    assert len(d["incidents"]) == 1
    assert len(d["certs_expiring"]) == 1
    subject, text, html = dg.digest_texts(d, "DgCo")
    assert "d.example.com" in text and "90.0%" in text
    assert "d.example.com" in html and "dir=\"rtl\"" in html
    with pytest.raises(ValueError):
        dg.build_digest(get_db(), ctx["org"], days=91)


def test_preview_endpoint(ctx):
    c = TestClient(main.app)
    _seed_daily(ctx["org"])
    r = c.get("/api/uptime-digest/preview?days=7",
              headers=_h(ctx["viewer"]))
    assert r.status_code == 200 and len(r.json()["targets"]) == 1
    r = c.get("/api/uptime-digest/preview?days=91",
              headers=_h(ctx["viewer"]))
    assert r.status_code == 400


# -------------------------------------------------------------------- send

def test_send_digest_mocked_smtp(ctx, monkeypatch):
    sent = []
    monkeypatch.setattr(email_alerts, "send_email",
                        lambda to, subj, txt, html=None:
                        (sent.append((to, subj)) or (True, 1, None)))
    _seed_daily(ctx["org"])
    db = get_db()
    res = dg.send_digest(db, ctx["org"], days=7, actor="tester")
    db.close()
    assert res == {"sent": 1, "total": 1, "skipped": False, "error": None}
    assert "d.example.com" in sent[0][1] or "الجهوزية" in sent[0][1]
    db = get_db()
    acts = {x["action"] for x in db.execute(
        "SELECT action FROM audit_log WHERE org_id=?", (ctx["org"],))}
    db.close()
    assert "uptime_digest.sent" in acts

    c = TestClient(main.app)
    r = c.post("/api/uptime-digest/send", json={"days": 7},
               headers=_h(ctx["viewer"]))
    assert r.status_code == 403


def test_send_digest_no_recipients_skipped(ctx, monkeypatch):
    db = get_db()
    db.execute("DELETE FROM alert_emails WHERE org_id=?", (ctx["org"],))
    db.commit()
    res = dg.send_digest(db, ctx["org"])
    db.close()
    assert res["skipped"] is True and res["sent"] == 0


def test_send_digest_smtp_unconfigured_skipped(ctx, monkeypatch):
    monkeypatch.setattr(email_alerts, "send_email",
                        lambda to, subj, txt, html=None:
                        (False, 0, "SMTP not configured"))
    _seed_daily(ctx["org"])
    db = get_db()
    res = dg.send_digest(db, ctx["org"])
    db.close()
    assert res["skipped"] is True


def test_run_digests_once(ctx, monkeypatch):
    sent = []
    monkeypatch.setattr(email_alerts, "send_email",
                        lambda to, subj, txt, html=None:
                        (sent.append(to) or (True, 1, None)))
    _seed_daily(ctx["org"])
    # due now: Monday 09:00 UTC, weekly Monday 08:00
    now = datetime(2026, 10, 5, 9, 0, tzinfo=timezone.utc)
    db = get_db()
    dg.upsert_config(db, ctx["org"], True, "weekly", 0, 1, 8)
    out = dg.run_digests_once(db, now)
    assert out == {"sent": 1, "skipped": 0}
    assert len(sent) == 1
    cfg = dg.get_config(db, ctx["org"])
    assert cfg["last_sent_at"] is not None
    # second run in the same period: not due anymore
    out = dg.run_digests_once(db, now)
    assert out == {"sent": 0, "skipped": 0}
    db.close()
