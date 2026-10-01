"""Tests for TLS certificate expiry monitoring.

- hostname validation + public-IP refusal (SSRF guard)
- cert probing against a faked TLS stack (no real network)
- CRUD endpoints: RBAC, validation, org isolation, audit
- alert fan-out to all 5 channels on expiry, notifications event=cert.expiry
- anti-spam: no repeat alert inside the repeat window, re-alert after it
- ok/error states never alert; sweep only probes due domains
"""
import os
import socket
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-cert-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-cert-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import cert_monitor  # noqa: E402
import scheduler  # noqa: E402
import telegram_alerts  # noqa: E402
import slack_alerts  # noqa: E402
import teams_alerts  # noqa: E402
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
    org = create_org(f"CertCo_{uid}", plan="free")
    other = create_org(f"CertOther_{uid}", plan="free")
    member = provision_key(org, f"cert-member-{uid}", actor="owner",
                           role="member")
    viewer = provision_key(org, f"cert-viewer-{uid}", actor="owner",
                           role="viewer")
    o_member = provision_key(other, f"cert-o-member-{uid}", actor="owner",
                             role="member")
    db = get_db()
    db.execute("INSERT INTO telegram_chats (org_id, chat_id, label,"
               " created_at) VALUES (?,?,?,?)",
               (org, "777000", "ops", "2026-10-02T00:00:00+00:00"))
    db.execute("INSERT INTO alert_emails (org_id, email, enabled,"
               " created_at) VALUES (?,?,1,?)",
               (org, f"ops-{uid}@example.com", "2026-10-02T00:00:00+00:00"))
    db.commit()
    db.close()
    return {"org": org, "other": other, "member": member, "viewer": viewer,
            "o_member": o_member, "uid": uid}


@pytest.fixture(autouse=True)
def _clean_cert_state(ctx):
    """cert.expiry notification rows share the session DB; test_schedules
    reads notifications with a bare fetchone(), so leftover rows from this
    module break it. Clean up after every test."""
    yield
    db = get_db()
    db.execute("DELETE FROM notifications WHERE event='cert.expiry'")
    db.execute("DELETE FROM cert_domains WHERE org_id IN (?,?)",
               (ctx["org"], ctx["other"]))
    db.commit()
    db.close()


def _h(key):
    return {"X-API-Key": key}


def _row(domain_id):
    db = get_db()
    r = dict(db.execute("SELECT * FROM cert_domains WHERE id=?",
                        (domain_id,)).fetchone())
    db.close()
    return r


def _notifs(org):
    db = get_db()
    rows = [dict(r) for r in db.execute(
        "SELECT * FROM notifications WHERE org_id=? AND event='cert.expiry'",
        (org,)).fetchall()]
    db.close()
    return rows


def _fake_expiry(days):
    def _fake(host, port=443, timeout=12):
        exp = datetime.now(timezone.utc) + timedelta(days=days)
        return exp, "/CN=Fake CA", None
    return _fake


# ---------------------------------------------------------------- validation

def test_validate_hostname_normalizes():
    assert cert_monitor.validate_hostname("  Example.COM. ") == "example.com"
    assert cert_monitor.validate_hostname("api.braimsec.world") == \
        "api.braimsec.world"


def test_validate_hostname_rejects():
    for bad in ["", "http://example.com", "not a host", "a" * 300 + ".com",
                "10.0.0.1", "localhost"]:
        with pytest.raises(ValueError):
            cert_monitor.validate_hostname(bad)


def test_private_ip_refused(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM,
                                          6, "", ("10.1.2.3", 0))])
    called = []
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: called.append(1))
    exp, issuer, err = cert_monitor.get_cert_expiry("internal.example.com")
    assert exp is None and "refusing" in err
    assert called == []  # never even dialed


def test_cert_expiry_parses_notafter(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM,
                                          6, "", ("93.184.216.34", 0))])

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeTLS:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getpeercert(self):
            return {"notAfter": "Oct 12 12:00:00 2030 GMT",
                    "issuer": ((("CN", "Fake CA"),),)}

    class FakeCtx:
        def wrap_socket(self, sock, server_hostname=None):
            assert server_hostname == "example.com"
            return FakeTLS()

    import ssl as _ssl
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: FakeSock())
    monkeypatch.setattr(_ssl, "create_default_context", lambda: FakeCtx())
    exp, issuer, err = cert_monitor.get_cert_expiry("example.com")
    assert err is None
    assert (exp.year, exp.month, exp.day) == (2030, 10, 12)
    assert "Fake CA" in issuer


# ------------------------------------------------------------------ CRUD

def test_crud_and_rbac(ctx, monkeypatch):
    c = TestClient(main.app)
    monkeypatch.setattr(cert_monitor, "get_cert_expiry",
                        _fake_expiry(90))
    r = c.post("/api/cert-domains",
               json={"hostname": "Example.COM.", "port": 443,
                     "warn_days": 14, "webhook_url": "https://hooks.x/c"},
               headers=_h(ctx["member"]))
    assert r.status_code == 200, r.text
    dom = r.json()
    assert dom["hostname"] == "example.com"
    assert dom["_live"]["status"] == "ok"
    assert dom["_live"]["days_left"] == 89
    did = dom["id"]

    # viewer cannot add
    r = c.post("/api/cert-domains", json={"hostname": "b.example.com"},
               headers=_h(ctx["viewer"]))
    assert r.status_code == 403

    # invalid hostname / port / duplicate
    r = c.post("/api/cert-domains", json={"hostname": "http://x.com"},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post("/api/cert-domains",
               json={"hostname": "dup.example.com", "port": 99999},
               headers=_h(ctx["member"]))
    assert r.status_code == 400
    r = c.post("/api/cert-domains", json={"hostname": "example.com"},
               headers=_h(ctx["member"]))
    assert r.status_code == 400  # duplicate

    # list (viewer ok)
    r = c.get("/api/cert-domains", headers=_h(ctx["viewer"]))
    assert r.status_code == 200
    assert any(d["id"] == did for d in r.json())

    # other org sees nothing / 404 on update
    r = c.get("/api/cert-domains", headers=_h(ctx["o_member"]))
    assert r.status_code == 200 and r.json() == []
    r = c.patch(f"/api/cert-domains/{did}", json={"warn_days": 30},
                headers=_h(ctx["o_member"]))
    assert r.status_code == 404

    # update + audit
    r = c.patch(f"/api/cert-domains/{did}",
                json={"warn_days": 30, "enabled": False},
                headers=_h(ctx["member"]))
    assert r.status_code == 200
    assert r.json()["warn_days"] == 30 and r.json()["enabled"] == 0
    r = c.patch(f"/api/cert-domains/{did}", json={},
                headers=_h(ctx["member"]))
    assert r.status_code == 400

    db = get_db()
    acts = {r2["action"] for r2 in db.execute(
        "SELECT action FROM audit_log WHERE org_id=?", (ctx["org"],))}
    db.close()
    assert {"cert_domain.added", "cert_domain.updated"} <= acts

    # delete
    r = c.delete(f"/api/cert-domains/{did}", headers=_h(ctx["member"]))
    assert r.status_code == 200 and r.json()["deleted"] == did
    r = c.delete(f"/api/cert-domains/{did}", headers=_h(ctx["member"]))
    assert r.status_code == 404


# ------------------------------------------------------------------ alerts

def _patch_senders(monkeypatch, calls):
    monkeypatch.setattr(scheduler, "send_alert",
                        lambda url, payload, org_id=None:
                        (calls.append(("webhook", url, payload)) or
                         (True, 1, 200, None)))
    monkeypatch.setattr(telegram_alerts, "send_telegram",
                        lambda chat_id, text:
                        (calls.append(("telegram", chat_id)) or
                         (True, 1, None)))
    monkeypatch.setattr(slack_alerts, "send_slack",
                        lambda url, text:
                        (calls.append(("slack", url)) or (True, 1, None)))
    monkeypatch.setattr(teams_alerts, "send_teams",
                        lambda url, card:
                        (calls.append(("teams", url)) or (True, 1, None)))
    monkeypatch.setattr(email_alerts, "send_email",
                        lambda to, subj, txt, html=None:
                        (calls.append(("email", to)) or (True, 1, None)))


def test_expiry_alert_fanout_all_channels(ctx, monkeypatch):
    c = TestClient(main.app)
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(cert_monitor, "get_cert_expiry", _fake_expiry(5))
    r = c.post("/api/cert-domains",
               json={"hostname": "soon.example.com",
                     "webhook_url": "https://hooks.x/cert"},
               headers=_h(ctx["member"]))
    assert r.status_code == 200
    did = r.json()["id"]
    assert r.json()["_live"]["status"] == "expiring"

    chans = {ch for ch, *_ in calls}
    assert {"webhook", "telegram", "email"} <= chans
    rows = _notifs(ctx["org"])
    assert {r2["channel"] for r2 in rows} == {"webhook", "telegram", "email"}
    assert all(r2["status"] == "sent" for r2 in rows)
    assert all(r2["severity"] == "high" for r2 in rows)  # 5 days -> high
    assert all(r2["new_count"] == 4 for r2 in rows)  # days_left persisted
    payload = rows[0]["payload"]
    assert "soon.example.com" in payload
    assert _row(did)["last_alerted_at"] is not None

    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM audit_log WHERE org_id=?"
                   " AND action='cert_domain.alerted'",
                   (ctx["org"],)).fetchone()["c"]
    db.close()
    assert n == 1


def test_no_repeat_alert_inside_window(ctx, monkeypatch):
    c = TestClient(main.app)
    calls = []
    _patch_senders(monkeypatch, calls)
    monkeypatch.setattr(cert_monitor, "get_cert_expiry", _fake_expiry(5))
    r = c.post("/api/cert-domains", json={"hostname": "rep.example.com"},
               headers=_h(ctx["member"]))
    did = r.json()["id"]
    assert len(_notifs(ctx["org"])) == 2  # telegram + email (no webhook url)

    # immediate re-check: alert suppressed
    r = c.post(f"/api/cert-domains/{did}/check", headers=_h(ctx["member"]))
    assert r.json()["_live"]["status"] == "expiring"
    assert len(_notifs(ctx["org"])) == 2

    # after the repeat window: re-alerts
    db = get_db()
    db.execute("UPDATE cert_domains SET last_alerted_at=?"
               " WHERE id=?", ("2020-01-01T00:00:00+00:00", did))
    db.commit()
    db.close()
    c.post(f"/api/cert-domains/{did}/check", headers=_h(ctx["member"]))
    assert len(_notifs(ctx["org"])) == 4


def test_ok_and_error_never_alert(ctx, monkeypatch):
    c = TestClient(main.app)
    calls = []
    _patch_senders(monkeypatch, calls)

    monkeypatch.setattr(cert_monitor, "get_cert_expiry", _fake_expiry(90))
    r = c.post("/api/cert-domains", json={"hostname": "fine.example.com"},
               headers=_h(ctx["member"]))
    assert r.json()["_live"]["status"] == "ok"
    assert _row(r.json()["id"])["last_alerted_at"] is None

    monkeypatch.setattr(cert_monitor, "get_cert_expiry",
                        lambda h, p=443, t=12: (None, None, "boom: refused"))
    r = c.post("/api/cert-domains", json={"hostname": "down.example.com"},
               headers=_h(ctx["member"]))
    assert r.json()["_live"]["status"] == "error"
    assert calls == []
    assert _notifs(ctx["org"]) == []


def test_sweep_only_probes_due_domains(ctx, monkeypatch):
    c = TestClient(main.app)
    calls = []
    monkeypatch.setattr(cert_monitor, "get_cert_expiry",
                        lambda h, p=443, t=12: calls.append(h) or
                        (datetime.now(timezone.utc) + timedelta(days=90),
                         None, None))
    r = c.post("/api/cert-domains", json={"hostname": "s1.example.com"},
               headers=_h(ctx["member"]))
    did = r.json()["id"]
    n_calls = len(calls)

    # sweep: already checked -> skipped
    out = cert_monitor.run_cert_checks_once()
    assert out["checked"] == 0
    assert len(calls) == n_calls

    # make it due -> probed again
    db = get_db()
    db.execute("UPDATE cert_domains SET last_checked_at=?"
               " WHERE id=?", ("2020-01-01T00:00:00+00:00", did))
    db.commit()
    db.close()
    out = cert_monitor.run_cert_checks_once()
    assert out["checked"] == 1 and len(calls) == n_calls + 1


def test_notifications_filter_cert_event(ctx, monkeypatch):
    c = TestClient(main.app)
    _patch_senders(monkeypatch, [])
    monkeypatch.setattr(cert_monitor, "get_cert_expiry", _fake_expiry(5))
    c.post("/api/cert-domains", json={"hostname": "fil.example.com"},
           headers=_h(ctx["member"]))
    r = c.get("/api/notifications?event=cert.expiry",
              headers=_h(ctx["member"]))
    assert r.status_code == 200
    assert len(r.json()) == 2
    r = c.get("/api/notifications?event=bogus", headers=_h(ctx["member"]))
    assert r.status_code == 400
