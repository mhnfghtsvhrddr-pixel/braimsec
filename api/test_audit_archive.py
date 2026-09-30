"""Tests for audit-log archival: POST /api/audit-log/archive and friends.

Archival moves rows older than the retention window out of the hot
``audit_log`` table into gzipped, sha256-manifested files. The run
itself is audited as ``audit_log.archived``.
"""
import gzip
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-arch-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-key-123")
os.environ.setdefault("BRAIMSEC_ARCHIVE_ROOT",
                      os.path.join(_tmp, "archives"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import audit  # noqa: E402
import main  # noqa: E402
from audit import log_event  # noqa: E402
from billing import create_org, ensure_owner_org, provision_key  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture()
def ctx():
    ensure_owner_org()
    org = create_org("ArchiveInc", plan="free")
    other = create_org("OtherCorp", plan="free")
    owner = provision_key(org, "owner", actor="owner", role="owner")
    admin = provision_key(org, "admin", actor="owner", role="admin")
    member = provision_key(org, "member", actor="owner", role="member")
    return {"org": org, "other": other, "owner": owner,
            "admin": admin, "member": member}


def _h(key):
    return {"x-api-key": key}


def _old_event(org, action, days_ago):
    rid = log_event(org, "owner", action, "scan", "s1", {"n": days_ago})
    old = (datetime.now(timezone.utc)
           - timedelta(days=days_ago)).isoformat(timespec="seconds")
    db = get_db()
    try:
        db.execute("UPDATE audit_log SET created_at=? WHERE id=?", (old, rid))
        db.commit()
    finally:
        db.close()
    return rid


def _hot_count(org):
    db = get_db()
    try:
        return db.execute("SELECT COUNT(*) c FROM audit_log WHERE org_id=?",
                          (org,)).fetchone()["c"]
    finally:
        db.close()


def test_archive_moves_old_rows(ctx):
    for d in (40, 50, 60):
        _old_event(ctx["org"], "scan.completed", d)
    _old_event(ctx["org"], "scan.completed", 5)
    log_event(ctx["org"], "owner", "scan.created", "scan", "fresh", {})
    before = _hot_count(ctx["org"])
    with TestClient(main.app) as c:
        r = c.post("/api/audit-log/archive", headers=_h(ctx["owner"]),
                   json={"older_than_days": 30})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["archived"] == 3
        assert body["archive_id"].startswith("arc_")
        # Hot table keeps only the recent rows (3 archived + the run's own
        # audit_log.archived event is new, so net -3... +1 = before - 2).
        assert _hot_count(ctx["org"]) == before - 3 + 1
        # Archive file exists, holds exactly the 3 old rows.
        path = os.path.join(os.environ["BRAIMSEC_ARCHIVE_ROOT"],
                            body["filename"])
        assert os.path.isfile(path)
        with gzip.open(path, "rt", encoding="utf-8") as gz:
            rows = [json.loads(line) for line in gz]
        assert len(rows) == 3
        assert {r["action"] for r in rows} == {"scan.completed"}
        # Manifest recorded with a matching sha256.
        manifests = c.get("/api/audit-log/archives",
                          headers=_h(ctx["owner"])).json()
        assert len(manifests) == 1
        m = manifests[0]
        assert m["row_count"] == 3
        with open(path, "rb") as fh:
            assert hashlib.sha256(fh.read()).hexdigest() == m["sha256"]
        assert m["first_id"] < m["last_id"]
        # The run itself is audited.
        events = c.get("/api/audit-log",
                       params={"action": "audit_log.archived"},
                       headers=_h(ctx["owner"])).json()
        assert any(e["resource_id"] == body["archive_id"]
                   and e["detail"]["rows"] == 3 for e in events)


def test_archive_nothing_to_do(ctx):
    log_event(ctx["org"], "owner", "scan.created", "scan", "s1", {})
    before = _hot_count(ctx["org"])
    with TestClient(main.app) as c:
        r = c.post("/api/audit-log/archive", headers=_h(ctx["owner"]),
                   json={"older_than_days": 30})
        assert r.status_code == 200, r.text
        assert r.json() == {"archived": 0, "archive_id": None}
        assert _hot_count(ctx["org"]) == before
        assert c.get("/api/audit-log/archives",
                     headers=_h(ctx["owner"])).json() == []


def test_archive_requires_owner(ctx):
    for key, expected in ((ctx["admin"], 403), (ctx["member"], 403)):
        with TestClient(main.app) as c:
            r = c.post("/api/audit-log/archive", headers=_h(key),
                       json={"older_than_days": 30})
            assert r.status_code == expected, r.text


def test_archive_rejects_too_small_window(ctx):
    with TestClient(main.app) as c:
        r = c.post("/api/audit-log/archive", headers=_h(ctx["owner"]),
                   json={"older_than_days": 0})
        assert r.status_code == 400, r.text
        r = c.post("/api/audit-log/archive", headers=_h(ctx["owner"]),
                   json={"older_than_days": "soon"})
        assert r.status_code == 400, r.text


def test_archives_are_org_isolated(ctx):
    _old_event(ctx["org"], "scan.completed", 40)
    _old_event(ctx["other"], "scan.completed", 40)
    with TestClient(main.app) as c:
        r = c.post("/api/audit-log/archive", headers=_h(ctx["owner"]),
                   json={"older_than_days": 30})
        assert r.json()["archived"] == 1
        assert _hot_count(ctx["other"]) == 1
        assert c.get("/api/audit-log/archives",
                     headers=_h(ctx["owner"])).json() != []


def test_admin_can_list_and_verify_but_not_archive(ctx):
    _old_event(ctx["org"], "scan.completed", 40)
    with TestClient(main.app) as c:
        arc = c.post("/api/audit-log/archive", headers=_h(ctx["owner"]),
                     json={"older_than_days": 30}).json()["archive_id"]
        # Admin: list + verify OK.
        assert c.get("/api/audit-log/archives",
                     headers=_h(ctx["admin"])).status_code == 200
        v = c.get(f"/api/audit-log/archives/{arc}/verify",
                  headers=_h(ctx["admin"])).json()
        assert v["match"] is True
        assert v["row_count"] == 1
        # Member: both rejected.
        assert c.get("/api/audit-log/archives",
                     headers=_h(ctx["member"])).status_code == 403
        assert c.get(f"/api/audit-log/archives/{arc}/verify",
                     headers=_h(ctx["member"])).status_code == 403
        # Unknown archive -> 404.
        r = c.get("/api/audit-log/archives/arc_nope/verify",
                  headers=_h(ctx["admin"]))
        assert r.status_code == 404


def test_verify_detects_tampering(ctx):
    _old_event(ctx["org"], "scan.completed", 40)
    with TestClient(main.app) as c:
        arc = c.post("/api/audit-log/archive", headers=_h(ctx["owner"]),
                     json={"older_than_days": 30}).json()
        path = os.path.join(os.environ["BRAIMSEC_ARCHIVE_ROOT"],
                            arc["filename"])
        with open(path, "ab") as fh:
            fh.write(b"tampered")
        v = c.get(f"/api/audit-log/archives/{arc['archive_id']}/verify",
                  headers=_h(ctx["owner"])).json()
        assert v["match"] is False
        assert v["actual_sha256"] != v["expected_sha256"]


def test_archive_failure_keeps_hot_table(ctx, monkeypatch):
    """If the file write blows up, no rows are deleted and no manifest
    or audit record is written."""
    for d in (40, 50):
        _old_event(ctx["org"], "scan.completed", d)
    before = _hot_count(ctx["org"])

    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(audit.gzip, "open", boom)
    with pytest.raises(RuntimeError, match="disk full"):
        audit.archive_events(ctx["org"], "owner", 30)
    assert _hot_count(ctx["org"]) == before
    db = get_db()
    try:
        n = db.execute("SELECT COUNT(*) c FROM audit_archives WHERE org_id=?",
                       (ctx["org"],)).fetchone()["c"]
    finally:
        db.close()
    assert n == 0
