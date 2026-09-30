"""Tests for the enterprise audit trail (api/audit.py + hooks).

- scan.created is logged on POST /api/scans with the key prefix as actor
- scan.completed is logged when the inline worker finishes the scan
- GET /api/audit-log returns the org's trail newest-first, org-isolated
- api_key.created / api_key.revoked are logged by billing
- unknown audit actions are rejected (closed vocabulary)
- the full key secret never appears in the log
"""
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-audit-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import audit  # noqa: E402
import tasks  # noqa: E402
from billing import create_org, provision_key, revoke_key, ensure_owner_org  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture()
def _mock_engines(monkeypatch):
    """No real semgrep/gitleaks in this env: stub the engine entry points
    (same approach as test_async_queue's `engines` fixture)."""
    monkeypatch.setattr(tasks, "run_semgrep", lambda d, scope=None: [])
    monkeypatch.setattr(tasks, "run_gitleaks", lambda d: [])
    monkeypatch.setattr(tasks, "run_sca", lambda d: [])
    monkeypatch.setattr(tasks.time, "sleep", lambda s: None)


@pytest.fixture()
def orgs():
    ensure_owner_org()
    a = create_org("Acme", plan="free")
    b = create_org("Globex", plan="free")
    key_a = provision_key(a, "ci", actor="owner")
    key_b = provision_key(b, "ci", actor="owner")
    return {"a": a, "b": b, "key_a": key_a, "key_b": key_b}


def _target(tmp_path):
    """Create a scan target inside the server's scan sandbox (LFI guard)."""
    from pathlib import Path
    d = Path(main.SCAN_ROOT) / f"pytest-audit-{tmp_path.name}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "app.py").write_text("print('hi')\n")
    return str(d)


def test_scan_lifecycle_audited(orgs, tmp_path, _mock_engines):
    headers = {"x-api-key": orgs["key_a"]}
    with TestClient(main.app) as c:
        r = c.post("/api/scans", headers=headers,
                   data={"target_path": _target(tmp_path)})
        assert r.status_code == 200, r.text
        scan_id = r.json()["scan_id"]
        # Inline worker runs before TestClient returns: completed is logged.
        log = c.get("/api/audit-log", headers=headers).json()
    actions = [e["action"] for e in log]
    assert "scan.created" in actions
    assert "scan.completed" in actions
    created = next(e for e in log if e["action"] == "scan.created")
    assert created["resource_id"] == scan_id
    assert created["actor"] == orgs["key_a"][:8]  # prefix, not the secret
    assert orgs["key_a"] not in str(log)  # full secret never logged
    # Newest first.
    assert log[0]["id"] > log[-1]["id"]


def test_failed_scan_audited(orgs, tmp_path, _mock_engines, monkeypatch):
    from scan_engine import EngineError
    monkeypatch.setattr(tasks, "run_semgrep",
                        lambda d, scope=None: (_ for _ in ()).throw(
                            EngineError("boom", exit_code=2)))
    monkeypatch.setattr(tasks.run_scan, "max_retries", 0)  # fail fast
    headers = {"x-api-key": orgs["key_a"]}
    with TestClient(main.app) as c:
        r = c.post("/api/scans", headers=headers,
                   data={"target_path": _target(tmp_path)})
        assert r.status_code == 200, r.text
        log = c.get("/api/audit-log", headers=headers).json()
    actions = [e["action"] for e in log]
    assert "scan.created" in actions
    assert "scan.failed" in actions
    failed = next(e for e in log if e["action"] == "scan.failed")
    assert failed["actor"] == "system"  # the worker closed it, not a key


def test_audit_log_is_org_isolated(orgs, tmp_path, _mock_engines):
    ha = {"x-api-key": orgs["key_a"]}
    hb = {"x-api-key": orgs["key_b"]}
    with TestClient(main.app) as c:
        r = c.post("/api/scans", headers=ha, data={"target_path": _target(tmp_path)})
        assert r.status_code == 200, r.text
        log_b = c.get("/api/audit-log", headers=hb).json()
        log_a = c.get("/api/audit-log", headers=ha).json()
    assert all(e["org_id"] == orgs["b"] for e in log_b)
    assert any(e["action"] == "scan.created" for e in log_a)
    assert not any(e["action"] == "scan.created" and
                   e["resource_id"] == r.json()["scan_id"] for e in log_b)


def test_audit_log_action_filter(orgs, tmp_path, _mock_engines):
    headers = {"x-api-key": orgs["key_a"]}
    with TestClient(main.app) as c:
        c.post("/api/scans", headers=headers, data={"target_path": _target(tmp_path)})
        only = c.get("/api/audit-log", headers=headers,
                     params={"action": "scan.created"}).json()
    assert only and all(e["action"] == "scan.created" for e in only)


def test_key_lifecycle_audited(orgs):
    # Revoke a *second* key: the test still needs key_a to read the log.
    spare = provision_key(orgs["a"], "spare", actor="owner")
    db = get_db()
    row = db.execute("SELECT id FROM api_keys WHERE key_prefix=? AND name='spare'",
                     (spare[:8],)).fetchone()
    db.close()
    revoke_key(row["id"], actor="owner")
    headers = {"x-api-key": orgs["key_a"]}
    with TestClient(main.app) as c:
        log = c.get("/api/audit-log", headers=headers).json()
    kinds = {(e["action"], e["actor"]) for e in log
             if e["action"] in ("api_key.created", "api_key.revoked")}
    assert ("api_key.created", "owner") in kinds
    assert ("api_key.revoked", "owner") in kinds
    assert spare not in str(log)  # raw secret never logged


def test_unknown_action_rejected(orgs):
    with pytest.raises(ValueError):
        audit.log_event(orgs["a"], "owner", "nope.not-real")


def test_master_key_actor_is_owner(orgs, tmp_path, _mock_engines):
    headers = {"x-api-key": "test-key-123"}
    with TestClient(main.app) as c:
        r = c.post("/api/scans", headers=headers,
                   data={"target_path": _target(tmp_path)})
        assert r.status_code == 200, r.text
        log = c.get("/api/audit-log", headers=headers,
                    params={"action": "scan.created"}).json()
    assert log and log[0]["actor"] == "owner"
