"""Async queue tests (Celery + Redis).

Covers the durable-queue increment without needing a live worker:

- task logic runs through the real Celery task objects (bind=True) with a
  fake task-self, so retry/idempotency paths are deterministic
- routing (celery vs inline) is asserted on enqueue_scan / enqueue_ai_review
- one end-to-end pass goes through TestClient with task_always_eager, i.e.
  through real Celery machinery but no broker
- the v1 HTTP contract is unchanged (queued -> poll -> done)

DB isolation: BRAIMSEC_DB points at a tmp file BEFORE any import, so this
module (imported first alphabetically) makes the whole pytest session hermetic.
"""
import hashlib
import hmac
import json
import os
import sys
import tempfile
from types import SimpleNamespace

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import tasks  # noqa: E402
from database import get_db, init_db  # noqa: E402

HEADERS = {"x-api-key": "test-key-123"}

FINDINGS = [
    {"tool": "semgrep", "rule_id": "python.lang.security.audit.eval-detected",
     "severity": "high", "message": "eval", "file": "a.py", "line": 1, "col": 1},
    {"tool": "gitleaks", "rule_id": "generic-api-key",
     "severity": "high", "message": "key", "file": "b.py", "line": 2, "col": 1},
]


class FakeSelf:
    """Minimal stand-in for a bound Celery task."""

    class RetryRaised(Exception):
        pass

    def __init__(self, max_retries=0):
        self.max_retries = max_retries
        self.request = SimpleNamespace(retries=0)
        self.retry_called = False

    def retry(self, exc=None, countdown=None):
        self.retry_called = True
        raise FakeSelf.RetryRaised()


@pytest.fixture()
def engines(monkeypatch):
    monkeypatch.setattr(tasks, "run_semgrep", lambda d: [dict(FINDINGS[0])])
    monkeypatch.setattr(tasks, "run_gitleaks", lambda d: [dict(FINDINGS[1])])
    monkeypatch.setattr(tasks, "run_sca", lambda d: [])
    monkeypatch.setattr(tasks.time, "sleep", lambda s: None)


def _mk_scan(webhook_url=None, webhook_secret=None):
    init_db()
    db = get_db()
    scan_id = "scan_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " webhook_url, webhook_secret) VALUES (?,?,?,?,?,?,?)",
        (scan_id, "owner", "t", "queued", "2026-01-01T00:00:00+00:00",
         webhook_url, webhook_secret))
    db.commit()
    db.close()
    return scan_id


def _sandbox_target(name):
    """Create a scan target inside the server's scan sandbox (LFI guard)."""
    from pathlib import Path
    d = Path(main.SCAN_ROOT) / f"pytest-{name}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.py").write_text("x = 1\n")
    return d


def _get_scan(scan_id):
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    n = db.execute("SELECT COUNT(*) c FROM findings WHERE scan_id=?",
                   (scan_id,)).fetchone()["c"]
    db.close()
    return dict(row), n


# ---------------------------------------------------------------------------
# Task logic
# ---------------------------------------------------------------------------

def test_run_scan_success_marks_done(engines):
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, "/tmp", None)
    scan, n = _get_scan(scan_id)
    assert scan["status"] == "done"
    assert scan["total_findings"] == 2
    assert n == 2


def test_run_scan_is_idempotent_on_redelivery(engines):
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, "/tmp", None)
    tasks._run_scan_impl(FakeSelf(), scan_id, "/tmp", None)  # redelivered
    _, n = _get_scan(scan_id)
    assert n == 2, "retry must not duplicate findings"


def test_run_scan_exhausted_retries_marks_failed(engines, monkeypatch):
    monkeypatch.setattr(tasks, "run_semgrep",
                        lambda d: (_ for _ in ()).throw(RuntimeError("boom")))
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(max_retries=0), scan_id, "/tmp", None)
    scan, _ = _get_scan(scan_id)
    assert scan["status"] == "failed"
    assert "boom" in (scan["error"] or "")


def test_run_scan_retries_on_transient_failure(engines, monkeypatch):
    monkeypatch.setattr(tasks, "run_semgrep",
                        lambda d: (_ for _ in ()).throw(RuntimeError("boom")))
    scan_id = _mk_scan()
    fake = FakeSelf(max_retries=2)
    with pytest.raises(FakeSelf.RetryRaised):
        tasks._run_scan_impl(fake, scan_id, "/tmp", None)
    assert fake.retry_called
    scan, _ = _get_scan(scan_id)
    assert scan["status"] == "running", "retry must not mark failed yet"


def test_webhook_signed_and_delivered(engines, monkeypatch):
    captured = {}

    class FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        return FakeResp()

    monkeypatch.setattr(tasks.urllib.request, "urlopen", fake_urlopen)
    scan_id = _mk_scan("https://hooks.example.test/x", "s3cr3t")
    tasks._run_scan_impl(FakeSelf(), scan_id, "/tmp", None)

    req = captured["req"]
    assert req.full_url == "https://hooks.example.test/x"
    body = req.data
    payload = json.loads(body)
    assert payload["event"] == "scan.completed"
    assert payload["scan_id"] == scan_id
    assert payload["total_findings"] == 2
    expected = hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
    assert req.headers["X-braimsec-signature"] == f"sha256={expected}"
    assert req.headers["X-braimsec-event"] == "scan.completed"


def test_webhook_failure_event_on_scan_failure(engines, monkeypatch):
    events = []

    class FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        events.append(json.loads(req.data)["event"])
        return FakeResp()

    monkeypatch.setattr(tasks.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(tasks, "run_semgrep",
                        lambda d: (_ for _ in ()).throw(RuntimeError("boom")))
    scan_id = _mk_scan("https://hooks.example.test/x", "s3cr3t")
    tasks._run_scan_impl(FakeSelf(max_retries=0), scan_id, "/tmp", None)
    assert events == ["scan.failed"]


def test_no_webhook_without_url(engines, monkeypatch):
    called = []
    monkeypatch.setattr(tasks.urllib.request, "urlopen",
                        lambda req, timeout=None: called.append(req))
    scan_id = _mk_scan()
    tasks._run_scan_impl(FakeSelf(), scan_id, "/tmp", None)
    assert called == []


# ---------------------------------------------------------------------------
# Routing: celery vs inline
# ---------------------------------------------------------------------------

def test_enqueue_routes_to_celery_when_configured(monkeypatch):
    monkeypatch.setenv("BRAIMSEC_BROKER_URL", "redis://127.0.0.1:6379/0")
    calls = []
    monkeypatch.setattr(tasks.run_scan, "delay",
                        lambda *a: calls.append(a))
    assert tasks.enqueue_scan("s1", "/tmp", None) == "celery"
    assert calls == [("s1", "/tmp", None, None)]
    assert tasks.queue_enabled() is True


def test_enqueue_passes_baseline_to_celery(monkeypatch):
    monkeypatch.setenv("BRAIMSEC_BROKER_URL", "redis://127.0.0.1:6379/0")
    calls = []
    monkeypatch.setattr(tasks.run_scan, "delay",
                        lambda *a: calls.append(a))
    assert tasks.enqueue_scan("s1", "/tmp", None,
                              baseline_scan_id="base1") == "celery"
    assert calls == [("s1", "/tmp", None, "base1")]


def test_enqueue_falls_back_inline_when_unconfigured(engines, monkeypatch):
    monkeypatch.delenv("BRAIMSEC_BROKER_URL", raising=False)
    calls = []
    monkeypatch.setattr(tasks.run_scan, "delay",
                        lambda *a: calls.append(a))
    scan_id = _mk_scan()
    assert tasks.enqueue_scan(scan_id, "/tmp", None) == "inline"
    assert calls == []
    scan, n = _get_scan(scan_id)
    assert scan["status"] == "done" and n == 2
    assert tasks.queue_enabled() is False


# ---------------------------------------------------------------------------
# HTTP contract (unchanged) + eager end-to-end through Celery machinery
# ---------------------------------------------------------------------------

def test_v1_contract_unchanged_eager(engines, monkeypatch, tmp_path):
    monkeypatch.setenv("BRAIMSEC_BROKER_URL", "redis://127.0.0.1:6379/0")
    tasks.celery_app.conf.task_always_eager = True
    try:
        target = _sandbox_target("eager")
        with TestClient(main.app) as c:
            r = c.post("/api/scans", headers=HEADERS,
                       data={"target_path": str(target)})
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["status"] == "queued" and body["scan_id"]
            # eager worker already ran it inline through Celery machinery
            s = c.get(f"/api/scans/{body['scan_id']}", headers=HEADERS)
            assert s.json()["status"] == "done"
            res = c.get(f"/api/scans/{body['scan_id']}/results",
                        headers=HEADERS)
            assert len(res.json()) == 2
    finally:
        tasks.celery_app.conf.task_always_eager = False


def test_webhook_url_accepted_and_secret_returned(engines, tmp_path):
    target = _sandbox_target("webhook")
    with TestClient(main.app) as c:
        r = c.post("/api/scans", headers=HEADERS,
                   data={"target_path": str(target),
                         "webhook_url": "https://hooks.example.test/x"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["webhook_secret"] and len(body["webhook_secret"]) == 32


def test_webhook_url_scheme_validated(tmp_path):
    target = _sandbox_target("scheme")
    with TestClient(main.app) as c:
        r = c.post("/api/scans", headers=HEADERS,
                   data={"target_path": str(target),
                         "webhook_url": "ftp://evil.example/x"})
        assert r.status_code == 400


def test_broker_unreachable_returns_503(monkeypatch, tmp_path):
    monkeypatch.setenv("BRAIMSEC_BROKER_URL", "redis://127.0.0.1:6399/0")
    target = _sandbox_target("unreachable")
    with TestClient(main.app) as c:
        r = c.post("/api/scans", headers=HEADERS,
                   data={"target_path": str(target)})
        assert r.status_code == 503, r.text
