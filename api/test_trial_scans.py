"""Tests for the public trial scans (POST/GET /api/trial/scans, GET /trial).

No signup, strict caps: git and URL validation are stubbed (no network),
scan execution is stubbed at main.enqueue_scan — what is tested is the
HTTP contract, the caps ledger (trial_scans), the summary shape, and
that trial scans never touch the trial org's plan quota.
"""
import os
import sys
import tempfile
import uuid

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-trial-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-trial-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import vcs  # noqa: E402
from billing import quota_status, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()
client = TestClient(main.app)
FAKE_SHA = "a" * 40


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture(autouse=True)
def _stub_git_and_queue(monkeypatch):
    def fake_validate(url):
        if not isinstance(url, str) or "bad" in url or " " in url:
            raise ValueError("repo_url must use https")
        return url.rstrip("/")

    def fake_clone(url, dest_dir, timeout=120):
        os.makedirs(dest_dir, exist_ok=True)
        with open(os.path.join(dest_dir, "app.py"), "w") as f:
            f.write("print('hello')\n")
        return FAKE_SHA

    monkeypatch.setattr(vcs, "validate_repo_url", fake_validate)
    monkeypatch.setattr(vcs, "clone_public_repo", fake_clone)
    monkeypatch.setattr(main, "enqueue_scan", lambda *a, **k: "inline")


@pytest.fixture(autouse=True)
def _clean_trial_rows():
    yield
    db = get_db()
    db.execute("DELETE FROM trial_scans")
    row = db.execute("SELECT id FROM organizations WHERE name=?",
                     (main.TRIAL_ORG_NAME,)).fetchone()
    if row:
        db.execute("DELETE FROM findings WHERE scan_id IN"
                   " (SELECT id FROM scans WHERE org_id=?)", (row["id"],))
        db.execute("DELETE FROM scans WHERE org_id=?", (row["id"],))
    db.commit()
    db.close()


def _trial_row(scan_id, ip="testclient"):
    db = get_db()
    db.execute(
        "INSERT INTO trial_scans (scan_id, ip, repo_url, created_at)"
        " VALUES (?,?,?,?)",
        (scan_id, ip, "https://github.com/acme/x", main.now()))
    db.commit()
    db.close()


def test_trial_scan_created_and_polled():
    r = client.post("/api/trial/scans",
                    data={"repo_url": "https://github.com/acme/widgets"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "queued"
    scan_id = body["scan_id"]
    assert body["poll_url"] == f"/api/trial/scans/{scan_id}"

    org_id = main._trial_org_id()
    db = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    trial = db.execute("SELECT * FROM trial_scans WHERE scan_id=?",
                       (scan_id,)).fetchone()
    db.close()
    assert scan["org_id"] == org_id
    assert scan["target_name"] == "github.com/acme/widgets"
    assert scan["commit_sha"] == FAKE_SHA
    assert trial is not None and trial["ip"] == "testclient"
    # Trial scans never consume the org's plan quota.
    _allowed, used, _quota = quota_status(org_id)
    assert used == 0

    r = client.get(f"/api/trial/scans/{scan_id}")
    assert r.status_code == 200
    assert r.json()["status"] == "queued"
    assert r.json()["target"] == "github.com/acme/widgets"


def test_trial_page_served():
    r = client.get("/trial")
    assert r.status_code == 200
    assert "trial scan" in r.text.lower()


def test_trial_invalid_url_rejected():
    r = client.post("/api/trial/scans", data={"repo_url": "bad url"})
    assert r.status_code == 400


def test_trial_clone_failure_rejected(monkeypatch):
    def boom(url, dest_dir, timeout=120):
        raise RuntimeError("git failed (rc=128): repository not found")

    monkeypatch.setattr(vcs, "clone_public_repo", boom)
    db = get_db()
    before = db.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    db.close()
    r = client.post("/api/trial/scans",
                    data={"repo_url": "https://github.com/acme/ghost"})
    assert r.status_code == 400
    assert "public repositories" in r.json()["detail"]
    db = get_db()
    after = db.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    db.close()
    assert after == before


def test_trial_per_ip_daily_cap():
    for i in range(main.TRIAL_PER_IP_DAILY):
        _trial_row("cap-ip-" + uuid.uuid4().hex[:8])
    r = client.post("/api/trial/scans",
                    data={"repo_url": "https://github.com/acme/widgets"})
    assert r.status_code == 429
    assert "Daily trial limit" in r.json()["detail"]


def test_trial_global_daily_cap():
    for i in range(main.TRIAL_GLOBAL_DAILY):
        _trial_row("cap-g-" + uuid.uuid4().hex[:8], ip=f"10.0.0.{i}")
    r = client.post("/api/trial/scans",
                    data={"repo_url": "https://github.com/acme/widgets"})
    assert r.status_code == 429
    assert "capacity is full" in r.json()["detail"]


def test_trial_status_unknown_and_nontrial_are_404():
    assert client.get("/api/trial/scans/nope").status_code == 404
    # A real scan that is not a trial scan stays invisible here.
    db = get_db()
    sid = "scan-" + uuid.uuid4().hex[:12]
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        (sid, main._trial_org_id(), "private", "done", main.now()))
    db.commit()
    db.close()
    assert client.get(f"/api/trial/scans/{sid}").status_code == 404


def test_trial_status_done_summary_top_findings():
    org_id = main._trial_org_id()
    sid = "trial-" + uuid.uuid4().hex[:12]
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " finished_at, total_findings) VALUES (?,?,?,?,?,?,?)",
        (sid, org_id, "github.com/acme/widgets", "done", main.now(),
         main.now(), 7))
    sevs = ["warning", "error", "note", "error", "warning", "warning",
            "error"]
    for i, sev in enumerate(sevs):
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (sid, "semgrep", f"rule-{i}", sev, f"msg {i}", f"f{i}.py",
             i + 1, 1))
    db.commit()
    db.close()
    _trial_row(sid)

    r = client.get(f"/api/trial/scans/{sid}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "done"
    assert body["total_findings"] == 7
    assert body["severity_summary"] == {"error": 3, "warning": 3, "note": 1}
    assert len(body["top_findings"]) == main.TRIAL_TOP_FINDINGS
    # Highest severity first.
    assert body["top_findings"][0]["severity"] == "error"
    assert "free account" in body["note"]


def _done_scan_with_findings(findings):
    """Insert a done trial scan with (rule_id, severity, file, line)
    findings rows and return its scan_id."""
    org_id = main._trial_org_id()
    sid = "trial-" + uuid.uuid4().hex[:12]
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " finished_at, total_findings) VALUES (?,?,?,?,?,?,?)",
        (sid, org_id, "github.com/acme/widgets", "done", main.now(),
         main.now(), len(findings)))
    for rule_id, sev, path, line in findings:
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (sid, "semgrep", rule_id, sev, f"msg {rule_id}", path, line, 1))
    db.commit()
    db.close()
    _trial_row(sid)
    return sid


def test_trial_summary_dedupes_cross_pack_keeps_distinct_advisories():
    wf = ".github/workflows/ci.yml"
    lock = "package-lock.json"
    sid = _done_scan_with_findings([
        # Two rule packs flag the same workflow line for the same issue.
        ("opt.rules.yaml.github-actions.security."
         "github-actions-mutable-action-tag", "warning", wf, 10),
        ("opt.rules-braimsec.braimsec.gha.unpinned-action",
         "warning", wf, 10),
        # Two distinct advisories against one lockfile line: both stay.
        ("GHSA-aaaa-1111", "error", lock, 5),
        ("GHSA-bbbb-2222", "error", lock, 5),
    ])
    body = client.get(f"/api/trial/scans/{sid}").json()
    assert body["total_findings"] == 3
    assert body["severity_summary"] == {"warning": 1, "error": 2}


def test_trial_top_findings_diversified_code_first():
    lock = "package-lock.json"
    rows = [(f"GHSA-{i:04d}", "error", lock, i + 1) for i in range(5)]
    rows += [
        ("python.sql-injection", "error", "app/views.py", 42),
        ("python.weak-hash", "warning", "app/util.py", 7),
        ("js.xss", "warning", "web/ui.js", 9),
    ]
    sid = _done_scan_with_findings(rows)
    body = client.get(f"/api/trial/scans/{sid}").json()
    top = body["top_findings"]
    assert len(top) == main.TRIAL_TOP_FINDINGS
    # A code error outranks lockfile errors at equal severity.
    assert top[0]["file"] == "app/views.py"
    # At most two rows from the lockfile in the top list.
    assert sum(1 for f in top if f["file"] == lock) == 2


def test_trial_top_findings_paths_are_repo_relative():
    sid = _done_scan_with_findings([
        ("python.sql-injection", "error",
         "/data/braimsec/uploads/braimsec-trial-xyz/src/app/main.py", 3),
    ])
    body = client.get(f"/api/trial/scans/{sid}").json()
    assert body["top_findings"][0]["file"] == "app/main.py"
    assert "/data/" not in body["top_findings"][0]["file"]
