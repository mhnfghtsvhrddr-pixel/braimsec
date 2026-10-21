"""Tests for the GitHub PR scan-comments integration.

- PR webhook payload parsing (actions opened/synchronize/reopened parsed;
  closed/labeled/etc ignored)
- PR comment markdown builder (findings / clean / failed scan)
- post_or_update_pr_comment against a mocked urlopen (POST new vs PATCH
  existing marker comment; token never leaks into errors)
- github_token write-only: POST/PATCH store it encrypted, GET never
  returns it, pr_comments_enabled is derived
- webhook: pull_request for unknown repo -> ignored; bad signature -> 400;
  valid signature queues the ingest with PR context
- ingest: PR head (possibly a fork) is cloned and the scan is recorded in
  pr_scans
- maybe_post_pr_comment: posts once, stores the comment id, never raises
"""
import hashlib
import hmac
import json
import os
import sys
import tempfile

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-ghpr-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-ghpr-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import github_pr  # noqa: E402
import main  # noqa: E402
import tasks  # noqa: E402
import vcs  # noqa: E402
from billing import create_org, ensure_owner_org, provision_key, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()
MASTER = os.environ["BRAIMSEC_API_KEY"]
WEBHOOK = "https://hooks.test/services/ghpr"  # .test: no DNS, passes SSRF check

PAT = "github_pat_" + "a" * 60
PAT2 = "ghp_" + "b" * 36


def _uid():
    import uuid as _u
    return _u.uuid4().hex[:8]


@pytest.fixture(autouse=True)
def _cleanup_rows():
    # Clean up rows this module inserts in shared tables (AGENTS.md rule).
    # notifications is intentionally absent: these tests never write there.
    yield
    db = get_db()
    for tbl in ("pr_scans", "findings", "scans", "vcs_repos"):
        db.execute(f"DELETE FROM {tbl}")
    db.commit()
    db.close()


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    # Same sandbox DNS caveat as test_vcs.py.
    monkeypatch.setattr(vcs, "_resolve_checked", lambda host: [])


@pytest.fixture()
def ctx():
    ensure_owner_org()
    org = create_org("GhPrTestCo", plan="free")
    member = provision_key(org, "g-member", actor="owner", role="member")
    viewer = provision_key(org, "g-viewer", actor="owner", role="viewer")
    return {"org": org, "member": member, "viewer": viewer}


def _h(key):
    return {"X-API-Key": key}


def _mk_repo(db, org, url=None, branch="main", token=None):
    url = url or f"https://github.com/testorg/ghpr-{_uid()}"
    rid = "ghpr_" + _uid()
    secret = vcs.generate_webhook_secret()
    db.execute(
        "INSERT INTO vcs_repos (id, org_id, provider, repo_url, full_name,"
        " branch, webhook_secret_hash, webhook_secret_enc, github_token_enc,"
        " webhook_url, alert_severity, enabled, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rid, org, "github", vcs.validate_repo_url(url),
         "/".join(url.split("/")[3:]), branch, vcs.hash_secret(secret),
         vcs.encrypt_secret(secret),
         vcs.encrypt_secret(token) if token else None,
         WEBHOOK, "warning", 1, "2026-10-01T00:00:00+00:00"))
    db.commit()
    return rid, secret


def _mk_scan(db, org, scan_id, status, repo_id=None, sha=None, error=None):
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " total_findings, target_dir, vcs_repo_id, commit_sha, error)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (scan_id, org, "api", status, "2026-10-01T00:00:00+00:00",
         2, "/x", repo_id, sha, error))
    db.commit()


def _mk_finding(db, scan_id, severity, rule, file, line, msg):
    db.execute(
        "INSERT INTO findings (scan_id, tool, rule_id, severity, message,"
        " file, line, col) VALUES (?,?,?,?,?,?,?,?)",
        (scan_id, "semgrep", rule, severity, msg, file, line, 1))
    db.commit()


def _mk_pr_scan(db, scan_id, repo_id, pr_number, sha):
    db.execute(
        "INSERT INTO pr_scans (scan_id, repo_id, pr_number, head_sha,"
        " comment_id, created_at) VALUES (?,?,?,?,NULL,?)",
        (scan_id, repo_id, pr_number, sha, "2026-10-01T00:00:00+00:00"))
    db.commit()


def _gh_sig(secret, raw: bytes):
    return "sha256=" + hmac.new(secret.encode(), raw,
                                hashlib.sha256).hexdigest()


def _gh_pr(full_name="testorg/ghpr-x", pr_number=7, action="opened",
           base="main", head_sha="c" * 40, head_ref="feature", fork=None):
    return {
        "action": action,
        "repository": {
            "full_name": full_name,
            "clone_url": f"https://github.com/{full_name}.git",
        },
        "pull_request": {
            "number": pr_number,
            "head": {"sha": head_sha, "ref": head_ref,
                     "repo": {"clone_url": fork or
                              f"https://github.com/{full_name}.git"}},
            "base": {"ref": base},
        },
    }


# ---------------------------------------------------------------------------
# PR payload parsing
# ---------------------------------------------------------------------------

def test_pr_parse_actions():
    for action in ("opened", "synchronize", "reopened"):
        p = vcs.parse_github_push(_gh_pr(action=action),
                                  "pull_request")
        assert p is not None, action
        assert p["type"] == "pull_request"
        assert p["full_name"] == "testorg/ghpr-x"
        assert p["clone_url"] == "https://github.com/testorg/ghpr-x.git"
        assert p["pr_number"] == 7
        assert p["head_sha"] == "c" * 40
        assert p["head_ref"] == "feature"
        assert p["head_clone_url"] == "https://github.com/testorg/ghpr-x.git"
        assert p["base_ref"] == "main"


@pytest.mark.parametrize("action",
                         ["closed", "labeled", "assigned", "edited", None])
def test_pr_ignored_actions(action):
    assert vcs.parse_github_push(_gh_pr(action=action),
                                 "pull_request") is None


def test_pr_parse_fork_head():
    fork = "https://github.com/contrib/ghpr-x.git"
    p = vcs.parse_github_push(_gh_pr(fork=fork), "pull_request")
    assert p["head_clone_url"] == fork


def test_pr_parse_malformed():
    bad = _gh_pr()
    bad["pull_request"]["head"]["sha"] = "short"
    assert vcs.parse_github_push(bad, "pull_request")["type"] == "ignore"
    bad = _gh_pr()
    bad["pull_request"]["number"] = None
    assert vcs.parse_github_push(bad, "pull_request")["type"] == "ignore"


# ---------------------------------------------------------------------------
# Comment builder
# ---------------------------------------------------------------------------

_FINDINGS = [
    {"tool": "semgrep", "rule_id": "sql-injection", "severity": "error",
     "file": "api/auth.py", "line": 42, "message": "raw SQL with user input"},
    {"tool": "gitleaks", "rule_id": "aws-key", "severity": "warning",
     "file": ".env", "line": 3, "message": "possible AWS key"},
    {"tool": "semgrep", "rule_id": "xss", "severity": "note",
     "file": "web/app.js", "line": 10, "message": "unescaped output"},
]


def test_build_comment_with_findings():
    md = github_pr.build_pr_comment(
        "testorg/ghpr-x", 7, "c" * 40,
        {"error": 1, "warning": 1, "note": 1}, _FINDINGS, 3)
    assert md.startswith(github_pr.PR_COMMENT_MARKER)
    assert "testorg/ghpr-x#7" in md
    assert "**3 findings**" in md
    assert "1 error" in md and "1 warning" in md and "1 note" in md
    assert "`api/auth.py:42`" in md
    assert "sql-injection" in md
    assert "Full results in your BraimSec dashboard." in md


def test_build_comment_truncates_to_ten():
    many = [dict(_FINDINGS[0], file=f"f{i}.py", line=i) for i in range(25)]
    md = github_pr.build_pr_comment("o/r", 1, "d" * 40, {"error": 25},
                                    many, 25)
    assert md.count("- `f") == 10


def test_build_comment_clean():
    md = github_pr.build_pr_comment("o/r", 1, "d" * 40, {}, [], 0)
    assert md.startswith(github_pr.PR_COMMENT_MARKER)
    assert "No issues found" in md


def test_build_comment_failed():
    md = github_pr.build_pr_comment("o/r", 1, "d" * 40, {}, [], 0,
                                    failed=True, error="engines down")
    assert "Scan failed" in md and "engines down" in md
    assert md.startswith(github_pr.PR_COMMENT_MARKER)


# ---------------------------------------------------------------------------
# post_or_update_pr_comment (mocked urlopen)
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status = status

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urlopen_factory(calls, comments, post_id=999):
    def fake(req, timeout=None):
        calls.append((req.method, req.full_url,
                      json.loads(req.data.decode()) if req.data else None))
        if req.method == "GET":
            return _FakeResp(comments)
        if req.method == "POST":
            return _FakeResp({"id": post_id})
        return _FakeResp({"id": comments[0]["id"]})
    return fake


def test_post_creates_new_comment(monkeypatch):
    calls = []
    monkeypatch.setattr(github_pr, "urlopen",
                        _fake_urlopen_factory(calls, []))
    monkeypatch.setattr(github_pr.time, "sleep", lambda s: None)
    cid = github_pr.post_or_update_pr_comment(
        PAT, "testorg/ghpr-x", 7, github_pr.PR_COMMENT_MARKER + "\nhi")
    assert cid == 999
    methods = [m for m, _, _ in calls]
    assert methods == ["GET", "POST"]
    _, url, body = calls[1]
    assert url.startswith(
        "https://api.github.com/repos/testorg/ghpr-x/issues/7/comments")
    assert github_pr.PR_COMMENT_MARKER in body["body"]


def test_post_updates_existing_marker_comment(monkeypatch):
    calls = []
    existing = {"id": 111, "body": github_pr.PR_COMMENT_MARKER + "\nold"}
    monkeypatch.setattr(github_pr, "urlopen",
                        _fake_urlopen_factory(calls, [existing]))
    monkeypatch.setattr(github_pr.time, "sleep", lambda s: None)
    cid = github_pr.post_or_update_pr_comment(
        PAT, "testorg/ghpr-x", 7, github_pr.PR_COMMENT_MARKER + "\nnew")
    assert cid == 111
    methods = [m for m, _, _ in calls]
    assert methods == ["GET", "PATCH"]
    _, url, body = calls[1]
    assert url.endswith("/repos/testorg/ghpr-x/issues/comments/111")
    assert "new" in body["body"]
    assert "POST" not in methods  # no duplicate comment


def test_post_uses_github_headers(monkeypatch):
    seen = {}

    def fake(req, timeout=None):
        seen.update(req.headers)
        return _FakeResp([] if req.method == "GET" else {"id": 5})
    monkeypatch.setattr(github_pr, "urlopen", fake)
    monkeypatch.setattr(github_pr.time, "sleep", lambda s: None)
    github_pr.post_or_update_pr_comment(PAT, "o/r", 1, "x")
    # urllib capitalizes header names — compare case-insensitively.
    lowered = {k.lower(): v for k, v in seen.items()}
    assert lowered["authorization"] == f"Bearer {PAT}"
    assert lowered["accept"] == "application/vnd.github+json"
    assert lowered["x-github-api-version"] == "2022-11-28"


def test_post_failure_never_leaks_token(monkeypatch):
    from urllib.error import URLError

    def boom(req, timeout=None):
        raise URLError("network down")
    monkeypatch.setattr(github_pr, "urlopen", boom)
    monkeypatch.setattr(github_pr.time, "sleep", lambda s: None)
    with pytest.raises(RuntimeError) as ei:
        github_pr.post_or_update_pr_comment(PAT, "o/r", 1, "x")
    assert PAT not in str(ei.value)


# ---------------------------------------------------------------------------
# Token write-only (HTTP)
# ---------------------------------------------------------------------------

def test_token_write_only(ctx):
    c = TestClient(main.app)
    url = f"https://github.com/testorg/ghpr-tok-{_uid()}"
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "github", "repo_url": url, "github_token": PAT})
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    # Write-only: the raw token is nowhere in the POST response...
    assert PAT not in r.text
    assert "github_token" not in r.json()
    # ...nor in any GET response, which carries the derived flag instead.
    g = c.get(f"/api/vcs/repos/{rid}", headers=_h(ctx["viewer"])).json()
    assert g["pr_comments_enabled"] is True
    assert PAT not in json.dumps(g) and "github_token" not in g
    lst = c.get("/api/vcs/repos", headers=_h(ctx["viewer"])).json()
    row = next(x for x in lst if x["id"] == rid)
    assert row["pr_comments_enabled"] is True
    assert PAT not in json.dumps(lst)
    # ...but it is stored encrypted at rest.
    db = get_db()
    enc = db.execute("SELECT github_token_enc FROM vcs_repos WHERE id=?",
                     (rid,)).fetchone()["github_token_enc"]
    db.close()
    assert enc and enc != PAT
    assert vcs.decrypt_secret(enc) == PAT
    # Bad tokens are rejected on POST...
    for bad in ["nope", "   ", "", None]:
        rb = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
            "provider": "github",
            "repo_url": f"https://github.com/testorg/ghpr-bad-{_uid()}",
            "github_token": bad})
        if bad is None:
            # explicit null = absent: fine
            assert rb.status_code == 200, rb.text
            c.delete(f"/api/vcs/repos/{rb.json()['id']}",
                     headers=_h(ctx["member"]))
        else:
            assert rb.status_code == 400, bad


def test_patch_token(ctx):
    c = TestClient(main.app)
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "github",
        "repo_url": f"https://github.com/testorg/ghpr-patch-{_uid()}"})
    rid = r.json()["id"]
    assert r.json()["pr_comments_enabled"] is False
    # Set the token via PATCH.
    r = c.patch(f"/api/vcs/repos/{rid}", headers=_h(ctx["member"]),
                json={"github_token": PAT2})
    assert r.status_code == 200, r.text
    assert r.json()["pr_comments_enabled"] is True
    assert PAT2 not in r.text and "github_token" not in r.json()
    # Replace it.
    r = c.patch(f"/api/vcs/repos/{rid}", headers=_h(ctx["member"]),
                json={"github_token": PAT})
    assert r.status_code == 200
    db = get_db()
    enc = db.execute("SELECT github_token_enc FROM vcs_repos WHERE id=?",
                     (rid,)).fetchone()["github_token_enc"]
    db.close()
    assert vcs.decrypt_secret(enc) == PAT
    # Invalid tokens rejected.
    assert c.patch(f"/api/vcs/repos/{rid}", headers=_h(ctx["member"]),
                   json={"github_token": "junk"}).status_code == 400
    assert c.patch(f"/api/vcs/repos/{rid}", headers=_h(ctx["member"]),
                   json={"github_token": "  "}).status_code == 400


# ---------------------------------------------------------------------------
# Webhook: pull_request events
# ---------------------------------------------------------------------------

def test_webhook_pr_unknown_repo(ctx):
    c = TestClient(main.app)
    raw = json.dumps(_gh_pr(full_name="stranger/repo")).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": "sha256=" + "0" * 64,
                        "X-GitHub-Event": "pull_request"})
    assert r.status_code == 200 and "unknown" in r.json()["ignored"]


def test_webhook_pr_bad_signature(ctx):
    c = TestClient(main.app)
    url_name = f"testorg/ghpr-badsig-{_uid()}"
    db = get_db()
    rid, secret = _mk_repo(db, ctx["org"],
                           url=f"https://github.com/{url_name}")
    db.close()
    raw = json.dumps(_gh_pr(full_name=url_name)).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": _gh_sig("wrong", raw),
                        "X-GitHub-Event": "pull_request"})
    assert r.status_code == 400


def test_webhook_pr_queues_with_context(ctx, monkeypatch):
    ingested = []
    monkeypatch.setattr("tasks._vcs_ingest_inline",
                        lambda repo_id, sha, **kw: ingested.append(
                            (repo_id, sha, kw.get("pr_number"),
                             kw.get("clone_url"), kw.get("head_ref"))))
    c = TestClient(main.app)
    name = f"testorg/ghpr-pr-{_uid()}"
    url = f"https://github.com/{name}"
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "github", "repo_url": url, "branch": "main",
        "github_token": PAT})
    assert r.status_code == 200, r.text
    rid, secret = r.json()["id"], r.json()["webhook_secret"]

    sha = "d" * 40
    fork = "https://github.com/contrib/ghpr-pr.git"
    raw = json.dumps(_gh_pr(full_name=name, pr_number=42, head_sha=sha,
                            fork=fork)).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": _gh_sig(secret, raw),
                        "X-GitHub-Event": "pull_request"})
    assert r.status_code == 202, r.text
    assert r.json()["pr_number"] == 42
    assert ingested == [(rid, sha, 42, fork, "feature")]

    # PR against an unwatched base branch is ignored.
    raw = json.dumps(_gh_pr(full_name=name, pr_number=43, base="develop",
                            head_sha="e" * 40)).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": _gh_sig(secret, raw),
                        "X-GitHub-Event": "pull_request"})
    assert r.status_code == 200 and "not watched" in r.json()["ignored"]
    assert len(ingested) == 1


# ---------------------------------------------------------------------------
# Ingest: PR head clone + pr_scans row
# ---------------------------------------------------------------------------

def test_pr_ingest_records_pr_scan(ctx, monkeypatch):
    calls = {}

    def fake_clone(url, branch, sha, dest, timeout=300):
        calls.update(url=url, branch=branch, sha=sha)
        os.makedirs(dest, exist_ok=True)
        return sha
    monkeypatch.setattr(vcs, "clone_repo", fake_clone)

    created = {}

    def fake_new_scan(org_id, target_name, dest, workdir, *a, **k):
        created["target_name"] = target_name
        db = get_db()
        db.execute(
            "INSERT INTO scans (id, org_id, target_name, status, created_at,"
            " total_findings, target_dir, vcs_repo_id, commit_sha)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (k["scan_id"], org_id, target_name, "done",
             "2026-10-01T00:00:00+00:00", 0, dest, k["vcs_repo_id"],
             k["commit_sha"]))
        db.commit()
        db.close()
    monkeypatch.setattr(main, "_new_scan", fake_new_scan)

    db = get_db()
    rid, _ = _mk_repo(db, ctx["org"])
    db.close()
    sha = "f" * 40
    fork = "https://github.com/contrib/ghpr-fork"
    res = vcs._ingest_vcs_push(rid, sha, pr_number=12, clone_url=fork,
                               head_ref="feature")
    assert res["ingested"] is True
    # The fork URL and the PR head branch were used for the clone.
    assert calls["url"] == fork and calls["branch"] == "feature"
    assert "#pr12" in created["target_name"]
    db = get_db()
    row = db.execute("SELECT * FROM pr_scans WHERE scan_id=?",
                     (res["scan_id"],)).fetchone()
    db.close()
    assert row is not None
    assert row["repo_id"] == rid and row["pr_number"] == 12
    assert row["head_sha"] == sha and row["comment_id"] is None


def test_push_ingest_records_no_pr_scan(ctx, monkeypatch):
    """Plain pushes keep the old behaviour: no pr_scans row."""
    monkeypatch.setattr(vcs, "clone_repo",
                        lambda url, branch, sha, dest, timeout=300: sha)
    monkeypatch.setattr(main, "_new_scan", lambda *a, **k: None)
    db = get_db()
    rid, _ = _mk_repo(db, ctx["org"])
    db.close()
    res = vcs._ingest_vcs_push(rid, "0" * 39 + "1")
    assert res["ingested"] is True
    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM pr_scans").fetchone()["c"]
    db.close()
    assert n == 0


# ---------------------------------------------------------------------------
# maybe_post_pr_comment
# ---------------------------------------------------------------------------

def _mock_gh(monkeypatch, comments=None, post_id=999):
    calls = []
    monkeypatch.setattr(github_pr, "urlopen",
                        _fake_urlopen_factory(calls, comments or [], post_id))
    monkeypatch.setattr(github_pr.time, "sleep", lambda s: None)
    return calls


def test_maybe_post_happy_path(ctx, monkeypatch):
    calls = _mock_gh(monkeypatch)
    db = get_db()
    rid, _ = _mk_repo(db, ctx["org"], token=PAT)
    sid = "scan" + _uid()
    _mk_scan(db, ctx["org"], sid, "done", repo_id=rid, sha="a" * 40)
    _mk_finding(db, sid, "error", "sql-injection", "api/auth.py", 42,
                "raw SQL")
    _mk_finding(db, sid, "warning", "xss", "web/app.js", 7, "unescaped")
    _mk_pr_scan(db, sid, rid, 7, "a" * 40)
    db.close()
    out = github_pr.maybe_post_pr_comment(sid)
    assert out == {"posted": True, "comment_id": 999, "pr": 7}
    assert [m for m, _, _ in calls] == ["GET", "POST"]
    _, _, body = calls[1]
    assert github_pr.PR_COMMENT_MARKER in body["body"]
    assert "api/auth.py:42" in body["body"]
    db = get_db()
    cid = db.execute("SELECT comment_id FROM pr_scans WHERE scan_id=?",
                     (sid,)).fetchone()["comment_id"]
    db.close()
    assert cid == 999


def test_maybe_post_updates_existing_comment(ctx, monkeypatch):
    calls = _mock_gh(monkeypatch,
                     comments=[{"id": 555,
                                "body": github_pr.PR_COMMENT_MARKER}])
    db = get_db()
    rid, _ = _mk_repo(db, ctx["org"], token=PAT)
    sid = "scan" + _uid()
    _mk_scan(db, ctx["org"], sid, "done", repo_id=rid, sha="a" * 40)
    _mk_pr_scan(db, sid, rid, 9, "a" * 40)
    db.close()
    out = github_pr.maybe_post_pr_comment(sid)
    assert out["posted"] is True and out["comment_id"] == 555
    assert [m for m, _, _ in calls] == ["GET", "PATCH"]


def test_maybe_post_failed_scan(ctx, monkeypatch):
    calls = _mock_gh(monkeypatch)
    db = get_db()
    rid, _ = _mk_repo(db, ctx["org"], token=PAT)
    sid = "scan" + _uid()
    _mk_scan(db, ctx["org"], sid, "failed", repo_id=rid, sha="a" * 40,
             error="engines unavailable")
    _mk_pr_scan(db, sid, rid, 3, "a" * 40)
    db.close()
    out = github_pr.maybe_post_pr_comment(sid)
    assert out["posted"] is True
    _, _, body = calls[1]
    assert "Scan failed" in body["body"]


def test_maybe_post_noops(ctx):
    db = get_db()
    rid, _ = _mk_repo(db, ctx["org"], token=PAT)
    sid = "scan" + _uid()
    _mk_scan(db, ctx["org"], sid, "done", repo_id=rid, sha="a" * 40)
    db.close()
    # Not a PR scan: no pr_scans row.
    assert github_pr.maybe_post_pr_comment(sid) == {
        "posted": False, "reason": "not a PR scan"}
    # PR scan but the scan is still running.
    db = get_db()
    _mk_pr_scan(db, sid, rid, 4, "a" * 40)
    db.execute("UPDATE scans SET status='running' WHERE id=?", (sid,))
    db.commit()
    db.close()
    out = github_pr.maybe_post_pr_comment(sid)
    assert out["posted"] is False and "running" in out["reason"]


def test_maybe_post_no_token(ctx):
    db = get_db()
    rid, _ = _mk_repo(db, ctx["org"])  # no token
    sid = "scan" + _uid()
    _mk_scan(db, ctx["org"], sid, "done", repo_id=rid, sha="a" * 40)
    _mk_pr_scan(db, sid, rid, 5, "a" * 40)
    db.close()
    assert github_pr.maybe_post_pr_comment(sid) == {
        "posted": False, "reason": "no github token"}


def test_maybe_post_never_raises(ctx, monkeypatch):
    """A GitHub outage must not break the scan terminal hook."""
    from urllib.error import URLError

    def boom(req, timeout=None):
        raise URLError("github is down")
    monkeypatch.setattr(github_pr, "urlopen", boom)
    monkeypatch.setattr(github_pr.time, "sleep", lambda s: None)
    db = get_db()
    rid, _ = _mk_repo(db, ctx["org"], token=PAT)
    sid = "scan" + _uid()
    _mk_scan(db, ctx["org"], sid, "done", repo_id=rid, sha="a" * 40)
    _mk_pr_scan(db, sid, rid, 6, "a" * 40)
    db.close()
    out = github_pr.maybe_post_pr_comment(sid)
    assert out["posted"] is False
