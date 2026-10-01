"""Tests for the VCS integration (scan on push: GitHub / GitLab).

- pure logic: webhook signature/token verification, push payload parsing,
  repo URL validation (strict SSRF), secret encrypt/decrypt round-trip
- HTTP: repo CRUD + RBAC + validation, public webhook receivers
  (valid/forged/missing signature, non-push ignored, branch filtering)
- ingest: verified push -> clone (mocked) -> real scan -> scan row linked
- alerts: evaluate_vcs_alerts diffs new vs previous push-scan and notifies
  (first run = silent baseline; failures alert loudly)
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
_tmp = tempfile.mkdtemp(prefix="braimsec-test-vcs-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-vcs-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import scheduler  # noqa: E402
import tasks  # noqa: E402
import vcs  # noqa: E402
from billing import create_org, ensure_owner_org, provision_key, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()
MASTER = os.environ["BRAIMSEC_API_KEY"]
WEBHOOK = "https://hooks.test/services/vcs"  # .test: no DNS, passes SSRF check


def _uid():
    import uuid as _u
    return _u.uuid4().hex[:8]


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    # The sandbox DNS hijacks github.com to a blocked range; the DNS layer
    # itself is covered by ssrf_guard's tests. Neutralize it here.
    monkeypatch.setattr(vcs, "_resolve_checked", lambda host: [])


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(scheduler.time, "sleep", lambda s: None)


@pytest.fixture()
def _mock_engines(monkeypatch):
    monkeypatch.setattr(tasks, "run_semgrep", lambda d, scope=None: [])
    monkeypatch.setattr(tasks, "run_gitleaks", lambda d, scope=None: [])
    monkeypatch.setattr(tasks, "run_sca", lambda d, scope=None: [])
    monkeypatch.setattr(tasks.time, "sleep", lambda s: None)


@pytest.fixture()
def ctx():
    ensure_owner_org()
    org = create_org("VcsTestCo", plan="free")
    other = create_org("VcsOtherCo", plan="free")
    admin = provision_key(org, "v-admin", actor="owner", role="admin")
    member = provision_key(org, "v-member", actor="owner", role="member")
    viewer = provision_key(org, "v-viewer", actor="owner", role="viewer")
    o_member = provision_key(other, "o-member", actor="owner", role="member")
    return {"org": org, "admin": admin, "member": member, "viewer": viewer,
            "o_member": o_member}


def _h(key):
    return {"X-API-Key": key}


def _repo_url(uid=None):
    return f"https://github.com/testorg/vcs-{uid or _uid()}"


def _mk_repo(db, org, provider="github", branch="main", enabled=1,
             url=None, webhook_url=WEBHOOK, severity="warning"):
    url = url or _repo_url()
    rid = "repo_" + _uid()
    secret = vcs.generate_webhook_secret()
    db.execute(
        "INSERT INTO vcs_repos (id, org_id, provider, repo_url, full_name,"
        " branch, webhook_secret_hash, webhook_secret_enc, webhook_url,"
        " alert_severity, enabled, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (rid, org, provider, vcs.validate_repo_url(url),
         "/".join(url.split("/")[3:]), branch, vcs.hash_secret(secret),
         vcs.encrypt_secret(secret) if provider == "github" else None,
         webhook_url, severity, enabled, "2026-10-01T00:00:00+00:00"))
    db.commit()
    return rid, secret, url


def _mk_scan(db, org, scan_id, status, findings, repo_id=None, sha=None):
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " total_findings, target_dir, vcs_repo_id, commit_sha)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (scan_id, org, "api", status, "2026-10-01T00:00:00+00:00",
         len(findings), "/x", repo_id, sha))
    for f in findings:
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, f["tool"], f["rule_id"], f["severity"], f["message"],
             f["file"], f["line"], 1))
    db.commit()


def _gh_sig(secret, raw: bytes):
    return "sha256=" + hmac.new(secret.encode(), raw,
                                hashlib.sha256).hexdigest()


def _gh_push(full_name="testorg/vcs-x", branch="main",
             sha="a" * 40, clone_url=None):
    return {
        "ref": f"refs/heads/{branch}",
        "after": sha,
        "repository": {
            "full_name": full_name,
            "clone_url": clone_url or f"https://github.com/{full_name}.git",
        },
    }


def _gl_push(path="testorg/vcs-x", branch="main", sha="b" * 40):
    return {
        "object_kind": "push",
        "ref": f"refs/heads/{branch}",
        "after": sha,
        "checkout_sha": sha,
        "project": {
            "path_with_namespace": path,
            "git_http_url": f"https://gitlab.com/{path}.git",
        },
    }


# ---------------------------------------------------------------------------
# Signature / token verification (pure)
# ---------------------------------------------------------------------------

def test_github_signature_valid():
    secret = vcs.generate_webhook_secret()
    raw = b'{"ref":"refs/heads/main"}'
    assert vcs.verify_github_signature(raw, _gh_sig(secret, raw), secret)


def test_github_signature_rejects_tampered_body():
    secret = vcs.generate_webhook_secret()
    raw = b'{"ref":"refs/heads/main"}'
    sig = _gh_sig(secret, raw)
    assert not vcs.verify_github_signature(b'{"ref":"refs/heads/evil"}',
                                           sig, secret)


def test_github_signature_rejects_wrong_secret():
    raw = b"{}"
    sig = _gh_sig("secret-one", raw)
    assert not vcs.verify_github_signature(raw, sig, "secret-two")


@pytest.mark.parametrize("header", [None, "", "sha1=abc123",
                                   "sha256=not-hex!!", "sha256=abcd"])
def test_github_signature_rejects_missing_or_malformed(header):
    assert not vcs.verify_github_signature(b"{}", header, "s3cret")


def test_gitlab_token_valid():
    secret = vcs.generate_webhook_secret()
    assert vcs.verify_gitlab_token(secret, vcs.hash_secret(secret))


def test_gitlab_token_rejects_wrong_or_missing():
    secret = vcs.generate_webhook_secret()
    assert not vcs.verify_gitlab_token("wrong", vcs.hash_secret(secret))
    assert not vcs.verify_gitlab_token(None, vcs.hash_secret(secret))
    assert not vcs.verify_gitlab_token(secret, "")


def test_secret_encrypt_decrypt_roundtrip():
    secret = vcs.generate_webhook_secret()
    enc = vcs.encrypt_secret(secret)
    assert enc != secret  # not stored in the clear
    assert vcs.decrypt_secret(enc) == secret
    # ...and the decrypted secret verifies a real GitHub HMAC.
    raw = b'{"a":1}'
    assert vcs.verify_github_signature(raw, _gh_sig(secret, raw),
                                       vcs.decrypt_secret(enc))


# ---------------------------------------------------------------------------
# Push payload parsing (pure)
# ---------------------------------------------------------------------------

def test_parse_github_push_ok():
    p = vcs.parse_github_push(_gh_push(), "push")
    assert p["type"] == "push" and p["branch"] == "main"
    assert p["sha"] == "a" * 40 and p["full_name"] == "testorg/vcs-x"


def test_parse_github_ping():
    p = vcs.parse_github_push(
        {"repository": {"clone_url": "https://github.com/o/r.git"}}, "ping")
    assert p["type"] == "ping"
    assert p["clone_url"] == "https://github.com/o/r.git"


def test_parse_github_ping_no_repo():
    assert vcs.parse_github_push({}, "ping")["type"] == "ping"


@pytest.mark.parametrize("event", ["issues", "pull_request", "release", ""])
def test_parse_github_ignores_non_push_events(event):
    assert vcs.parse_github_push(_gh_push(), event) is None


def test_parse_github_ignores_branch_deletion():
    p = _gh_push()
    p["deleted"] = True
    p["after"] = "0" * 40
    assert vcs.parse_github_push(p, "push")["type"] == "ignore"


def test_parse_github_ignores_tag_push():
    p = _gh_push()
    p["ref"] = "refs/tags/v1.0"
    assert vcs.parse_github_push(p, "push")["type"] == "ignore"


def test_parse_gitlab_push_ok():
    p = vcs.parse_gitlab_push(_gl_push(), "Push Hook")
    assert p["type"] == "push" and p["branch"] == "main"
    assert p["sha"] == "b" * 40


@pytest.mark.parametrize("header", [None, "Tag Push Hook", "Merge Request Hook"])
def test_parse_gitlab_ignores_non_push(header):
    assert vcs.parse_gitlab_push(_gl_push(), header) is None


def test_parse_gitlab_ignores_branch_deletion():
    p = _gl_push()
    p["after"] = "0" * 40
    assert vcs.parse_gitlab_push(p, "Push Hook")["type"] == "ignore"


# ---------------------------------------------------------------------------
# Repo URL validation: strict SSRF
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://github.com/o/r",                    # https only
    "https://user:pass@github.com/o/r",         # no credentials
    "https://github.com:8443/o/r",              # no ports
    "https://evil.com/o/r",                     # allowlist
    "https://github.com.evil.com/o/r",          # subdomain trick
    "https://127.0.0.1/o/r",                    # loopback
    "https://169.254.169.254/o/r",              # cloud metadata
    "https://github.com/",                      # missing path
    "https://github.com/o/r?x=1",               # no query
    "https://github.com/o/r#frag",              # no fragment
    "https://github.com/o/r/<script>",          # bad chars
    "not a url",
    "",
])
def test_repo_url_rejects_bad(url):
    with pytest.raises(ValueError):
        vcs.validate_repo_url(url)


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/Org/Repo", "https://github.com/Org/Repo"),
    ("https://github.com/org/repo/", "https://github.com/org/repo"),
    ("https://github.com/org/repo.git", "https://github.com/org/repo"),
    ("https://GitHub.COM/org/repo", "https://github.com/org/repo"),
    ("https://gitlab.com/group/sub/repo", "https://gitlab.com/group/sub/repo"),
])
def test_repo_url_normalizes(url, expected):
    assert vcs.validate_repo_url(url) == expected


def test_repo_url_rejects_blocked_dns(monkeypatch):
    def blocked(host):
        raise ValueError("webhook_url resolves to a blocked"
                         " (private/internal) address")
    monkeypatch.setattr(vcs, "_resolve_checked", blocked)
    with pytest.raises(ValueError, match="blocked"):
        vcs.validate_repo_url("https://github.com/o/r")


def test_repo_url_tolerates_transient_dns(monkeypatch):
    def flaky(host):
        raise ValueError("webhook_url does not resolve: temporary")
    monkeypatch.setattr(vcs, "_resolve_checked", flaky)
    assert vcs.validate_repo_url("https://github.com/o/r") == \
        "https://github.com/o/r"


def test_repo_url_allowlist_configurable(monkeypatch):
    monkeypatch.setenv("BRAIMSEC_VCS_HOSTS", "git.example.com")
    with pytest.raises(ValueError, match="not allowed"):
        vcs.validate_repo_url("https://github.com/o/r")
    assert vcs.validate_repo_url("https://git.example.com/o/r") == \
        "https://git.example.com/o/r"


@pytest.mark.parametrize("branch", ["", "x" * 101, "main;rm", "feat/a b"])
def test_branch_validation_rejects(branch):
    with pytest.raises(ValueError):
        vcs.validate_branch(branch)


def test_branch_validation_accepts():
    assert vcs.validate_branch("feature/my-branch_1.2") == "feature/my-branch_1.2"


# ---------------------------------------------------------------------------
# Repo CRUD over HTTP
# ---------------------------------------------------------------------------

def test_register_repo_returns_secret_once(ctx):
    c = TestClient(main.app)
    url = _repo_url()
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "github", "repo_url": url, "branch": "main",
        "alert_severity": "warning", "webhook_url": WEBHOOK})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["repo_url"] == url
    assert body["full_name"] == "testorg/" + url.rsplit("/", 1)[1]
    assert len(body["webhook_secret"]) == 64
    assert body["receiver_url"].endswith("/api/webhooks/github")
    assert "never be shown again" in body["warning"]

    # The secret is never exposed again...
    r2 = c.get("/api/vcs/repos", headers=_h(ctx["member"]))
    assert r2.status_code == 200
    mine = [x for x in r2.json() if x["id"] == body["id"]]
    assert len(mine) == 1
    assert "webhook_secret" not in mine[0]
    assert "webhook_secret_hash" not in mine[0]
    assert "webhook_secret_enc" not in mine[0]

    # ...and registering the same URL twice is a 409.
    r3 = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "github", "repo_url": url, "branch": "main",
        "webhook_url": WEBHOOK})
    assert r3.status_code == 409


def test_register_repo_gitlab_no_encrypted_secret(ctx):
    c = TestClient(main.app)
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "gitlab",
        "repo_url": f"https://gitlab.com/g1/g2/repo-{_uid()}",
        "branch": "develop", "webhook_url": WEBHOOK})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["provider"] == "gitlab"
    assert body["receiver_url"].endswith("/api/webhooks/gitlab")
    db = get_db()
    row = db.execute("SELECT webhook_secret_hash, webhook_secret_enc"
                     " FROM vcs_repos WHERE id=?", (body["id"],)).fetchone()
    db.close()
    assert len(row["webhook_secret_hash"]) == 64
    assert row["webhook_secret_enc"] is None  # token verified by hash only


@pytest.mark.parametrize("payload,why", [
    ({"provider": "bitbucket", "repo_url": "https://github.com/o/r",
      "webhook_url": WEBHOOK}, "bad provider"),
    ({"provider": "github", "repo_url": "https://evil.com/o/r",
      "webhook_url": WEBHOOK}, "SSRF host"),
    ({"provider": "github", "repo_url": "http://github.com/o/r",
      "webhook_url": WEBHOOK}, "http scheme"),
    ({"provider": "github", "repo_url": "https://github.com/o/r",
      "branch": "no spaces", "webhook_url": WEBHOOK}, "bad branch"),
    ({"provider": "github", "repo_url": "https://github.com/o/r",
      "alert_severity": "critical", "webhook_url": WEBHOOK}, "bad severity"),
    ({"provider": "github", "repo_url": "https://github.com/o/r",
      "webhook_url": "https://evil.com/hook"}, "bad webhook"),
])
def test_register_repo_validation(ctx, payload, why):
    c = TestClient(main.app)
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json=payload)
    assert r.status_code == 400, why


def test_register_repo_without_webhook_is_email_only(ctx):
    """Missing webhook_url no longer 400s: the repo is email-only."""
    c = TestClient(main.app)
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]),
               json={"provider": "github",
                     "repo_url": "https://github.com/o/r"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["webhook_url"] == ""
    # cleanup so later tests see a pristine repo list
    rr = c.delete(f"/api/vcs/repos/{body['id']}",
                  headers=_h(ctx["member"]))
    assert rr.status_code == 200


def test_repo_rbac(ctx):
    c = TestClient(main.app)
    url = _repo_url()
    # viewer cannot register
    r = c.post("/api/vcs/repos", headers=_h(ctx["viewer"]), json={
        "provider": "github", "repo_url": url, "webhook_url": WEBHOOK})
    assert r.status_code == 403
    # member can
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "github", "repo_url": url, "webhook_url": WEBHOOK})
    assert r.status_code == 200
    rid = r.json()["id"]
    # other org: invisible
    assert c.get(f"/api/vcs/repos/{rid}",
                 headers=_h(ctx["o_member"])).status_code == 404
    assert c.get("/api/vcs/repos", headers=_h(ctx["o_member"])).json() == []
    # viewer can read, member can patch/delete
    assert c.get(f"/api/vcs/repos/{rid}",
                 headers=_h(ctx["viewer"])).status_code == 200
    assert c.patch(f"/api/vcs/repos/{rid}", headers=_h(ctx["viewer"]),
                   json={"enabled": False}).status_code == 403
    r = c.patch(f"/api/vcs/repos/{rid}", headers=_h(ctx["member"]),
                json={"branch": "develop", "alert_severity": "error",
                      "enabled": False})
    assert r.status_code == 200
    assert (r.json()["branch"], r.json()["alert_severity"],
            r.json()["enabled"]) == ("develop", "error", False)
    assert c.delete(f"/api/vcs/repos/{rid}",
                    headers=_h(ctx["viewer"])).status_code == 403
    assert c.delete(f"/api/vcs/repos/{rid}",
                    headers=_h(ctx["member"])).status_code == 200
    assert c.get(f"/api/vcs/repos/{rid}",
                 headers=_h(ctx["member"])).status_code == 404


def test_rotate_secret(ctx):
    c = TestClient(main.app)
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "github", "repo_url": _repo_url(),
        "webhook_url": WEBHOOK})
    rid, old_secret = r.json()["id"], r.json()["webhook_secret"]
    r = c.post(f"/api/vcs/repos/{rid}/rotate-secret",
               headers=_h(ctx["member"]))
    assert r.status_code == 200
    new_secret = r.json()["webhook_secret"]
    assert new_secret != old_secret
    db = get_db()
    row = db.execute("SELECT webhook_secret_hash FROM vcs_repos WHERE id=?",
                     (rid,)).fetchone()
    db.close()
    assert row["webhook_secret_hash"] == vcs.hash_secret(new_secret)


# ---------------------------------------------------------------------------
# Public webhook receivers
# ---------------------------------------------------------------------------

def _register(c, ctx, provider="github", branch="main", url=None):
    url = url or _repo_url()
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": provider, "repo_url": url, "branch": branch,
        "webhook_url": WEBHOOK})
    assert r.status_code == 200, r.text
    return r.json()["id"], r.json()["webhook_secret"], url


def test_github_webhook_verifies_and_routes(ctx, monkeypatch):
    # Never clone for real in webhook unit tests.
    monkeypatch.setattr(vcs, "clone_repo",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("clone must not run here")))
    ingested = []
    monkeypatch.setattr("tasks._vcs_ingest_inline",
                        lambda repo_id, sha: ingested.append((repo_id, sha)))
    c = TestClient(main.app)
    rid, secret, url = _register(c, ctx)
    name = url.split("github.com/")[1]

    payload = _gh_push(full_name=name)
    raw = json.dumps(payload).encode()
    # Push event but no signature at all -> 400
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-GitHub-Event": "push"})
    assert r.status_code == 400
    # Forged signature -> 400
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": _gh_sig("wrong", raw),
                        "X-GitHub-Event": "push"})
    assert r.status_code == 400
    # Valid signature, wrong branch -> ignored
    other = dict(payload, ref="refs/heads/feature")
    raw2 = json.dumps(other).encode()
    r = c.post("/api/webhooks/github", content=raw2,
               headers={"X-Hub-Signature-256": _gh_sig(secret, raw2),
                        "X-GitHub-Event": "push"})
    assert r.status_code == 200 and "not watched" in r.json()["ignored"]
    assert ingested == []
    # Valid signature, watched branch -> 202 queued
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": _gh_sig(secret, raw),
                        "X-GitHub-Event": "push"})
    assert r.status_code == 202 and r.json()["queued"] is True
    assert ingested == [(rid, "a" * 40)]


def test_github_webhook_ignores_noise(ctx):
    c = TestClient(main.app)
    rid, secret, url = _register(c, ctx)
    name = url.split("github.com/")[1]
    # ping with a valid signature -> pong
    raw = json.dumps({"zen": "hi", "repository": {
        "clone_url": f"https://github.com/{name}.git"}}).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": _gh_sig(secret, raw),
                        "X-GitHub-Event": "ping"})
    assert r.status_code == 200 and r.json().get("pong") is True
    # non-push event -> ignored (no signature needed to ignore safely)
    raw = json.dumps(_gh_push(full_name=name)).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-GitHub-Event": "issues"})
    assert r.status_code == 200 and r.json()["ignored"] == "not a push event"
    # branch deletion -> ignored
    p = _gh_push(full_name=name)
    p["deleted"] = True
    p["after"] = "0" * 40
    raw = json.dumps(p).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": _gh_sig(secret, raw),
                        "X-GitHub-Event": "push"})
    assert r.status_code == 200 and "deleted" in r.json()["ignored"]
    # unknown repo (valid JSON, bad signature irrelevant) -> ignored
    raw = json.dumps(_gh_push(full_name="stranger/repo")).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": "sha256=" + "0" * 64,
                        "X-GitHub-Event": "push"})
    assert r.status_code == 200 and "unknown" in r.json()["ignored"]
    # malformed JSON -> 400
    r = c.post("/api/webhooks/github", content=b"not json",
               headers={"X-GitHub-Event": "push"})
    assert r.status_code == 400


def test_github_webhook_same_repo_two_orgs(ctx, monkeypatch):
    """The same public repo registered by two orgs: each push verifies
    against its own org's secret."""
    ingested = []
    monkeypatch.setattr("tasks._vcs_ingest_inline",
                        lambda repo_id, sha: ingested.append((repo_id, sha)))
    c = TestClient(main.app)
    url = _repo_url()
    name = url.split("github.com/")[1]
    r1 = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "github", "repo_url": url, "webhook_url": WEBHOOK})
    r2 = c.post("/api/vcs/repos", headers=_h(ctx["o_member"]), json={
        "provider": "github", "repo_url": url, "webhook_url": WEBHOOK})
    assert r1.status_code == 200 and r2.status_code == 200
    rid1, s1 = r1.json()["id"], r1.json()["webhook_secret"]
    rid2, s2 = r2.json()["id"], r2.json()["webhook_secret"]
    assert s1 != s2

    def push(secret):
        raw = json.dumps(_gh_push(full_name=name, sha="f" * 40)).encode()
        return c.post("/api/webhooks/github", content=raw,
                      headers={"X-Hub-Signature-256": _gh_sig(secret, raw),
                               "X-GitHub-Event": "push"})

    # Org 1's secret routes to org 1's repo...
    assert push(s1).status_code == 202
    # ...org 2's secret routes to org 2's repo (same commit sha is fine:
    # dedup is per repo row).
    assert push(s2).status_code == 202
    assert sorted(i[0] for i in ingested) == sorted([rid1, rid2])
    # A stranger's signature verifies against neither.
    assert push("0" * 64).status_code == 400


def test_github_webhook_respects_disabled(ctx, monkeypatch):
    monkeypatch.setattr("tasks._vcs_ingest_inline",
                        lambda *a: (_ for _ in ()).throw(
                            AssertionError("must not ingest")))
    c = TestClient(main.app)
    rid, secret, url = _register(c, ctx)
    name = url.split("github.com/")[1]
    c.patch(f"/api/vcs/repos/{rid}", headers=_h(ctx["member"]),
            json={"enabled": False})
    raw = json.dumps(_gh_push(full_name=name)).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": _gh_sig(secret, raw),
                        "X-GitHub-Event": "push"})
    assert r.status_code == 200 and "disabled" in r.json()["ignored"]


def test_gitlab_webhook_verifies_and_routes(ctx, monkeypatch):
    ingested = []
    monkeypatch.setattr("tasks._vcs_ingest_inline",
                        lambda repo_id, sha: ingested.append((repo_id, sha)))
    c = TestClient(main.app)
    url = f"https://gitlab.com/g1/repo-{_uid()}"
    r = c.post("/api/vcs/repos", headers=_h(ctx["member"]), json={
        "provider": "gitlab", "repo_url": url, "branch": "main",
        "webhook_url": WEBHOOK})
    assert r.status_code == 200, r.text
    rid, secret = r.json()["id"], r.json()["webhook_secret"]
    path = url.split("gitlab.com/")[1]

    payload = _gl_push(path=path)
    raw = json.dumps(payload).encode()
    # Wrong token -> 400
    r = c.post("/api/webhooks/gitlab", content=raw,
               headers={"X-Gitlab-Token": "wrong",
                        "X-Gitlab-Event": "Push Hook"})
    assert r.status_code == 400
    # Missing token -> 400
    r = c.post("/api/webhooks/gitlab", content=raw,
               headers={"X-Gitlab-Event": "Push Hook"})
    assert r.status_code == 400
    # Right token -> 202
    r = c.post("/api/webhooks/gitlab", content=raw,
               headers={"X-Gitlab-Token": secret,
                        "X-Gitlab-Event": "Push Hook"})
    assert r.status_code == 202 and r.json()["queued"] is True
    assert ingested == [(rid, "b" * 40)]
    # Tag push hook -> ignored
    r = c.post("/api/webhooks/gitlab", content=raw,
               headers={"X-Gitlab-Token": secret,
                        "X-Gitlab-Event": "Tag Push Hook"})
    assert r.status_code == 200 and r.json()["ignored"] == "not a push event"


# ---------------------------------------------------------------------------
# Ingest: push -> clone -> scan (end to end, engines mocked)
# ---------------------------------------------------------------------------

def test_ingest_end_to_end_with_alert(ctx, _mock_engines, monkeypatch):
    captured = []
    monkeypatch.setattr(
        vcs, "send_alert",
        lambda url, payload, org_id=None: captured.append((url, payload)) or (True, 1, 200, None))

    findings_now = []

    def fake_clone(repo_url, branch, sha, dest_dir, timeout=300):
        os.makedirs(dest_dir, exist_ok=True)
        with open(os.path.join(dest_dir, "app.py"), "w") as f:
            f.write("x = 1\n")
        return sha

    monkeypatch.setattr(vcs, "clone_repo", fake_clone)
    monkeypatch.setattr(tasks, "run_semgrep",
                        lambda d, scope=None: [dict(f) for f in findings_now])

    c = TestClient(main.app)
    rid, secret, url = _register(c, ctx)
    name = url.split("github.com/")[1]

    def push(sha):
        raw = json.dumps(_gh_push(full_name=name, sha=sha)).encode()
        return c.post("/api/webhooks/github", content=raw,
                      headers={"X-Hub-Signature-256": _gh_sig(secret, raw),
                               "X-GitHub-Event": "push"})

    # Push 1: clean tree -> scan created & linked, no alert (baseline).
    r = push("c" * 40)
    assert r.status_code == 202, r.text
    db = get_db()
    scan1 = db.execute("SELECT * FROM scans WHERE vcs_repo_id=?",
                       (rid,)).fetchone()
    assert scan1 is not None and scan1["status"] == "done"
    assert scan1["commit_sha"] == "c" * 40
    repo = db.execute("SELECT last_scan_id, prev_scan_id FROM vcs_repos"
                      " WHERE id=?", (rid,)).fetchone()
    assert repo["last_scan_id"] == scan1["id"] and repo["prev_scan_id"] is None
    db.close()
    assert captured == []

    # Same commit pushed again -> deduped, no second scan.
    r = push("c" * 40)
    assert r.status_code == 200 and r.json().get("deduped") is True
    db = get_db()
    n_scans = db.execute("SELECT COUNT(*) c FROM scans WHERE vcs_repo_id=?",
                         (rid,)).fetchone()["c"]
    db.close()
    assert n_scans == 1

    # Push 2: a new error-severity finding appears -> alert fires.
    findings_now.append({"tool": "semgrep", "rule_id": "r.vcs",
                         "severity": "error", "message": "vcs vuln",
                         "file": "app.py", "line": 1, "col": 1})
    r = push("d" * 40)
    assert r.status_code == 202, r.text
    assert len(captured) == 1
    url_sent, payload = captured[0]
    assert url_sent == WEBHOOK
    assert payload["event"] == "vcs.alert"
    assert payload["new_count"] == 1
    assert payload["highest_severity"] == "error"
    assert payload["repo"] == name
    assert payload["commit"] == "d" * 40

    db = get_db()
    n = db.execute("SELECT status, event, new_count, vcs_repo_id,"
                   " schedule_id FROM notifications"
                   " WHERE vcs_repo_id=?", (rid,)).fetchone()
    repo = db.execute("SELECT last_scan_id, prev_scan_id FROM vcs_repos"
                      " WHERE id=?", (rid,)).fetchone()
    db.close()
    assert (n["status"], n["event"], n["new_count"],
            n["schedule_id"]) == ("sent", "vcs.alert", 1, None)
    assert repo["prev_scan_id"] == scan1["id"]
    assert repo["last_scan_id"] != scan1["id"]


def test_ingest_clone_failure_recorded(ctx, monkeypatch):
    monkeypatch.setattr(vcs, "clone_repo",
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("network down")))
    c = TestClient(main.app)
    rid, secret, url = _register(c, ctx)
    name = url.split("github.com/")[1]
    raw = json.dumps(_gh_push(full_name=name, sha="e" * 40)).encode()
    r = c.post("/api/webhooks/github", content=raw,
               headers={"X-Hub-Signature-256": _gh_sig(secret, raw),
                        "X-GitHub-Event": "push"})
    assert r.status_code == 202
    db = get_db()
    repo = db.execute("SELECT last_error, last_scan_id FROM vcs_repos"
                      " WHERE id=?", (rid,)).fetchone()
    n_scans = db.execute("SELECT COUNT(*) c FROM scans WHERE vcs_repo_id=?",
                         (rid,)).fetchone()["c"]
    db.close()
    assert n_scans == 0 and "clone failed" in (repo["last_error"] or "")
    assert repo["last_scan_id"] is None


# ---------------------------------------------------------------------------
# evaluate_vcs_alerts (direct, deterministic)
# ---------------------------------------------------------------------------

def test_vcs_alert_first_run_is_silent(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        vcs, "send_alert",
        lambda url, payload, org_id=None: captured.append(payload) or (True, 1, 200, None))
    db = get_db()
    rid, _, _ = _mk_repo(db, ctx["org"])
    sn = "vscan_first_" + _uid()
    _mk_scan(db, ctx["org"], sn, "done",
             [{"tool": "semgrep", "rule_id": "r.a", "severity": "error",
               "message": "m", "file": "a.py", "line": 1}],
             repo_id=rid, sha="f" * 40)
    db.execute("UPDATE vcs_repos SET last_scan_id=? WHERE id=?", (sn, rid))
    db.commit()
    db.close()
    out = vcs.evaluate_vcs_alerts(sn)
    assert out["alerted"] is False
    assert out["reason"] == "first run: baseline set"
    assert captured == []


def test_vcs_alert_respects_threshold_and_suppression(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        vcs, "send_alert",
        lambda url, payload, org_id=None: captured.append(payload) or (True, 1, 200, None))
    db = get_db()
    rid, _, _ = _mk_repo(db, ctx["org"], severity="error")  # errors only
    old = [{"tool": "semgrep", "rule_id": "r.a", "severity": "warning",
            "message": "old", "file": "a.py", "line": 1}]
    new = old + [{"tool": "semgrep", "rule_id": "r.b", "severity": "warning",
                  "message": "below threshold", "file": "b.py", "line": 2}]
    so, sn = "vscan_o_" + _uid(), "vscan_n_" + _uid()
    _mk_scan(db, ctx["org"], so, "done", old, repo_id=rid, sha="1" * 40)
    _mk_scan(db, ctx["org"], sn, "done", new, repo_id=rid, sha="2" * 40)
    db.execute("UPDATE vcs_repos SET last_scan_id=?, prev_scan_id=?"
               " WHERE id=?", (sn, so, rid))
    db.commit()
    db.close()
    out = vcs.evaluate_vcs_alerts(sn)
    assert out["alerted"] is False and captured == []

    # Suppressed FP never alerts, even above threshold.
    db = get_db()
    import scheduler as _s
    fp = _s.finding_fingerprint("semgrep", "r.c", "c.py", "fp issue")
    db.execute("INSERT INTO finding_suppressions (org_id, fingerprint,"
               " created_at) VALUES (?,?,?)",
               (ctx["org"], fp, "2026-10-01T00:00:00+00:00"))
    sn2 = "vscan_n2_" + _uid()
    _mk_scan(db, ctx["org"], sn2, "done",
             [{"tool": "semgrep", "rule_id": "r.c", "severity": "error",
               "message": "fp issue", "file": "c.py", "line": 3}],
             repo_id=rid, sha="3" * 40)
    db.execute("UPDATE vcs_repos SET last_scan_id=?, prev_scan_id=?"
               " WHERE id=?", (sn2, so, rid))
    db.commit()
    db.close()
    out = vcs.evaluate_vcs_alerts(sn2)
    assert out["alerted"] is False and captured == []


def test_vcs_failed_scan_alerts_loudly(ctx, monkeypatch):
    captured = []
    monkeypatch.setattr(
        vcs, "send_alert",
        lambda url, payload, org_id=None: captured.append(payload) or (True, 1, 200, None))
    db = get_db()
    rid, _, _ = _mk_repo(db, ctx["org"])
    sb = "vscan_bad_" + _uid()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " target_dir, error, vcs_repo_id) VALUES (?,?,?,?,?,?,?,?)",
        (sb, ctx["org"], "api", "failed", "2026-10-01T00:00:00+00:00",
         "/x", "boom", rid))
    db.execute("UPDATE vcs_repos SET last_scan_id=? WHERE id=?", (sb, rid))
    db.commit()
    db.close()
    out = vcs.evaluate_vcs_alerts(sb)
    assert out["alerted"] is True and out["event"] == "vcs.failed"
    assert captured[0]["event"] == "vcs.failed"
    db = get_db()
    n = db.execute("SELECT event, severity FROM notifications"
                   " WHERE vcs_repo_id=?", (rid,)).fetchone()
    db.close()
    assert (n["event"], n["severity"]) == ("vcs.failed", "error")


def test_evaluate_ignores_non_vcs_scans(ctx):
    db = get_db()
    s = "vscan_plain_" + _uid()
    _mk_scan(db, ctx["org"], s, "done", [])
    db.close()
    assert vcs.evaluate_vcs_alerts(s)["reason"] == "not a vcs scan"
    assert vcs.evaluate_vcs_alerts("nope")["reason"] == "not a vcs scan"
