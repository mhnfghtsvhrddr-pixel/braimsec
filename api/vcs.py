"""VCS integration (v1): scan a repo automatically on every push.

Supported providers: GitHub and GitLab. Flow:

1.  The customer registers a repo (``POST /api/vcs/repos``) and gets a
    one-time webhook secret plus the public receiver URL to paste into the
    provider's webhook settings.
2.  On push, the provider POSTs to ``/api/webhooks/github`` (or ``/gitlab``).
    GitHub is verified with ``X-Hub-Signature-256`` (HMAC-SHA256 over the raw
    body); GitLab with the ``X-Gitlab-Token`` header. Non-push events and
    pushes to unwatched branches are ignored.
3.  A verified push shallow-clones the pushed commit and creates a scan
    through the normal ``_new_scan`` path (quota, sandbox engines, alerts).
4.  New findings above the repo's severity threshold are delivered through the
    existing alert infrastructure (webhooks); FP suppressions are honoured.

Security notes
--------------
* Repo URLs are strictly validated: https only, no credentials/ports, host
  must be on the ``BRAIMSEC_VCS_HOSTS`` allowlist (default
  ``github.com,gitlab.com``), and DNS must not resolve to a blocked range
  (fail-closed, mirrors ``ssrf_guard``).
* The webhook secret is stored as a SHA-256 hash (shown once at registration,
  like API keys). GitLab tokens are verified by hashing the presented token.
  GitHub's HMAC-SHA256 protocol cryptographically *requires* the raw secret
  at verification time, so for ``github`` repos the raw secret is *additionally*
  stored encrypted-at-rest (Fernet, key derived from ``BRAIMSEC_API_KEY``) in
  ``webhook_secret_enc``. GitLab repos never populate that column.
* Secrets/tokens are never written to logs.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from database import get_db
from scheduler import (SEVERITY_ORDER, _scan_findings, _send_email_alerts,
                       _send_telegram_alerts, _suppressed_fps,
                       finding_fingerprint, send_alert)
from ssrf_guard import _resolve_checked  # noqa: F401  (fail-closed DNS check)

log = logging.getLogger("braimsec.vcs")

VCS_PROVIDERS = ("github", "gitlab")

_ZERO_SHA = "0" * 40

# [SECURITY] path segments of a repo URL: owner / repo (GitLab allows nested
# groups, so 1..5 segments are accepted).
_SEG = r"[A-Za-z0-9_.\-]+"
_REPO_PATH_RE = re.compile(rf"^({_SEG})(/{_SEG}){{0,4}}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9_.\-/]{1,100}$")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def allowed_vcs_hosts() -> set:
    """Allowlisted VCS hostnames (lowercase). Configurable via env."""
    raw = os.environ.get("BRAIMSEC_VCS_HOSTS", "github.com,gitlab.com")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Repo URL validation / normalization (strict SSRF)
# ---------------------------------------------------------------------------

def normalize_repo_url(url: str) -> str:
    """Canonical form: ``https://host/owner/repo`` (no .git, no trailing /).

    Raises ValueError on anything that is not a well-formed repo path.
    Does NOT do the DNS check (use :func:`validate_repo_url` for that).
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("repo_url: required")
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise ValueError("repo_url must use https")
    if parts.username or parts.password:
        raise ValueError("repo_url must not contain credentials")
    if parts.port:
        raise ValueError("repo_url must not include a port")
    if parts.query or parts.fragment:
        raise ValueError("repo_url must not contain query or fragment")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError("repo_url: missing host")
    path = (parts.path or "").rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not _REPO_PATH_RE.match(path.lstrip("/")):
        raise ValueError("repo_url path must look like /owner/repo")
    return f"https://{host}/{path.lstrip('/')}"


def validate_repo_url(url: str) -> str:
    """Full validation: normalization + host allowlist + fail-closed DNS."""
    normalized = normalize_repo_url(url)
    host = urlsplit(normalized).hostname
    if host not in allowed_vcs_hosts():
        raise ValueError(f"repo_url host not allowed: {host}")
    try:
        _resolve_checked(host)
    except ValueError as e:
        # Transient DNS failure is tolerated (mirrors validate_webhook_url);
        # blocked/private ranges fail closed.
        if "does not resolve" in str(e):
            log.warning("vcs: DNS lookup failed for %s (transient, allowed)",
                        host)
        else:
            raise ValueError(f"repo_url: {e}")
    return normalized


def validate_branch(branch: str) -> str:
    if not isinstance(branch, str) or not _BRANCH_RE.match(branch or ""):
        raise ValueError("branch: 1-100 chars of [A-Za-z0-9_.-/]")
    return branch


# ---------------------------------------------------------------------------
# Webhook secrets
# ---------------------------------------------------------------------------

def generate_webhook_secret() -> str:
    return secrets.token_hex(32)


def hash_secret(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _fernet():
    """Fernet instance keyed off BRAIMSEC_API_KEY (stable per deployment)."""
    from cryptography.fernet import Fernet
    master = os.environ.get("BRAIMSEC_API_KEY", "")
    if not master:
        raise RuntimeError("BRAIMSEC_API_KEY is required for webhook "
                           "secret encryption")
    dk = hashlib.pbkdf2_hmac("sha256", master.encode("utf-8"),
                             b"braimsec-vcs-webhook-enc-v1", 200_000, 32)
    return Fernet(base64.urlsafe_b64encode(dk))


def encrypt_secret(raw: str) -> str:
    return _fernet().encrypt(raw.encode("utf-8")).decode("ascii")


def decrypt_secret(enc: str) -> str:
    return _fernet().decrypt(enc.encode("ascii")).decode("utf-8")


def verify_github_signature(raw_body: bytes, signature_header: str | None,
                            secret: str) -> bool:
    """Verify ``X-Hub-Signature-256: sha256=<hex>`` (constant-time)."""
    if not signature_header or not secret:
        return False
    if not signature_header.startswith("sha256="):
        return False
    try:
        provided = bytes.fromhex(signature_header[len("sha256="):])
    except ValueError:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body,
                        hashlib.sha256).digest()
    return hmac.compare_digest(expected, provided)


def verify_gitlab_token(provided: str | None, secret_hash: str) -> bool:
    """Verify ``X-Gitlab-Token`` against the stored SHA-256 hash."""
    if not provided or not secret_hash:
        return False
    return hmac.compare_digest(hash_secret(provided), secret_hash)


# ---------------------------------------------------------------------------
# Push payload parsing (providers -> normalized dict)
# ---------------------------------------------------------------------------

def parse_github_push(payload: dict, event: str) -> dict | None:
    """Return None for ignorable events, else a normalized push dict.

    Normalized dict types: ``ping`` | ``push`` | ``ignore``.
    """
    if event == "ping":
        repo = payload.get("repository") or {}
        return {"type": "ping",
                "clone_url": repo.get("clone_url") or ""}
    if event != "push":
        return None
    repo = payload.get("repository") or {}
    ref = payload.get("ref") or ""
    after = payload.get("after") or ""
    if payload.get("deleted") or after == _ZERO_SHA:
        return {"type": "ignore", "reason": "branch deleted"}
    if not ref.startswith("refs/heads/"):
        return {"type": "ignore", "reason": "not a branch push"}
    branch = ref[len("refs/heads/"):]
    if not after or len(after) != 40:
        return {"type": "ignore", "reason": "missing commit sha"}
    return {
        "type": "push",
        "full_name": repo.get("full_name") or "",
        "clone_url": repo.get("clone_url") or "",
        "branch": branch,
        "sha": after,
    }


def parse_gitlab_push(payload: dict, event_header: str | None) -> dict | None:
    """Same contract as :func:`parse_github_push` for GitLab."""
    if event_header != "Push Hook" or payload.get("object_kind") != "push":
        return None
    ref = payload.get("ref") or ""
    after = payload.get("after") or payload.get("checkout_sha") or ""
    if after == _ZERO_SHA:
        return {"type": "ignore", "reason": "branch deleted"}
    if not ref.startswith("refs/heads/"):
        return {"type": "ignore", "reason": "not a branch push"}
    branch = ref[len("refs/heads/"):]
    if not after or len(after) != 40:
        return {"type": "ignore", "reason": "missing commit sha"}
    project = payload.get("project") or {}
    return {
        "type": "push",
        "full_name": project.get("path_with_namespace") or "",
        "clone_url": project.get("git_http_url") or "",
        "branch": branch,
        "sha": after,
    }


def find_repos(provider: str, clone_url: str) -> list:
    """All registered repos matching a provider clone URL (any org).

    Returns [] for unknown repos or unparseable URLs. The caller must still
    verify the webhook signature — the first row whose secret verifies wins,
    so the same public repo can be registered by several orgs.
    """
    try:
        normalized = normalize_repo_url(clone_url)
    except ValueError:
        return []
    db = get_db()
    try:
        rows = db.execute(
            "SELECT * FROM vcs_repos WHERE provider=? AND repo_url=?"
            " ORDER BY created_at",
            (provider, normalized)).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def find_repo(provider: str, clone_url: str) -> dict | None:
    """First matching repo, or None (see :func:`find_repos`)."""
    repos = find_repos(provider, clone_url)
    return repos[0] if repos else None


def scan_exists_for_commit(repo_id: str, sha: str) -> bool:
    db = get_db()
    try:
        row = db.execute(
            "SELECT 1 FROM scans WHERE vcs_repo_id=? AND commit_sha=? LIMIT 1",
            (repo_id, sha)).fetchone()
        return row is not None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Cloning (public repos, shallow, fail loudly)
# ---------------------------------------------------------------------------

def clone_repo(repo_url: str, branch: str, sha: str, dest_dir: str,
               timeout: int = 300) -> str:
    """Shallow-clone ``branch`` then checkout ``sha``. Returns the real sha.

    Raises RuntimeError on any failure (no silent partial checkouts).
    """
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    os.makedirs(dest_dir, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch,
             "--single-branch", repo_url, dest_dir],
            check=True, capture_output=True, text=True, timeout=timeout,
            env=env)
        out = subprocess.run(
            ["git", "-C", dest_dir, "fetch", "--depth", "1", "origin", sha],
            check=True, capture_output=True, text=True, timeout=timeout,
            env=env)
        subprocess.run(
            ["git", "-C", dest_dir, "checkout", sha],
            check=True, capture_output=True, text=True, timeout=timeout,
            env=env)
        rev = subprocess.run(
            ["git", "-C", dest_dir, "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=60,
            env=env)
        actual = rev.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40}", actual):
            raise RuntimeError(f"unexpected rev-parse output: {actual!r}")
        return actual
    except FileNotFoundError:
        raise RuntimeError("git binary not found on this host")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"git clone/fetch timed out after {timeout}s")
    except subprocess.CalledProcessError as e:
        # Never leak tokens: clone_url is validated token-free, but the
        # remote may still echo sensitive data — keep the tail short.
        tail = (e.stderr or e.stdout or "")[-300:]
        raise RuntimeError(f"git failed (rc={e.returncode}): {tail}")


# ---------------------------------------------------------------------------
# Ingest: verified push -> scan
# ---------------------------------------------------------------------------

def _set_repo_error(repo_id: str, message: str | None):
    db = get_db()
    try:
        db.execute("UPDATE vcs_repos SET last_error=? WHERE id=?",
                   (message, repo_id))
        db.commit()
    finally:
        db.close()


def _ingest_vcs_push(repo_id: str, sha: str) -> dict:
    """Clone the pushed commit and create a scan. Safe to run in a worker.

    Returns a small result dict; never raises for business failures (quota,
    clone errors) — those are recorded on the repo row. Unexpected crashes
    still propagate so the task layer can see them.
    """
    from main import SCAN_ROOT, _new_scan  # noqa: E402  (deferred: main imports vcs)
    from fastapi import HTTPException  # noqa: E402

    db = get_db()
    try:
        row = db.execute("SELECT * FROM vcs_repos WHERE id=?",
                         (repo_id,)).fetchone()
        repo = dict(row) if row else None
    finally:
        db.close()
    if not repo:
        return {"ingested": False, "reason": "repo not found"}
    if not repo["enabled"]:
        return {"ingested": False, "reason": "repo disabled"}
    if scan_exists_for_commit(repo_id, sha):
        return {"ingested": False, "reason": "duplicate commit"}

    workdir = os.path.join(SCAN_ROOT, "vcs", repo_id, sha[:12])
    shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir, exist_ok=True)
    dest = os.path.join(workdir, "src")
    try:
        actual_sha = clone_repo(repo["repo_url"], repo["branch"], sha, dest)
    except RuntimeError as e:
        log.warning("vcs ingest: clone failed for %s: %s", repo["full_name"],
                    e)
        _set_repo_error(repo_id, f"clone failed: {e}")
        shutil.rmtree(workdir, ignore_errors=True)
        return {"ingested": False, "reason": "clone failed"}

    if scan_exists_for_commit(repo_id, actual_sha):
        shutil.rmtree(workdir, ignore_errors=True)
        return {"ingested": False, "reason": "duplicate commit"}

    # Pre-generate the scan id and link it BEFORE enqueueing, so the worker's
    # terminal hook (evaluate_vcs_alerts via repo.last_scan_id) resolves it.
    # Mirrors the scheduled-scan pattern.
    scan_id = uuid.uuid4().hex[:12]
    db = get_db()
    try:
        db.execute(
            "UPDATE vcs_repos SET prev_scan_id=last_scan_id,"
            " last_scan_id=?, last_scan_at=?, last_error=NULL WHERE id=?",
            (scan_id, _now_iso(), repo_id))
        db.commit()
    finally:
        db.close()

    target_name = f"{repo['full_name']}@{actual_sha[:8]}"
    try:
        _new_scan(repo["org_id"], target_name, dest, workdir, None,
                  baseline_scan_id=None, project_id=repo["project_id"],
                  scan_id=scan_id, vcs_repo_id=repo_id,
                  commit_sha=actual_sha)
    except HTTPException as e:
        if e.status_code == 402:
            db = get_db()
            try:
                db.execute(
                    "UPDATE vcs_repos SET prev_scan_id=last_scan_id,"
                    " last_scan_id=NULL, last_error=? WHERE id=?",
                    ("quota exceeded (402)", repo_id))
                db.commit()
            finally:
                db.close()
            shutil.rmtree(workdir, ignore_errors=True)
            return {"ingested": False, "reason": "quota exceeded"}
        # 503 (engines unavailable): the scan row exists as failed — run the
        # alert evaluation now, like scheduled scans do.
        _set_repo_error(repo_id, f"scan failed: {e.detail}")
        try:
            evaluate_vcs_alerts(scan_id)
        except Exception:  # noqa: BLE001 - alerting must not mask ingest
            log.exception("vcs ingest: alert evaluation failed")
        return {"ingested": False, "reason": f"scan error: {e.detail}"}

    from audit import log_event  # noqa: E402
    log_event(repo["org_id"], "system", "vcs.scan.created",
              "scan", scan_id,
              {"repo_id": repo_id, "commit": actual_sha[:12]})
    return {"ingested": True, "scan_id": scan_id, "commit": actual_sha}


# ---------------------------------------------------------------------------
# Alerts for VCS scans (new findings vs previous VCS scan)
# ---------------------------------------------------------------------------

def build_vcs_alert_payload(repo: dict, scan: dict,
                            new_findings: list[dict]) -> dict:
    sev_rank = {"note": 0, "warning": 1, "error": 2}
    highest = max(new_findings, key=lambda f: sev_rank.get(f["severity"], 0))
    top = sorted(new_findings,
                 key=lambda f: sev_rank.get(f["severity"], 0),
                 reverse=True)[:10]
    lines = [f"• [{f['severity']}] {f['rule_id']} — {f['file']}:{f['line']}"
             for f in top]
    more = (f"\n…و{len(new_findings) - len(top)} أخرى"
            if len(new_findings) > len(top) else "")
    text = (f"🔔 BraimSec: نتائج جديدة في المستودع "
            f"'{repo['full_name']}' (فرع {repo['branch']}, "
            f"commit {(scan.get('commit_sha') or '')[:8]}): "
            f"{len(new_findings)} نتيجة جديدة\n" + "\n".join(lines) + more)
    payload = {
        "event": "vcs.alert",
        "text": text,
        "content": text,
        "vcs_repo_id": repo["id"],
        "repo": repo["full_name"],
        "branch": repo["branch"],
        "commit": scan.get("commit_sha"),
        "scan_id": scan["id"],
        "new_count": len(new_findings),
        "highest_severity": highest["severity"],
        "findings": [
            {"tool": f["tool"], "rule_id": f["rule_id"],
             "severity": f["severity"], "file": f["file"],
             "line": f["line"], "message": f["message"][:300]}
            for f in top
        ],
    }
    return payload


def _alert_vcs_failure(db, repo: dict, scan: dict) -> dict:
    """A failed VCS scan means blind monitoring: say so, loudly."""
    payload = {
        "event": "vcs.failed",
        "text": (f"⚠️ BraimSec: فشل فحص المستودع '{repo['full_name']}' "
                 f"(فرع {repo['branch']}) — {(scan['error'] or 'unknown error')[:200]}"),
        "vcs_repo_id": repo["id"],
        "repo": repo["full_name"],
        "scan_id": scan["id"],
        "error": (scan["error"] or "")[:500],
    }
    payload["content"] = payload["text"]
    webhook_url = repo["webhook_url"] or ""
    email_out = _send_email_alerts(
        db, org_id=repo["org_id"], schedule_id=None, vcs_repo_id=repo["id"],
        scan_id=scan["id"], event="vcs.failed", severity="error",
        new_count=0, heading=f"المستودع {repo['full_name']}",
        subheading=(f"فرع {repo['branch']} — "
                    f"{(scan['error'] or 'unknown error')[:200]}"),
        findings=[])
    telegram_out = _send_telegram_alerts(
        db, org_id=repo["org_id"], schedule_id=None, vcs_repo_id=repo["id"],
        scan_id=scan["id"], event="vcs.failed", severity="error",
        new_count=0, heading=f"المستودع {repo['full_name']}",
        subheading=(f"فرع {repo['branch']} — "
                    f"{(scan['error'] or 'unknown error')[:200]}"),
        findings=[])
    if webhook_url:
        ok, attempts, code, err = send_alert(webhook_url, payload)
        db.execute(
            "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id, scan_id,"
            " event, severity, new_count, webhook_url, channel, status, attempts,"
            " response_code, error, payload, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (repo["org_id"], None, repo["id"], scan["id"], "vcs.failed",
             "error", 0, webhook_url, "webhook", "sent" if ok else "failed",
             attempts, code, err, json.dumps(payload, ensure_ascii=False),
             _now_iso()))
        db.commit()
    else:
        ok, err = False, None
    emailed = bool(email_out.get("emailed"))
    telegrammed = bool(telegram_out.get("telegrammed"))
    return {"alerted": bool(ok) or emailed or telegrammed,
            "event": "vcs.failed",
            "error": err, "email": email_out, "telegram": telegram_out}


def evaluate_vcs_alerts(scan_id: str) -> dict:
    """Diff a finished VCS scan against the previous one and alert on new.

    Called from the scan terminal hook (tasks.py) and from the ingest path
    on 503. Mirrors ``evaluate_schedule_alerts``.
    """
    db = get_db()
    try:
        row = db.execute("SELECT * FROM scans WHERE id=?",
                         (scan_id,)).fetchone()
        if not row or not row["vcs_repo_id"]:
            return {"alerted": False, "reason": "not a vcs scan"}
        scan = dict(row)
        rrow = db.execute("SELECT * FROM vcs_repos WHERE id=?",
                          (scan["vcs_repo_id"],)).fetchone()
        if not rrow:
            return {"alerted": False, "reason": "repo gone"}
        repo = dict(rrow)
        if not repo["enabled"]:
            return {"alerted": False, "reason": "repo disabled"}
        if scan["status"] == "failed":
            return _alert_vcs_failure(db, repo, scan)
        if scan["status"] != "done":
            return {"alerted": False, "reason": f"status={scan['status']}"}
        prev_id = repo.get("prev_scan_id")
        if not prev_id:
            return {"alerted": False, "reason": "first run: baseline set"}
        old_fps = {finding_fingerprint(f["tool"], f["rule_id"], f["file"],
                                       f["message"])
                   for f in _scan_findings(db, prev_id)}
        threshold = SEVERITY_ORDER.get(repo.get("alert_severity",
                                               "warning"), 1)
        suppressed = _suppressed_fps(db, repo["org_id"])
        new_findings = [
            f for f in _scan_findings(db, scan_id)
            if finding_fingerprint(f["tool"], f["rule_id"], f["file"],
                                   f["message"]) not in old_fps
            and finding_fingerprint(f["tool"], f["rule_id"], f["file"],
                                    f["message"]) not in suppressed
            and SEVERITY_ORDER.get(f["severity"], 0) >= threshold
        ]
        if not new_findings:
            return {"alerted": False, "reason": "no new findings >= threshold"}
        payload = build_vcs_alert_payload(repo, scan, new_findings)
        webhook_url = repo["webhook_url"] or ""
        email_out = _send_email_alerts(
            db, org_id=repo["org_id"], schedule_id=None, vcs_repo_id=repo["id"],
            scan_id=scan_id, event="vcs.alert",
            severity=payload["highest_severity"],
            new_count=len(new_findings),
            heading=f"المستودع {repo['full_name']}",
            subheading=(f"فرع {repo['branch']} — "
                        f"commit {(scan.get('commit_sha') or '')[:8]}"),
            findings=[{"severity": f["severity"], "rule_id": f["rule_id"],
                       "file": f["file"], "line": f["line"],
                       "message": f["message"]} for f in new_findings])
        telegram_out = _send_telegram_alerts(
            db, org_id=repo["org_id"], schedule_id=None, vcs_repo_id=repo["id"],
            scan_id=scan_id, event="vcs.alert",
            severity=payload["highest_severity"],
            new_count=len(new_findings),
            heading=f"المستودع {repo['full_name']}",
            subheading=(f"فرع {repo['branch']} — "
                        f"commit {(scan.get('commit_sha') or '')[:8]}"),
            findings=[{"severity": f["severity"], "rule_id": f["rule_id"],
                       "file": f["file"], "line": f["line"],
                       "message": f["message"]} for f in new_findings])
        if webhook_url:
            ok, attempts, code, err = send_alert(webhook_url, payload)
            db.execute(
                "INSERT INTO notifications (org_id, schedule_id, vcs_repo_id,"
                " scan_id, event, severity, new_count, webhook_url, channel,"
                " status, attempts, response_code, error, payload, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (repo["org_id"], None, repo["id"], scan_id, "vcs.alert",
                 payload["highest_severity"], len(new_findings),
                 webhook_url, "webhook", "sent" if ok else "failed", attempts,
                 code, err, json.dumps(payload, ensure_ascii=False),
                 _now_iso()))
            db.commit()
        else:
            # Email-only repo: no webhook configured, nothing to send/record.
            ok, attempts, err = False, 0, None
        emailed = bool(email_out.get("emailed"))
        telegrammed = bool(telegram_out.get("telegrammed"))
        return {"alerted": bool(ok) or emailed or telegrammed,
                "new_count": len(new_findings), "attempts": attempts,
                "error": err, "email": email_out, "telegram": telegram_out}
    finally:
        db.close()
