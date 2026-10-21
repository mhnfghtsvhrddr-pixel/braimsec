"""GitHub pull-request scan comments (VCS PR integration).

When a pull request targets a watched branch, the PR head commit is
scanned like a push, and the result is posted as a comment on the PR
thread. The comment body starts with ``PR_COMMENT_MARKER`` so later
pushes to the same PR find and PATCH the same comment instead of
spamming the thread.

Posting needs a GitHub PAT registered on the repo (``github_token``,
write-only, Fernet-encrypted in ``vcs_repos.github_token_enc`` — see
``vcs.validate_github_token``). The token is used solely for the
Comments API; cloning always uses the public repo URL.

``urlopen`` is imported as a module-level name (``from urllib.request
import urlopen``) so tests can monkeypatch ``github_pr.urlopen`` without
touching global urllib. The token never appears in a log line or in an
error string.
"""
from __future__ import annotations

import json
import logging
import time
from urllib.parse import quote
from urllib.request import Request, urlopen

from database import get_db

log = logging.getLogger("braimsec.github_pr")

PR_COMMENT_MARKER = "<!-- braimsec-pr-scan -->"

_GH_API = "https://api.github.com"
_PR_TIMEOUT_S = 20.0
_PR_MAX_FINDINGS = 10
# GitHub issue-comment limit is 65536 chars; stay comfortably under it.
_PR_MAX_CHARS = 60000
_PR_ATTEMPTS = 2

_SEV_RANK = {"note": 0, "warning": 1, "error": 2}


# ---------------------------------------------------------------------------
# Comment building (markdown)
# ---------------------------------------------------------------------------

def build_pr_comment(full_name: str, pr_number: int, head_sha: str,
                     severity_summary: dict, top_findings: list[dict],
                     total: int, *, failed: bool = False,
                     error: str | None = None) -> str:
    """Markdown body for the PR scan comment.

    ``severity_summary`` maps severity -> count (API vocabulary:
    error | warning | note); ``top_findings`` are dicts with file, line,
    rule_id, severity, message. ``failed`` selects the failed-scan variant
    (the positional signature otherwise matches the healthy path).
    """
    short = (head_sha or "")[:8]
    head = (f"{PR_COMMENT_MARKER}\n"
            f"## 🛡️ BraimSec scan — `{full_name}#{pr_number}` @ `{short}`\n")
    if failed:
        body = (head + "\n⚠️ **Scan failed** — "
                f"{(error or 'unknown error')[:300]}\n\n"
                "The automatic check could not complete; review the "
                "failure in your BraimSec dashboard.\n")
        return body[:_PR_MAX_CHARS]
    if not total:
        return (head + "\n✅ **No issues found** — the scan is clean.\n\n"
                "Full results in your BraimSec dashboard.\n")[:_PR_MAX_CHARS]
    counts = " · ".join(
        f"{severity_summary.get(s, 0)} {s}"
        for s in ("error", "warning", "note")
        if severity_summary.get(s))
    lines = [head,
             f"\n**{total} finding{'s' if total != 1 else ''}**"
             + (f" — {counts}" if counts else "") + "\n",
             "### Top findings"]
    for f in (top_findings or [])[:_PR_MAX_FINDINGS]:
        msg = " ".join(str(f.get("message") or "").split())[:160]
        bullet = (f"- `{f.get('file')}:{f.get('line')}` — "
                  f"**{f.get('severity')}** `{f.get('rule_id')}`")
        if msg:
            bullet += f" — {msg}"
        lines.append(bullet)
    lines += ["", "Full results in your BraimSec dashboard."]
    return "\n".join(lines)[:_PR_MAX_CHARS]


# ---------------------------------------------------------------------------
# Comments API (post once, PATCH the marker comment afterwards)
# ---------------------------------------------------------------------------

def _gh_headers(token: str) -> dict:
    # The token only ever travels in this Authorization header; it is never
    # formatted into log lines or error strings anywhere in this module.
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "braimsec-pr-scan/1.0",
    }


def _gh_json(method: str, url: str, token: str,
             payload: dict | None = None) -> dict | list:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = Request(url, data=data, headers=_gh_headers(token), method=method)
    with urlopen(req, timeout=_PR_TIMEOUT_S) as resp:
        raw = (resp.read() or b"").decode("utf-8", "replace")
    try:
        return json.loads(raw) if raw.strip() else {}
    except ValueError:
        return {}


def post_or_update_pr_comment(token: str, full_name: str, pr_number: int,
                              markdown: str) -> int:
    """Post the scan comment, or PATCH the existing marker comment.

    Returns the comment id. Retries once on transient errors. Raises
    RuntimeError when both attempts fail — the message never contains the
    token.
    """
    owner_repo = quote(full_name, safe="/")
    comments_url = (f"{_GH_API}/repos/{owner_repo}/issues/{pr_number}"
                    f"/comments?per_page=100")
    last_err = None
    for attempt in range(1, _PR_ATTEMPTS + 1):
        try:
            comments = _gh_json("GET", comments_url, token) or []
            existing = next(
                (c for c in comments
                 if PR_COMMENT_MARKER in str(c.get("body") or "")), None)
            if existing:
                url = (f"{_GH_API}/repos/{owner_repo}/issues/comments/"
                       f"{existing['id']}")
                out = _gh_json("PATCH", url, token, {"body": markdown})
                comment_id = int(out.get("id") or existing["id"])
                log.info("github_pr: updated comment %s on %s#%s",
                         comment_id, full_name, pr_number)
                return comment_id
            out = _gh_json("POST", comments_url, token, {"body": markdown})
            comment_id = int(out["id"])
            log.info("github_pr: posted comment %s on %s#%s",
                     comment_id, full_name, pr_number)
            return comment_id
        except Exception as e:  # noqa: BLE001 - retry once, token never logged
            last_err = f"{type(e).__name__}: {str(e)[:150]}"
            log.warning("github_pr: attempt %d failed for %s#%s: %s",
                        attempt, full_name, pr_number, last_err)
            time.sleep(2 ** attempt)
    raise RuntimeError(f"github comment failed: {last_err}")


# ---------------------------------------------------------------------------
# Terminal-hook entry point (best-effort)
# ---------------------------------------------------------------------------

def maybe_post_pr_comment(scan_id: str) -> dict:
    """Post/update the PR comment for a finished PR-triggered scan.

    No-op unless a ``pr_scans`` row exists for the scan, the repo has a
    GitHub PAT, and the scan reached a terminal state (done/failed).
    Returns a small outcome dict and never raises — alerting must not
    break scan completion.
    """
    try:
        return _maybe_post_pr_comment(scan_id)
    except Exception as e:  # noqa: BLE001 - alerting must not break scans
        log.exception("github_pr: failed for scan %s", scan_id)
        return {"posted": False,
                "reason": f"internal error: {type(e).__name__}"}


def _maybe_post_pr_comment(scan_id: str) -> dict:
    db = get_db()
    try:
        pr = db.execute("SELECT * FROM pr_scans WHERE scan_id=?",
                        (scan_id,)).fetchone()
        if not pr:
            return {"posted": False, "reason": "not a PR scan"}
        pr = dict(pr)
        repo = db.execute("SELECT * FROM vcs_repos WHERE id=?",
                          (pr["repo_id"],)).fetchone()
        if not repo:
            return {"posted": False, "reason": "repo gone"}
        repo = dict(repo)
        enc = repo.get("github_token_enc")
        if not enc:
            return {"posted": False, "reason": "no github token"}
        scan = db.execute("SELECT * FROM scans WHERE id=?",
                          (scan_id,)).fetchone()
        if not scan:
            return {"posted": False, "reason": "scan gone"}
        scan = dict(scan)
        if scan["status"] not in ("done", "failed"):
            return {"posted": False,
                    "reason": f"status={scan['status']}"}
        summary_rows = db.execute(
            "SELECT severity, COUNT(*) c FROM findings WHERE scan_id=?"
            " GROUP BY severity", (scan_id,)).fetchall()
        severity_summary = {r["severity"]: r["c"] for r in summary_rows}
        finding_rows = db.execute(
            "SELECT tool, rule_id, severity, message, file, line"
            " FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        top = sorted((dict(f) for f in finding_rows),
                     key=lambda f: _SEV_RANK.get(f["severity"], 0),
                     reverse=True)[:_PR_MAX_FINDINGS]
        total = sum(severity_summary.values())
    finally:
        db.close()

    from vcs import decrypt_secret  # noqa: E402  (deferred: import graph)
    try:
        token = decrypt_secret(enc)
    except Exception:  # noqa: BLE001 - corrupt row must not kill the scan
        log.warning("github_pr: stored token undecryptable for repo %s",
                    pr["repo_id"])
        return {"posted": False, "reason": "token undecryptable"}

    if scan["status"] == "failed":
        markdown = build_pr_comment(repo["full_name"], pr["pr_number"],
                                    pr["head_sha"], {}, [], 0,
                                    failed=True, error=scan.get("error"))
    else:
        markdown = build_pr_comment(repo["full_name"], pr["pr_number"],
                                    pr["head_sha"], severity_summary, top,
                                    total)
    try:
        comment_id = post_or_update_pr_comment(token, repo["full_name"],
                                               pr["pr_number"], markdown)
    except Exception as e:  # noqa: BLE001 - best effort by design
        log.warning("github_pr: post failed for %s#%s: %s",
                    repo["full_name"], pr["pr_number"],
                    f"{type(e).__name__}: {str(e)[:150]}")
        return {"posted": False, "reason": "post failed"}
    db = get_db()
    try:
        db.execute("UPDATE pr_scans SET comment_id=? WHERE scan_id=?",
                   (comment_id, scan_id))
        db.commit()
    finally:
        db.close()
    return {"posted": True, "comment_id": comment_id,
            "pr": pr["pr_number"]}
