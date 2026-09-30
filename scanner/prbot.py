"""PR Review Bot — Proposal Part 4 (v1).

Reviews the *diff*, not the repo. A finding becomes an inline PR comment
only if ALL of these hold (proposal §4 amendments):

  1. its line is an ADDED line in ``base...head`` (diff-aware scope);
  2. it does not already fire on the same code in the base revision
     (base-branch dedup — a moved legacy line is not "new");
  3. overlapping findings collapse: one comment per (file, line), and one
     comment per taint flow (a source-line hit covered by another
     finding's taint path folds into the sink comment);
  3. severity is ``error`` (configurable floor; warnings never comment —
     a bot that spams warnings gets disabled on day one);
  4. the AI gate: ``tool == "gitleaks"`` passes deterministically
     (a leaked secret is high-confidence by construction), and so does
     ``tool == "osv"`` (an exact pinned-version CVE match is
     high-confidence by construction); everything else needs
     ``analyze_finding`` -> ``vulnerable``. On AI failure or
     timeout the bot stays SILENT and logs — never comments unreviewed.

SCA on the diff: when the diff touches dependency manifests
(requirements.txt, package-lock.json, go.mod, Cargo.lock,
Gemfile.lock), only NEW or version-CHANGED pins are queried against
OSV — historical vulnerabilities the PR did not introduce never
comment. One aggregated comment per pin (all its CVE IDs inside).
Disable with ``--no-sca``; ``SCA_OFFLINE=1`` also skips it.

Enrichment per comment is best-effort: the taint-flow trace (Part 3,
deterministic) is attached when the rule is a taint rule; a
``suggestion`` block is attached when the auto-fix generator is
importable and the AI is configured.

Usage (in CI)::

    python scanner/prbot.py --base <base-sha> --head <head-sha> \\
        --post --repo-slug owner/repo --pr 123

Without ``--post`` it prints the JSON report (dry-run). AI comes from
the same ``AI_API_URL`` / ``AI_API_KEY`` env as the API layer; without
them only gitleaks findings can comment.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))

from scan_engine import run_gitleaks, run_semgrep  # noqa: E402

try:
    from ai_layer import LLMClient, analyze_finding, read_snippet  # noqa: E402
except Exception:  # noqa: BLE001 - bot works AI-less (secrets only)
    LLMClient = analyze_finding = read_snippet = None

try:
    from taintflow import (ast_backward_slice, extract_taint_path,  # noqa: E402
                           _is_taint_rule)
except Exception:  # noqa: BLE001
    ast_backward_slice = extract_taint_path = None

    def _is_taint_rule(rule_id):  # fallback if taintflow import fails
        return bool(rule_id) and "braimsec.taint." in rule_id

try:
    from fix_suggestions import (  # noqa: E402
        extract_fix_context, generate_fix)
except Exception:  # noqa: BLE001
    extract_fix_context = generate_fix = None

try:
    from sca_diff import run_sca_on_diff  # noqa: E402
except Exception:  # noqa: BLE001 - bot works without diff SCA
    run_sca_on_diff = None

SEVERITY_RANK = {"note": 0, "warning": 1, "error": 2}

GIT_TIMEOUT = 60
SCAN_TIMEOUT_NOTE = ("semgrep runs are bounded by scan_engine itself; "
                     "kept scoped to changed files only")


# ---------------------------------------------------------------------------
# Diff handling
# ---------------------------------------------------------------------------

def git_diff(repo, base, head):
    """Unified diff (zero context) of ``base...head``."""
    p = subprocess.run(
        ["git", "-C", repo, "diff", "--no-color", "-U0",
         f"{base}...{head}", "--"],
        capture_output=True, text=True, timeout=GIT_TIMEOUT)
    if p.returncode != 0:
        raise RuntimeError(f"git diff failed: {p.stderr.strip()[:200]}")
    return p.stdout


_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def added_lines(diff_text):
    """{repo-relative path: set(added line numbers)} from a -U0 diff."""
    added, cur, new_line = {}, None, 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            m = _DIFF_FILE_RE.match(raw)
            cur = m.group(1) if m else None
            if cur == "/dev/null":
                cur = None
            if cur is not None:
                added.setdefault(cur, set())
            continue
        if cur is None:
            continue
        m = _HUNK_RE.match(raw)
        if m:
            new_line = int(m.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            added[cur].add(new_line)
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        else:  # context line (shouldn't appear with -U0, stay safe)
            new_line += 1
    return {k: v for k, v in added.items() if v}


def _rel(repo, path):
    return os.path.relpath(os.path.realpath(path), os.path.realpath(repo))


# ---------------------------------------------------------------------------
# Base-branch dedup: is this finding really new?
# ---------------------------------------------------------------------------

def _base_text(repo, base, rel):
    p = subprocess.run(["git", "-C", repo, "show", f"{base}:{rel}"],
                       capture_output=True, text=True, timeout=GIT_TIMEOUT)
    return p.stdout if p.returncode == 0 else None


def _norm_line(text, line):
    try:
        return text.splitlines()[line - 1].strip()
    except IndexError:
        return ""


def _finding_sig(repo, finding):
    """(rule_id, normalized code line) identity for base comparison."""
    abs_path = (finding["file"] if os.path.isabs(finding["file"])
                else os.path.join(repo, finding["file"]))
    try:
        with open(abs_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        text = ""
    return (finding.get("rule_id"), _norm_line(text, finding.get("line") or 0))


def is_new_finding(finding, added, repo, base):
    """True only if on an added line AND absent from the base revision."""
    rel = _rel(repo, finding.get("file") or "")
    lines = added.get(rel)
    if not lines or (finding.get("line") or 0) not in lines:
        return False
    base_src = _base_text(repo, base, rel)
    if base_src is None:
        return True  # new file — new by definition
    sig = _finding_sig(repo, finding)
    if not sig[1]:
        return True
    with tempfile.TemporaryDirectory(prefix="braimsec-prbase-") as tmp:
        tmp_file = os.path.join(tmp, os.path.basename(rel) or "base.py")
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(base_src)
        try:
            base_findings = run_semgrep(tmp, scope=[tmp_file])
        except Exception:  # noqa: BLE001 - base check best-effort
            return True
    for bf in base_findings:
        bline = _norm_line(base_src, bf.get("line") or 0)
        if bf.get("rule_id") == sig[0] and bline == sig[1]:
            return False  # same rule, same code in base: legacy
    return True


# ---------------------------------------------------------------------------
# Same-line dedup: one comment per (file, line)
# ---------------------------------------------------------------------------

def _dup_priority(f):
    rid = f.get("rule_id") or ""
    if _is_taint_rule(rid):
        return (0, rid)
    if f.get("tool") == "gitleaks":
        return (1, rid)
    return (2, rid)


def dedupe_by_line(findings, repo):
    """Collapse overlapping findings on the same line to one.

    Semgrep often fires several rules on one sink (registry + our taint
    rules). A PR bot posting 3 comments on the same line looks broken.
    Priority: our taint rules > secrets > anything else, then rule_id
    (deterministic). Presentation-only: the API still stores every finding.
    """
    best = {}
    for f in findings:
        key = (_rel(repo, f.get("file") or ""), f.get("line") or 0)
        if key not in best or _dup_priority(f) < _dup_priority(best[key]):
            best[key] = f
    kept = list(best.values())
    stats = {"line_dups": len(findings) - len(kept)}
    return kept, stats


def _collapse_taint_overlaps(findings, repo):
    """One vuln, one comment.

    Registry rules sometimes report the SOURCE line while our taint rule
    reports the SINK line of the same flow (e.g. lines 5 and 6 of one
    SSRF). Drop a finding whose line is covered by another finding's
    taint path (same file, non-sink steps). Uses the fast AST slicer
    (~70ms) — not the semgrep-trace path — because only the line set
    matters here. Best-effort: if the slice fails, lines stay separate.
    """
    if ast_backward_slice is None:
        return findings, 0
    owners = []  # (finding, {source/propagation lines})
    for f in findings:
        if not _is_taint_rule(f.get("rule_id")):
            continue
        abs_p = (f["file"] if os.path.isabs(f.get("file") or "")
                 else os.path.join(repo, f.get("file") or ""))
        try:
            steps = ast_backward_slice(abs_p, f.get("line") or 0)
        except Exception:  # noqa: BLE001
            continue
        if steps:
            owners.append((f, {s["line"] for s in steps
                              if s["type"] != "sink"}))
    if not owners:
        return findings, 0
    out = []
    for f in findings:
        rel = _rel(repo, f.get("file") or "")
        covered = any(
            f is not o and _rel(repo, o.get("file") or "") == rel
            and (f.get("line") or 0) in lines
            for o, lines in owners)
        if not covered:
            out.append(f)
    return out, len(findings) - len(out)


# ---------------------------------------------------------------------------
# Gates (§4 amendments)
# ---------------------------------------------------------------------------

def ai_verdict_for(client, finding, repo):
    """(verdict_dict | None, dropped_reason | None). Never raises."""
    if analyze_finding is None or client is None or not client.configured:
        return None, "ai gate: LLM not configured"
    abs_path = (finding["file"] if os.path.isabs(finding["file"])
                else os.path.join(repo, finding["file"]))
    snippet = read_snippet(abs_path, finding.get("line") or 0) \
        if read_snippet else ""
    try:
        res = analyze_finding(client, finding, snippet)
    except Exception as e:  # noqa: BLE001 - silent bot, loud log
        return None, f"ai gate: analyzer failed ({type(e).__name__})"
    if res.get("ai_verdict") != "vulnerable":
        return None, (f"ai gate: verdict={res.get('ai_verdict')} "
                       f"conf={res.get('ai_confidence')}")
    return res, None


def apply_gates(findings, repo, client, min_severity="error"):
    """Split findings into (commentable, dropped)."""
    floor = SEVERITY_RANK.get(min_severity, 2)
    ok, dropped = [], []
    for f in findings:
        sev = f.get("severity") or "warning"
        if SEVERITY_RANK.get(sev, 1) < floor:
            dropped.append((f, f"severity gate: {sev} < {min_severity}"))
            continue
        if f.get("tool") in ("gitleaks", "osv"):
            ok.append((f, None))  # deterministic high-confidence:
            continue              # leaked secret / exact-pin CVE match
        ai_res, reason = ai_verdict_for(client, f, repo)
        if ai_res is None:
            dropped.append((f, reason))
        else:
            ok.append((f, ai_res))
    return ok, dropped


# ---------------------------------------------------------------------------
# Comment rendering
# ---------------------------------------------------------------------------

def _taint_details(finding, repo):
    if extract_taint_path is None:
        return ""
    if not _is_taint_rule(finding.get("rule_id")):
        return ""
    try:
        trace = extract_taint_path(finding, repo)
    except Exception:  # noqa: BLE001 - enrichment is best-effort
        return ""
    if not trace.get("available"):
        return ""
    lines = ["<details>", "<summary>🔍 Exploitation path (taint flow)</summary>",
             ""]
    for s in trace["taint_path"]:
        icon = {"source": "🟢", "propagation": "🟡",
                "sink": "🔴"}.get(s["type"], "▫️")
        lines.append(f"{icon} `{s['type']}` "
                     f"`{os.path.basename(s['file'])}:{s['line']}` — "
                     f"`{s['snippet'][:90]}`")
    lines += ["",
              f"Sanitization: **{trace['sanitization']['verdict']}**",
              "</details>", ""]
    return "\n".join(lines)


def _suggestion_block(finding, repo, client):
    if generate_fix is None or client is None or not client.configured:
        return ""
    abs_path = (finding["file"] if os.path.isabs(finding["file"])
                else os.path.join(repo, finding["file"]))
    try:
        func_src, imports_src = extract_fix_context(
            abs_path, finding.get("line") or 0)
        if not func_src:
            return ""
        gen = generate_fix(client, finding, func_src, imports_src)
        patched = gen.get("fix_patched", "").strip()
        if not patched:
            return ""
    except Exception:  # noqa: BLE001 - enrichment is best-effort
        return ""
    return ("**💡 Suggested fix** (review before applying):\n"
            "```suggestion\n" + patched[:2000] + "\n```\n")


def build_comment(finding, ai_res, repo, client=None):
    rel = _rel(repo, finding.get("file") or "")
    line = finding.get("line") or 1
    head = (f"🛡️ **BraimSec** `[{finding.get('severity', 'error').upper()}]` "
            f"{finding.get('message', '')}")
    meta = f"`{finding.get('tool')}/{finding.get('rule_id')}`"
    if ai_res:
        meta += (f" · AI verdict: **{ai_res.get('ai_verdict')}** "
                 f"({ai_res.get('ai_confidence')})")
        expl = (ai_res.get("ai_explanation") or "").strip()
    elif finding.get("tool") == "osv":
        expl = ("Deterministic: this exact pinned version is listed in the "
                "OSV vulnerability database. No AI review needed.")
    else:
        expl = "Deterministic high-confidence finding (leaked secret)."
    body = f"{head}\n\n{meta}\n\n{expl}\n\n"
    body += _taint_details(finding, repo)
    body += _suggestion_block(finding, repo, client)
    body += "\n<sub>Posted by BraimSec PR Review — only new, high-confidence "
    body += "findings comment. Warnings never do.</sub>"
    return {"path": rel, "line": line, "body": body}


def build_review_payload(comments, head_sha, summary):
    return {
        "commit_id": head_sha,
        "event": "COMMENT",
        "body": summary,
        "comments": [
            {"path": c["path"], "line": c["line"], "side": "RIGHT",
             "body": c["body"]} for c in comments
        ],
    }


def post_review(repo_slug, pr_number, token, payload, dry_run=False):
    if dry_run:
        return {"dry_run": True,
                "would_post": len(payload["comments"])}
    url = (f"https://api.github.com/repos/{repo_slug}/pulls/"
           f"{pr_number}/reviews")
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json",
                 "User-Agent": "braimsec-prbot/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return {"posted": True, "status": r.status,
                    "review": json.loads(r.read().decode() or "{}")
                    .get("html_url")}
    except Exception as e:  # noqa: BLE001 - report, don't crash CI
        return {"posted": False, "error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_bot(repo, base, head, ai=True, min_severity="error", client=None,
            sca=True):
    """Full pipeline -> {comments, dropped, stats}. No network calls."""
    repo = os.path.realpath(repo)
    diff = git_diff(repo, base, head)
    added = added_lines(diff)
    stats = {"changed_files": len(added),
             "added_lines": sum(len(v) for v in added.values())}

    abs_files = [os.path.join(repo, rel) for rel in added]
    findings = []
    if abs_files:
        findings += run_semgrep(repo, scope=abs_files)
        findings += run_gitleaks(repo, scope=abs_files)
    stats["raw_findings"] = len(findings)

    # Diff-aware SCA: new/changed pins only. Findings are already scoped
    # (added lines, absent from base), so they skip is_new_finding but
    # still flow through dedup + the severity/AI gates below.
    sca_findings = []
    if sca and run_sca_on_diff is not None:
        try:
            sca_findings = run_sca_on_diff(repo, base, added)
        except Exception as e:  # noqa: BLE001 - SCA never breaks the bot
            print(f"[prbot] WARN: diff SCA failed ({type(e).__name__}); "
                  "continuing without it", file=sys.stderr)
    stats["sca_findings"] = len(sca_findings)

    new_findings = [f for f in findings
                    if is_new_finding(f, added, repo, base)]
    new_findings += sca_findings
    stats["new_findings"] = len(new_findings)

    new_findings, dup_stats = dedupe_by_line(new_findings, repo)
    stats.update(dup_stats)
    new_findings, collapsed = _collapse_taint_overlaps(new_findings, repo)
    stats["taint_collapsed"] = collapsed

    if ai and LLMClient is not None:
        client = client or LLMClient()
    else:
        client = None
    gated, dropped = apply_gates(new_findings, repo, client,
                                 min_severity=min_severity)
    stats["dropped"] = len(dropped)

    comments = [build_comment(f, ai_res, repo, client)
                for f, ai_res in gated]
    stats["comments"] = len(comments)
    return {
        "comments": comments,
        "dropped": [
            {"file": _rel(repo, f.get("file") or ""),
             "line": f.get("line"), "rule_id": f.get("rule_id"),
             "reason": reason} for f, reason in dropped
        ],
        "stats": stats,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="BraimSec PR Review Bot")
    ap.add_argument("repo", nargs="?", default=".",
                    help="git repo to review (default: .)")
    ap.add_argument("--base", default="HEAD~1", help="base revision")
    ap.add_argument("--head", default="HEAD", help="head revision")
    ap.add_argument("--min-severity", default="error",
                    choices=["note", "warning", "error"])
    ap.add_argument("--no-ai", action="store_true",
                    help="skip the AI gate (secrets only can comment)")
    ap.add_argument("--no-sca", action="store_true",
                    help="skip diff-aware SCA on dependency manifests")
    ap.add_argument("--post", action="store_true",
                    help="post the review to GitHub (default: dry-run)")
    ap.add_argument("--repo-slug", default=os.environ.get("GITHUB_REPOSITORY", ""),
                    help="owner/repo for posting")
    ap.add_argument("--pr", default="",
                    help="pull request number for posting")
    ap.add_argument("--fail-on-findings", action="store_true",
                    help="exit 1 when comments were produced")
    args = ap.parse_args(argv)

    result = run_bot(args.repo, args.base, args.head,
                     ai=not args.no_ai, min_severity=args.min_severity,
                     sca=not args.no_sca)

    summary = (f"BraimSec found {result['stats']['comments']} new "
               f"high-confidence issue(s) in this diff "
               f"({result['stats']['dropped']} below the bar).")
    posted = None
    if args.post:
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token or not args.repo_slug or not args.pr:
            print("ERROR: --post needs GITHUB_TOKEN, --repo-slug and --pr",
                  file=sys.stderr)
            return 2
        head_sha = subprocess.run(
            ["git", "-C", args.repo, "rev-parse", args.head],
            capture_output=True, text=True).stdout.strip()
        payload = build_review_payload(result["comments"], head_sha, summary)
        posted = post_review(args.repo_slug, args.pr, token, payload)
        print(json.dumps(posted, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))

    if args.fail_on_findings and result["comments"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
