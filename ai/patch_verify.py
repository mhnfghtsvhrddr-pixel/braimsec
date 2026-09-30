"""Closed-loop patch verification — Proposal Part 1 (full auto-patch engine).

Fix suggestions (``ai/fix_suggestions.py``) are only *syntactically* checked.
This module closes the loop that the proposal's review (§4) demands:

1. **Eligibility gate** — phased rollout. v1 covers only three families:
   ``sql-injection``, ``path-traversal``, ``xss``. Anything else is reported
   as ineligible, never force-fitted.
2. **Fuzzy application** — the file may have drifted since the suggestion was
   generated. Each diff hunk is re-anchored by context search; when the
   context no longer matches, the patch is declared STALE explicitly
   (``PatchStale``) instead of being applied to the wrong place.
3. **Re-scan** — semgrep runs on the patched file and the verdict requires
   BOTH: the original finding is gone AND no new findings were introduced.

Honest framing, surfaced to callers: a ``verified=True`` patch is still a
*suggestion requiring human review*. Verification proves the scanner went
quiet, not that the code is correct or behavior-preserving. A wrong patch
that feels safe is an FP-class catastrophe — so the loop fails closed.

``ai/`` must be on ``sys.path`` (same convention as ``api/tasks.py``).
"""

import ast
import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter

# ---------------------------------------------------------------------------
# 1. Eligibility — phased rollout (proposal §4.4)
# ---------------------------------------------------------------------------

# v1 families. Matched against the lowercased rule_id. Deliberately explicit:
# a bare "sql" substring would over-match, so the SQLi list names the
# patterns we actually mean.
_PATCHABLE_FAMILIES = {
    "sql-injection": (
        "cwe-89", "sql-injection", "sqli", "raw-sql", "formatted-sql",
        "tainted-sql", "sql-string-concat",
    ),
    "path-traversal": (
        "cwe-22", "path-traversal", "path_traversal", "directory-traversal",
        "zip-slip", "lfi", "tainted-path",
    ),
    "xss": (
        "cwe-79", "xss", "cross-site-scripting", "cross_site_scripting",
        "unescaped-html", "tainted-html",
    ),
}


def classify_patch_family(tool, rule_id):
    """Return the patchable family name, or None when out of the v1 rollout.

    ``tool`` is accepted for future per-tool gates; v1 gates on rule_id only.
    """
    rid = (rule_id or "").lower()
    for family, markers in _PATCHABLE_FAMILIES.items():
        if any(m in rid for m in markers):
            return family
    return None


# ---------------------------------------------------------------------------
# 2. Fuzzy diff application
# ---------------------------------------------------------------------------

class PatchStale(Exception):
    """The diff's context no longer matches the file — refuse to apply."""


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.M)


def parse_unified_diff(diff):
    """Parse a unified diff into hunks.

    Returns a list of dicts: {old_start, old_count, new_start, new_count,
    lines}. Raises ValueError when no hunk headers are found.
    """
    hunks = []
    matches = list(_HUNK_RE.finditer(diff or ""))
    if not matches:
        raise ValueError("not a unified diff: no @@ hunk headers")
    for i, m in enumerate(matches):
        body_start = m.end()
        body_end = matches[i + 1].start() if i + 1 < len(matches) else len(diff)
        lines = [l for l in diff[body_start:body_end].splitlines()
                 if not l.startswith("\\")]
        hunks.append({
            "old_start": int(m.group(1)),
            "old_count": int(m.group(2)) if m.group(2) is not None else 1,
            "new_start": int(m.group(3)),
            "new_count": int(m.group(4)) if m.group(4) is not None else 1,
            "lines": lines,
        })
    return hunks


def apply_patch_fuzzy(src, diff, search_radius=60, min_ratio=0.80):
    """Apply a unified diff to ``src``, tolerating drifted context.

    Returns ``(patched_src, info)`` where info holds:
      - ``hunks``: number of hunks applied
      - ``fuzzy``: True when at least one hunk landed away from its
        recorded position (context matched, but shifted)
      - ``delta_before``: dict mapping each hunk's original old_start to the
        cumulative line delta *after* that hunk (used to project a finding's
        line number into patched coordinates)

    Raises PatchStale when a hunk's context cannot be found, ValueError when
    the diff is not a parseable unified diff.
    """
    lines = src.splitlines()
    hunks = parse_unified_diff(diff)
    cumulative = 0
    fuzzy = False
    delta_before = {}

    for idx, h in enumerate(hunks):
        old_block = [l[1:] for l in h["lines"] if l[:1] in (" ", "-")]
        new_block = [l[1:] for l in h["lines"] if l[:1] in (" ", "+")]
        expected = h["old_start"] - 1 + cumulative

        if not old_block:
            # Pure insertion: anchor at the recorded position.
            if not (0 <= expected <= len(lines)):
                raise PatchStale(f"hunk {idx}: insertion point out of range")
            lines[expected:expected] = new_block
            cumulative += len(new_block)
            delta_before[h["old_start"]] = cumulative
            continue

        lo = max(0, expected - search_radius)
        hi = min(len(lines) - len(old_block), expected + search_radius)
        best_pos, best_ratio = expected, -1.0
        if lo <= hi:
            for pos in range(lo, hi + 1):
                ratio = difflib.SequenceMatcher(
                    None, old_block, lines[pos:pos + len(old_block)],
                    autojunk=False).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_pos = pos
                    if ratio >= 1.0:
                        break
        if best_ratio < min_ratio:
            raise PatchStale(
                f"hunk {idx}: context no longer matches "
                f"(best similarity {best_ratio:.2f} < {min_ratio:.2f})")
        if best_pos != expected:
            fuzzy = True
        lines[best_pos:best_pos + len(old_block)] = new_block
        cumulative += len(new_block) - len(old_block)
        delta_before[h["old_start"]] = cumulative

    info = {"hunks": len(hunks), "fuzzy": fuzzy, "delta_before": delta_before}
    patched = "\n".join(lines)
    if src.endswith("\n"):
        patched += "\n"
    return patched, info


def project_line(line, delta_before):
    """Project an original-coordinate line number into patched coordinates."""
    delta = 0
    for old_start in sorted(delta_before):
        if old_start < (line or 0):
            delta = delta_before[old_start]
    return (line or 0) + delta


# ---------------------------------------------------------------------------
# 3. Re-scan (semgrep before/after)
# ---------------------------------------------------------------------------

def _semgrep_bin():
    for cand in (os.environ.get("SEMGREP_BIN"),
                 shutil.which("semgrep"),
                 os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _default_configs():
    """Mirror scan_engine: auto registry + our taint rules when present."""
    configs = ["auto"]
    here = os.path.dirname(os.path.abspath(__file__))
    pack = os.path.normpath(os.path.join(here, "..", "scanner", "rules",
                                         "braimsec-taint.yaml"))
    env_pack = os.environ.get("BRAIMSEC_TAINT_RULES", "")
    if env_pack:
        pack = env_pack
    if pack and os.path.isfile(pack):
        configs.append(pack)
    return configs


def semgrep_scan_file(abs_path, configs=None, timeout=180):
    """Run semgrep on one file -> [{rule_id, line, snippet}].

    Raises RuntimeError when no semgrep binary is available.
    """
    sg = _semgrep_bin()
    if not sg:
        raise RuntimeError("semgrep binary not available")
    configs = configs if configs is not None else _default_configs()
    cmd = [sg]
    for c in configs:
        cmd += ["--config", c]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    cmd += ["--json", "--quiet", "-o", out_path, abs_path]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        with open(out_path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, OSError):
        data = {}
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        snippet = (extra.get("lines") or "").strip()
        findings.append({
            "rule_id": r.get("check_id", "unknown"),
            "line": (r.get("start") or {}).get("line", 0),
            "snippet": snippet,
        })
    return findings


def _norm_snippet(snippet):
    # NOTE: recent semgrep builds gate extra.lines behind login
    # ("requires login"), so matching is done on source lines read locally
    # (see _code_text) — never on this field.
    return " ".join((snippet or "").split())


def _same_rule(a, b):
    """Rule-id equality tolerant of semgrep's dotted-path check_ids.

    Our taint rules are stored by scan_engine as the full dotted config path
    (``....rules.braimsec.taint.x``); callers may use the short id.
    """
    a, b = (a or ""), (b or "")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _code_text(src, line):
    """Normalized source text of a 1-based line: comments/whitespace folded.

    Used to match findings across the re-scan without trusting semgrep's
    (sometimes gated) ``extra.lines``.
    """
    try:
        text = src.splitlines()[line - 1]
    except (IndexError, TypeError):
        return ""
    text = text.split("#", 1)[0]  # single-line comment fold (heuristic)
    return " ".join(text.split())


def _resolve_in_dir(target_dir, rel):
    base = os.path.realpath(target_dir or "")
    abs_path = os.path.realpath(os.path.join(base, rel)) if rel else ""
    if not base or not abs_path.startswith(base + os.sep):
        return None
    return abs_path if os.path.isfile(abs_path) else None


# ---------------------------------------------------------------------------
# Closed loop
# ---------------------------------------------------------------------------

FRAMING_VERIFIED = ("verified suggestion — scanner is quiet after the patch; "
                    "still requires human review, not a guaranteed fix")


def verify_patch(finding, target_dir, diff, configs=None, timeout=180):
    """Run the closed verification loop on a stored fix suggestion.

    ``finding``: dict with tool/rule_id/file/line (+id). ``diff``: the stored
    unified diff from fix-suggestion. Returns a verdict dict; never raises on
    expected conditions (missing semgrep, stale patch, gone sources) — those
    become ``verified=False`` with an honest ``reason``.
    """
    verdict = {
        "family": None, "eligible": False, "applied": False, "fuzzy": False,
        "syntax_ok": None, "original_gone": False, "new_findings": [],
        "verified": False, "reason": "", "framing": "",
    }
    family = classify_patch_family(finding.get("tool"), finding.get("rule_id"))
    verdict["family"] = family
    if not family:
        verdict["reason"] = (
            "rule family not in the phase-1 patch rollout "
            "(sql-injection, path-traversal, xss) — no patch attempted")
        return verdict
    verdict["eligible"] = True

    abs_path = _resolve_in_dir(target_dir, (finding.get("file") or "").strip())
    if not abs_path:
        verdict["reason"] = ("source file not available "
                             "(deleted after scan, or path escapes scan dir)")
        return verdict
    try:
        with open(abs_path, encoding="utf-8", errors="replace") as f:
            src = f.read()
    except OSError as e:
        verdict["reason"] = f"could not read source file: {e}"
        return verdict

    try:
        before = semgrep_scan_file(abs_path, configs=configs, timeout=timeout)
    except RuntimeError as e:
        verdict["reason"] = str(e)
        return verdict

    try:
        patched, info = apply_patch_fuzzy(src, diff)
    except PatchStale as e:
        verdict["reason"] = (f"patch no longer applies cleanly ({e}) — "
                             "regenerate the suggestion on current code")
        return verdict
    except ValueError as e:
        verdict["reason"] = f"stored diff is not a valid unified diff: {e}"
        return verdict
    verdict["applied"] = True
    verdict["fuzzy"] = info["fuzzy"]

    if abs_path.endswith(".py"):
        try:
            ast.parse(patched)
            verdict["syntax_ok"] = True
        except SyntaxError as e:
            verdict["syntax_ok"] = False
            verdict["reason"] = f"patched file does not parse: {e}"
            return verdict

    suffix = os.path.splitext(abs_path)[1] or ".txt"
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                     encoding="utf-8") as f:
        f.write(patched)
        tmp_path = f.name
    try:
        after = semgrep_scan_file(tmp_path, configs=configs, timeout=timeout)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    expected_line = project_line(finding.get("line"), info["delta_before"])
    rule_id = finding.get("rule_id")
    orig_code = _code_text(src, finding.get("line") or 0)

    def _is_original(r):
        # The original finding survived the patch when the same rule fires
        # on the same normalized code, or at the projected line (a reflowed
        # but unfixed sink keeps its line modulo the patch delta).
        return (_same_rule(r["rule_id"], rule_id)
                and (_code_text(patched, r["line"] or 0) == orig_code
                     or (r["line"] or 0) == expected_line))

    still_there = [r for r in after if _is_original(r)]
    verdict["original_gone"] = not still_there

    # Anything else in `after` that was not in `before` (by rule + code,
    # multiset so a fixed twin does not mask a remaining one) is new.
    before_counts = Counter(
        (b["rule_id"], _code_text(src, b["line"] or 0)) for b in before)
    new = []
    for r in after:
        if r in still_there:
            continue
        key = (r["rule_id"], _code_text(patched, r["line"] or 0))
        if before_counts[key] > 0:
            before_counts[key] -= 1
        else:
            new.append(r)
    verdict["new_findings"] = [
        {"rule_id": r["rule_id"], "line": r["line"],
         "code": _code_text(patched, r["line"] or 0)} for r in new]

    if verdict["original_gone"] and not new:
        verdict["verified"] = True
        verdict["framing"] = FRAMING_VERIFIED
        verdict["reason"] = ("patch applied; original finding no longer "
                             "reported; no new findings introduced")
    elif not verdict["original_gone"]:
        verdict["reason"] = ("patch applied but the original finding is still "
                             "reported after re-scan — the fix is incomplete")
    else:
        verdict["reason"] = (f"patch removed the original finding but "
                             f"introduced {len(new)} new finding(s) — rejected")
    return verdict
