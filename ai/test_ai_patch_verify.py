"""Tests for ai/patch_verify.py — the closed-loop auto-patch engine.

Unit tests (eligibility, fuzzy application) run without semgrep.
End-to-end verification tests need a semgrep binary and are skipped
otherwise (same convention as scanner/test_taint_rules.py).
"""

import difflib
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from patch_verify import (  # noqa: E402
    PatchStale,
    apply_patch_fuzzy,
    classify_patch_family,
    parse_unified_diff,
    project_line,
    semgrep_scan_file,
    verify_patch,
)

TAINT_RULES = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scanner", "rules",
    "braimsec-taint.yaml"))


def _semgrep():
    for cand in (os.environ.get("SEMGREP_BIN"),
                 shutil.which("semgrep"),
                 os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


needs_sg = pytest.mark.skipif(_semgrep() is None,
                              reason="semgrep binary not found")


def _diff(old, new, name="app.py"):
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile="a/" + name, tofile="b/" + name))


# ---------------------------------------------------------------------------
# 1. Eligibility
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id,expected", [
    ("braimsec.taint.path-traversal-open", "path-traversal"),
    ("python.lang.security.audit.path-traversal", "path-traversal"),
    ("python.django.security.audit.raw-sql", "sql-injection"),
    ("python.lang.security.audit.formatted-sql-query", "sql-injection"),
    ("javascript.lang.security.audit.xss", "xss"),
    ("CWE-89-whatever", "sql-injection"),
    ("braimsec.taint.ssrf-requests", None),          # phase 2, not v1
    ("braimsec.taint.unrestricted-file-upload", None),
    ("generic-api-key", None),                        # gitleaks: not patchable
    ("", None),
    (None, None),
])
def test_classify_patch_family(rule_id, expected):
    assert classify_patch_family("semgrep", rule_id) == expected


# ---------------------------------------------------------------------------
# 2. Fuzzy application
# ---------------------------------------------------------------------------

SRC = ("import os\n"
       "\n"
       "def run(cmd):\n"
       "    os.system(\"ls \" + cmd)\n"
       "\n"
       "def ok():\n"
       "    return 1\n")

PATCHED = SRC.replace('    os.system("ls " + cmd)',
                      '    subprocess.run(["ls", cmd], check=True)')
PATCHED = PATCHED.replace("import os\n", "import os\nimport subprocess\n")


def test_apply_clean(tmp_path):
    diff = _diff(SRC, PATCHED)
    out, info = apply_patch_fuzzy(SRC, diff)
    assert out == PATCHED
    assert info["hunks"] == 1  # both edits are within one context window
    assert info["fuzzy"] is False


def test_apply_shifted_context_still_lands():
    # File drifted: 5 lines were added above since the suggestion was made.
    drifted = "# header\n" * 5 + SRC
    diff = _diff(SRC, PATCHED)
    out, info = apply_patch_fuzzy(drifted, diff)
    assert out == "# header\n" * 5 + PATCHED
    assert info["fuzzy"] is True  # landed away from recorded positions


def test_apply_stale_context_raises():
    rewritten = SRC.replace('    os.system("ls " + cmd)',
                            '    print("totally different call here")\n'
                            '    print("more different lines")\n'
                            '    print("even more")')
    diff = _diff(SRC, PATCHED)
    with pytest.raises(PatchStale):
        apply_patch_fuzzy(rewritten, diff)


def test_apply_pure_insertion():
    old = "a\nb\n"
    new = "a\ninserted\nb\n"
    out, info = apply_patch_fuzzy(old, _diff(old, new))
    assert out == new
    assert info["hunks"] == 1


def test_apply_malformed_diff_raises_value_error():
    with pytest.raises(ValueError):
        apply_patch_fuzzy(SRC, "this is not a diff at all")


def test_parse_unified_diff_hunk_headers():
    diff = _diff(SRC, PATCHED)
    hunks = parse_unified_diff(diff)
    assert len(hunks) == 1
    assert all("old_start" in h and "lines" in h for h in hunks)


def test_project_line_uses_hunk_deltas():
    # one hunk before line 10 added 2 lines -> line 10 projects to 12
    assert project_line(10, {4: 2}) == 12
    assert project_line(3, {4: 2}) == 3   # before the hunk: unchanged
    assert project_line(10, {}) == 10


# ---------------------------------------------------------------------------
# 3. Re-scan plumbing
# ---------------------------------------------------------------------------

VULN_TRAVERSAL = ("from flask import request\n"
                  "\n"
                  "def download():\n"
                  '    name = request.args.get("f")\n'
                  "    data = open(name).read()\n"
                  "    return data\n")

FIXED_TRAVERSAL = ("from flask import request\n"
                   "import os\n"
                   "\n"
                   "def download():\n"
                   '    name = request.args.get("f")\n'
                   "    safe = os.path.basename(name)\n"
                   "    data = open(safe).read()\n"
                   "    return data\n")


@needs_sg
def test_semgrep_scan_file_finds_traversal(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(VULN_TRAVERSAL)
    found = semgrep_scan_file(str(p), configs=[TAINT_RULES])
    rule_ids = [f["rule_id"] for f in found]
    # semgrep reports our pack rules with the full dotted config path
    assert any(r.endswith("braimsec.taint.path-traversal-open")
               for r in rule_ids)
    assert any(f["line"] == 5 for f in found)


@needs_sg
def test_semgrep_scan_file_quiet_after_fix(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(FIXED_TRAVERSAL)
    found = semgrep_scan_file(str(p), configs=[TAINT_RULES])
    assert [f["rule_id"] for f in found] == []


# ---------------------------------------------------------------------------
# 4. Closed loop — verify_patch
# ---------------------------------------------------------------------------

def _finding(**kw):
    d = {"id": 1, "tool": "semgrep",
         "rule_id": "braimsec.taint.path-traversal-open",
         "file": "app.py", "line": 5}
    d.update(kw)
    return d


@needs_sg
def test_verify_good_patch(tmp_path):
    (tmp_path / "app.py").write_text(VULN_TRAVERSAL)
    diff = _diff(VULN_TRAVERSAL, FIXED_TRAVERSAL)
    v = verify_patch(_finding(), str(tmp_path), diff, configs=[TAINT_RULES])
    assert v["eligible"] is True
    assert v["family"] == "path-traversal"
    assert v["applied"] is True
    assert v["fuzzy"] is False
    assert v["syntax_ok"] is True
    assert v["original_gone"] is True
    assert v["new_findings"] == []
    assert v["verified"] is True
    assert "human review" in v["framing"]


@needs_sg
def test_verify_bad_patch_still_reported(tmp_path):
    # Patch that applies but does NOT remove the sink.
    bad = VULN_TRAVERSAL.replace("    data = open(name).read()",
                                 "    data = open(name).read()  # nosec")
    (tmp_path / "app.py").write_text(VULN_TRAVERSAL)
    diff = _diff(VULN_TRAVERSAL, bad)
    v = verify_patch(_finding(), str(tmp_path), diff, configs=[TAINT_RULES])
    assert v["applied"] is True
    assert v["original_gone"] is False
    assert v["verified"] is False
    assert "still reported" in v["reason"]


@needs_sg
def test_verify_rejects_patch_introducing_new_finding(tmp_path):
    new_vuln = (FIXED_TRAVERSAL +
                "\n"
                "def preview():\n"
                '    other = request.args["p"]\n'
                "    return open(other).read()\n")
    (tmp_path / "app.py").write_text(VULN_TRAVERSAL)
    diff = _diff(VULN_TRAVERSAL, new_vuln)
    v = verify_patch(_finding(), str(tmp_path), diff, configs=[TAINT_RULES])
    assert v["original_gone"] is True
    assert len(v["new_findings"]) == 1
    assert v["new_findings"][0]["rule_id"].endswith(
        "braimsec.taint.path-traversal-open")
    assert v["verified"] is False
    assert "new finding" in v["reason"]


@needs_sg
def test_verify_syntax_breaking_patch_rejected(tmp_path):
    broken = VULN_TRAVERSAL.replace("    data = open(name).read()",
                                    "    def broken(:")
    (tmp_path / "app.py").write_text(VULN_TRAVERSAL)
    diff = _diff(VULN_TRAVERSAL, broken)
    v = verify_patch(_finding(), str(tmp_path), diff, configs=[TAINT_RULES])
    assert v["applied"] is True
    assert v["syntax_ok"] is False
    assert v["verified"] is False


@needs_sg
def test_verify_stale_patch_declared(tmp_path):
    drifted = ("from flask import request\n"
               "\n"
               "def download():\n"
               '    fname = request.args.get("f")\n'
               "    data = open(fname).read()\n"
               "    return data\n")
    (tmp_path / "app.py").write_text(drifted)
    diff = _diff(VULN_TRAVERSAL, FIXED_TRAVERSAL)  # built against old code
    v = verify_patch(_finding(), str(tmp_path), diff, configs=[TAINT_RULES])
    assert v["applied"] is False
    assert v["verified"] is False
    assert "no longer applies cleanly" in v["reason"]


def test_verify_ineligible_family_no_scan(tmp_path):
    # SSRF is phase-2: verdict without touching semgrep or the file.
    v = verify_patch(_finding(rule_id="braimsec.taint.ssrf-requests"),
                     "/nonexistent", "whatever")
    assert v["eligible"] is False
    assert v["verified"] is False
    assert "phase-1" in v["reason"]


def test_verify_missing_source_file(tmp_path):
    v = verify_patch(_finding(), str(tmp_path), _diff("a", "b"))
    assert v["eligible"] is True
    assert v["verified"] is False
    assert "not available" in v["reason"]


def test_verify_path_escape_rejected(tmp_path):
    v = verify_patch(_finding(file="../../etc/passwd"), str(tmp_path),
                     _diff("a", "b"))
    assert v["verified"] is False
