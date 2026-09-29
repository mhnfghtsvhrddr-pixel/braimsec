"""Tests for scanner/prbot.py (Proposal Part 4: PR Review Bot).

Unit (no semgrep/git):
- diff -> added-lines parsing
- same-line dedup (3 findings, 1 line -> 1 comment)
- gates: severity floor, AI vulnerable/safe/failure/unconfigured, gitleaks
  deterministic pass
- comment + review payload shapes, post dry-run

End-to-end (real git repo + real semgrep, AI stubbed):
- new SSRF on added lines -> exactly 1 inline comment
- legacy vuln MOVED by refactoring -> no comment (base-branch dedup)
"""
import json
import os
import subprocess
import sys

import pytest

os.environ.setdefault("SEMGREP_BIN",
                      os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep"))
os.environ.setdefault("GITLEAKS_BIN",
                      os.path.expanduser("~/workspace/bin/gitleaks"))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import prbot
from prbot import (
    added_lines,
    apply_gates,
    build_comment,
    build_review_payload,
    dedupe_by_line,
    post_review,
    run_bot,
)

SG_OK = os.path.isfile(os.environ["SEMGREP_BIN"])

VULN_FUNC = '''\
import requests
from flask import request

def fetch():
    url = request.args.get("u")
    return requests.get(url, timeout=5).text
'''


def _syn(tool="semgrep", rule="r", sev="error", file="/repo/a.py", line=1):
    return {"tool": tool, "rule_id": rule, "severity": sev,
            "message": "m", "file": file, "line": line, "col": 1}


class _StubClient:
    configured = True


def _vuln_ai(monkeypatch):
    monkeypatch.setattr(
        prbot, "analyze_finding",
        lambda client, finding, snippet="": {
            "ai_verdict": "vulnerable", "ai_confidence": 0.9,
            "ai_explanation": "شرح تجريبي",
            "ai_family": "taint"})


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------

DIFF_FIXTURE = """\
diff --git a/app.py b/app.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/app.py
@@ -0,0 +1,3 @@
+line one
+line two
+line three
diff --git a/old.py b/new.py
similarity index 90% 100%
rename from old.py
rename to new.py
--- a/old.py
+++ b/new.py
@@ -5,2 +5,3 @@
 ctx
-old line
+new line one
+new line two
"""


def test_added_lines_parse():
    added = added_lines(DIFF_FIXTURE)
    assert added["app.py"] == {1, 2, 3}
    # rename: +++ b/ path wins
    assert added["new.py"] == {6, 7}


def test_added_lines_empty():
    assert added_lines("") == {}


# ---------------------------------------------------------------------------
# Same-line dedup
# ---------------------------------------------------------------------------

def test_dedupe_by_line_keeps_taint_rule():
    fs = [_syn(rule="python.flask.security.injection.ssrf-requests.ssrf-requests"),
          _syn(rule="braimsec.taint.ssrf-requests"),
          _syn(rule="python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests")]
    kept, stats = dedupe_by_line(fs, "/repo")
    assert len(kept) == 1
    assert kept[0]["rule_id"] == "braimsec.taint.ssrf-requests"
    assert stats["line_dups"] == 2


def test_dedupe_by_line_distinct_lines_kept():
    fs = [_syn(line=1), _syn(line=2)]
    kept, _ = dedupe_by_line(fs, "/repo")
    assert len(kept) == 2


def test_collapse_taint_overlaps(tmp_path):
    # registry rule flags the SOURCE line (5), ours the SINK line (6):
    # same flow -> one finding survives (pure-AST, no semgrep needed)
    src = tmp_path / "v.py"
    src.write_text(VULN_FUNC)
    fs = [_syn(rule="python.django.security.injection.ssrf.ssrf-injection-requests.ssrf-injection-requests",
               file=str(src), line=5),
          _syn(rule="braimsec.taint.ssrf-requests", file=str(src), line=6)]
    kept, n = prbot._collapse_taint_overlaps(fs, str(tmp_path))
    assert n == 1 and len(kept) == 1
    assert kept[0]["line"] == 6


def test_collapse_no_taint_noop(tmp_path):
    fs = [_syn(rule="x", line=5), _syn(rule="y", line=6)]
    kept, n = prbot._collapse_taint_overlaps(fs, str(tmp_path))
    assert kept == fs and n == 0


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

def test_gate_drops_warnings(monkeypatch):
    _vuln_ai(monkeypatch)
    ok, dropped = apply_gates([_syn(sev="warning")], "/repo", _StubClient())
    assert ok == [] and len(dropped) == 1
    assert "severity gate" in dropped[0][1]


def test_gate_ai_vulnerable_passes(monkeypatch):
    _vuln_ai(monkeypatch)
    ok, dropped = apply_gates([_syn()], "/repo", _StubClient())
    assert len(ok) == 1 and dropped == []
    assert ok[0][1]["ai_verdict"] == "vulnerable"


def test_gate_ai_safe_dropped(monkeypatch):
    monkeypatch.setattr(
        prbot, "analyze_finding",
        lambda c, f, snippet="": {"ai_verdict": "false_positive",
                                  "ai_confidence": 0.9, "ai_explanation": "x"})
    ok, dropped = apply_gates([_syn()], "/repo", _StubClient())
    assert ok == [] and "false_positive" in dropped[0][1]


def test_gate_ai_failure_stays_silent(monkeypatch):
    def boom(client, finding, snippet=""):
        raise RuntimeError("llm down")
    monkeypatch.setattr(prbot, "analyze_finding", boom)
    ok, dropped = apply_gates([_syn()], "/repo", _StubClient())
    assert ok == [] and "ai gate: analyzer failed" in dropped[0][1]


def test_gate_ai_unconfigured_dropped(monkeypatch):
    _vuln_ai(monkeypatch)
    ok, dropped = apply_gates([_syn()], "/repo", None)
    assert ok == [] and "not configured" in dropped[0][1]


def test_gate_gitleaks_passes_without_ai(monkeypatch):
    def must_not_run(*a, **k):
        raise AssertionError("AI must not be consulted for secrets")
    monkeypatch.setattr(prbot, "analyze_finding", must_not_run)
    f = _syn(tool="gitleaks", rule="generic-api-key")
    ok, dropped = apply_gates([f], "/repo", None)
    assert len(ok) == 1 and ok[0][1] is None and dropped == []


def test_gate_min_severity_configurable(monkeypatch):
    _vuln_ai(monkeypatch)
    ok, _ = apply_gates([_syn(sev="warning")], "/repo", _StubClient(),
                        min_severity="warning")
    assert len(ok) == 1


# ---------------------------------------------------------------------------
# Comment / payload shapes
# ---------------------------------------------------------------------------

def test_build_comment_shape(monkeypatch, tmp_path):
    _vuln_ai(monkeypatch)
    monkeypatch.setattr(prbot, "extract_taint_path", None)
    f = _syn(rule="braimsec.taint.ssrf-requests", file=str(tmp_path / "a.py"),
             line=6)
    c = build_comment(f, {"ai_verdict": "vulnerable", "ai_confidence": 0.9,
                          "ai_explanation": "شرح"}, str(tmp_path),
                      client=_StubClient())
    assert c["path"] == "a.py" and c["line"] == 6
    assert "BraimSec" in c["body"] and "vulnerable" in c["body"]
    assert "braimsec.taint.ssrf-requests" in c["body"]


def test_build_review_payload_shape():
    comments = [{"path": "a.py", "line": 6, "body": "b"}]
    p = build_review_payload(comments, "abc123", "summary")
    assert p["commit_id"] == "abc123" and p["event"] == "COMMENT"
    assert p["comments"][0]["side"] == "RIGHT"
    assert p["comments"][0]["path"] == "a.py"


def test_post_review_dry_run():
    p = build_review_payload([{"path": "a", "line": 1, "body": "b"}], "s",
                             "sum")
    assert post_review("o/r", 1, "tok", p, dry_run=True) == {
        "dry_run": True, "would_post": 1}


# ---------------------------------------------------------------------------
# End-to-end on a real git repo
# ---------------------------------------------------------------------------

def _git(repo, *args):
    subprocess.run(["git", "-C", repo, *args], check=True,
                   capture_output=True, timeout=60)


@pytest.fixture()
def pr_repo(tmp_path):
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (tmp_path / "repo" / "legacy.py").write_text(VULN_FUNC)
    (tmp_path / "repo" / "clean.py").write_text('x = 1\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    # head: NEW ssrf in app.py + legacy vuln MOVED down (refactor)
    (tmp_path / "repo" / "app.py").write_text(VULN_FUNC)
    moved = VULN_FUNC.replace(
        "import requests\n",
        "import requests\n# refactor note\n# another note\n", 1)
    (tmp_path / "repo" / "legacy.py").write_text(moved)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "pr")
    return repo


@pytest.mark.skipif(not SG_OK, reason="semgrep not installed")
def test_e2e_new_vuln_commented_moved_legacy_not(pr_repo, monkeypatch):
    _vuln_ai(monkeypatch)
    res = run_bot(pr_repo, "HEAD~1", "HEAD", ai=True, client=_StubClient())
    assert res["stats"]["changed_files"] == 2
    assert res["stats"]["comments"] == 1, json.dumps(res["stats"])
    c = res["comments"][0]
    assert c["path"] == "app.py" and c["line"] == 6
    # the moved legacy vuln was filtered by the base-branch dedup,
    # the registry duplicates collapsed by line-dedup
    assert res["stats"]["line_dups"] >= 1
    assert all(d["file"] != "legacy.py" or "legacy" in d["reason"]
               for d in res["dropped"])
    assert "BraimSec" in c["body"]


@pytest.mark.skipif(not SG_OK, reason="semgrep not installed")
def test_e2e_no_ai_means_no_taint_comments(pr_repo):
    res = run_bot(pr_repo, "HEAD~1", "HEAD", ai=False)
    assert res["comments"] == []
    assert any("ai gate" in d["reason"] for d in res["dropped"])
