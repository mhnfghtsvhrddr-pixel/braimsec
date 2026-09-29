"""Tests for scanner/taintflow.py (Proposal Part 3, v1: linear trace).

Covers, without any live LLM or network:

- AST backward slicing: linear source->propagation->sink, direct source
  at the sink, sanitized (html.escape), uncertain (custom clean fn),
  method-call propagation (.strip() is NOT an unverified transform)
- semgrep --dataflow-traces text parser on a captured fixture
- _semgrep_trace_steps: graceful None when the binary is missing
- extract_taint_path: semgrep->AST fallback, unavailable paths
- one live semgrep integration test (skipped when the binary is absent)
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import taintflow
from taintflow import (
    _semgrep_trace_steps,
    ast_backward_slice,
    extract_taint_path,
    parse_dataflow_text,
    sanitize_verdict,
)

SG_BIN = os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep")

UNSANITIZED_SRC = """\
import requests
from flask import request

def fetch():
    raw = request.args.get("u")
    cleaned = raw.strip()
    url = "https://" + cleaned
    return requests.get(url, timeout=5).text
"""

SANITIZED_SRC = """\
import html
import requests
from flask import request

def fetch():
    raw = request.args.get("u")
    safe = html.escape(raw)
    return requests.get("https://x/" + safe, timeout=5).text
"""

UNCERTAIN_SRC = """\
import requests
from flask import request

def clean_url(u):
    return u.replace("..", "")

def fetch():
    raw = request.args.get("u")
    url = clean_url(raw)
    return requests.get(url, timeout=5).text
"""

DIRECT_SRC = """\
import requests
from flask import request

def fetch():
    return requests.get(request.args.get("u"), timeout=5).text
"""


def _write(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return str(p)


def _types(steps):
    return [s["type"] for s in steps]


# ---------------------------------------------------------------------------
# AST backward slicing
# ---------------------------------------------------------------------------

def test_ast_slice_linear_trace(tmp_path):
    p = _write(tmp_path, "a.py", UNSANITIZED_SRC)
    steps = ast_backward_slice(p, 8)
    assert _types(steps) == ["source", "propagation", "propagation", "sink"]
    assert [s["line"] for s in steps] == [5, 6, 7, 8]
    assert all(s["origin"] == "ast-slice" for s in steps)
    assert steps[0]["snippet"].startswith('raw = request.args.get("u")')
    assert steps[-1]["snippet"].startswith("return requests.get(url")
    verdict, details = sanitize_verdict(steps)
    assert verdict == "unsanitized"
    assert details["unverified_transforms"] == []


def test_ast_slice_direct_source_at_sink(tmp_path):
    p = _write(tmp_path, "b.py", DIRECT_SRC)
    steps = ast_backward_slice(p, 5)
    assert _types(steps) == ["source", "sink"]
    assert steps[0]["line"] == 5
    assert "request.args.get" in steps[0]["snippet"]


def test_ast_slice_sanitized(tmp_path):
    p = _write(tmp_path, "c.py", SANITIZED_SRC)
    steps = ast_backward_slice(p, 8)
    verdict, details = sanitize_verdict(steps)
    assert verdict == "sanitized"
    assert any("html.escape" in s for s in details["sanitizers"])


def test_ast_slice_uncertain_custom_cleaner(tmp_path):
    p = _write(tmp_path, "d.py", UNCERTAIN_SRC)
    steps = ast_backward_slice(p, 10)
    verdict, details = sanitize_verdict(steps)
    assert verdict == "uncertain"
    assert any("clean_url" in u for u in details["unverified_transforms"])


def test_ast_slice_method_call_is_propagation_not_unverified(tmp_path):
    # .strip() must not flip the verdict to uncertain (documented heuristic)
    p = _write(tmp_path, "a.py", UNSANITIZED_SRC)
    steps = ast_backward_slice(p, 8)
    verdict, _ = sanitize_verdict(steps)
    assert verdict == "unsanitized"


def test_ast_slice_broken_file_returns_empty(tmp_path):
    p = _write(tmp_path, "bad.py", "def broken(:\n")
    assert ast_backward_slice(p, 1) == []


def test_sanitize_never_emits_ai_inferred(tmp_path):
    p = _write(tmp_path, "a.py", UNSANITIZED_SRC)
    steps = ast_backward_slice(p, 8)
    assert all(s["origin"] != "ai-inferred" for s in steps)


# ---------------------------------------------------------------------------
# semgrep --dataflow-traces text parser (captured fixture)
# ---------------------------------------------------------------------------

TRACE_FIXTURE = """\
    multi.py
   ❯❯❱ home.hatch.workspace.goals.goal-3.repo.scanner.rules.braimsec.taint.ssrf-requests
          ❰❰ Blocking ❱❱
          User-controlled URL passed to requests — possible Server-Side Request Forgery (SSRF). Validate the
          URL against an allowlist of hosts/schemes before requesting it.
            8┆ return requests.get(url, timeout=5).text


          Taint comes from:

            5┆ raw = request.args.get("u")


          Taint flows through these intermediate variables:

            5┆ raw = request.args.get("u")

            6┆ cleaned = raw.strip()

            7┆ url = "https://" + cleaned


                This is how taint reaches the sink:

            8┆ return requests.get(url, timeout=5).text
"""


def test_parse_dataflow_text_fixture():
    blocks = parse_dataflow_text(TRACE_FIXTURE)
    assert len(blocks) == 1
    b = blocks[0]
    assert b["rule"].endswith("braimsec.taint.ssrf-requests")
    assert b["sink_line"] == 8
    assert b["sources"] == [(5, 'raw = request.args.get("u")')]
    assert (6, "cleaned = raw.strip()") in b["intermediates"]
    assert (7, 'url = "https://" + cleaned') in b["intermediates"]


def test_parse_dataflow_text_empty():
    assert parse_dataflow_text("no findings here\n") == []


def test_semgrep_trace_steps_missing_binary(tmp_path, monkeypatch):
    p = _write(tmp_path, "a.py", UNSANITIZED_SRC)
    monkeypatch.setattr(taintflow, "SEMGREP_BIN", "/nonexistent/semgrep")
    assert _semgrep_trace_steps(p, "braimsec.taint.ssrf-requests", 8) is None


@pytest.mark.skipif(not os.path.isfile(SG_BIN),
                    reason="semgrep binary not installed here")
def test_semgrep_trace_steps_live(tmp_path, monkeypatch):
    monkeypatch.setattr(taintflow, "SEMGREP_BIN", SG_BIN)
    p = _write(tmp_path, "live.py", UNSANITIZED_SRC)
    steps = _semgrep_trace_steps(p, "braimsec.taint.ssrf-requests", 8)
    assert steps, "expected a live semgrep trace"
    assert _types(steps) == ["source", "propagation", "propagation", "sink"]
    assert all(s["origin"] == "semgrep-trace" for s in steps)
    assert [s["line"] for s in steps] == [5, 6, 7, 8]


# ---------------------------------------------------------------------------
# extract_taint_path
# ---------------------------------------------------------------------------

def _finding(**kw):
    d = {"id": 1, "tool": "semgrep",
         "rule_id": "braimsec.taint.ssrf-requests",
         "file": "app.py", "line": 8}
    d.update(kw)
    return d


def test_extract_falls_back_to_ast_when_no_semgrep(tmp_path, monkeypatch):
    _write(tmp_path, "app.py", UNSANITIZED_SRC)
    monkeypatch.setattr(taintflow, "SEMGREP_BIN", "/nonexistent/semgrep")
    out = extract_taint_path(_finding(), str(tmp_path))
    assert out["available"] is True
    assert out["trace_origin"] == "ast-slice"
    assert _types(out["taint_path"]) == [
        "source", "propagation", "propagation", "sink"]
    assert out["sanitization"]["verdict"] == "unsanitized"
    assert out["engine"] == "taintflow-v1"
    assert out["limits"], "honest limits must be present"
    # proposal §2 schema keys
    for s in out["taint_path"]:
        assert set(s) >= {"step", "type", "file", "line", "snippet",
                          "origin"}


def test_extract_sanitized_path(tmp_path, monkeypatch):
    _write(tmp_path, "app.py", SANITIZED_SRC)
    monkeypatch.setattr(taintflow, "SEMGREP_BIN", "/nonexistent/semgrep")
    out = extract_taint_path(_finding(line=8), str(tmp_path))
    assert out["sanitization"]["verdict"] == "sanitized"


def test_extract_unavailable_missing_file(tmp_path):
    out = extract_taint_path(_finding(file="nope.py"), str(tmp_path))
    assert out["available"] is False


def test_extract_rejects_path_escape(tmp_path):
    out = extract_taint_path(_finding(file="../../etc/passwd"), str(tmp_path))
    assert out["available"] is False
    assert "escapes" in out["reason"]


def test_extract_non_python_unavailable(tmp_path):
    (tmp_path / "app.js").write_text("var x = 1;\n")
    out = extract_taint_path(_finding(file="app.js", tool="eslint"),
                             str(tmp_path))
    assert out["available"] is False
