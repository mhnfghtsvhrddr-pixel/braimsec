"""Fail-closed behavior of the scan engines.

- An empty incremental scope must return [] without invoking any engine
  (and must NOT fall back to scanning the whole target).
- A crashed semgrep (non-zero exit, no output file) must raise EngineError,
  never masquerade as a clean scan.
- A missing/corrupt engine report must raise EngineError even when the
  exit code is 0: both engines always write valid JSON on success
  (verified empirically), so an unreadable report means malfunction.
"""
import os

import pytest

import scan_engine
from scan_engine import EngineError, run_gitleaks, run_semgrep


def test_empty_scope_returns_empty_without_running(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        raise AssertionError("engine must not run on empty scope")

    monkeypatch.setattr(scan_engine.subprocess, "run", fake_run)
    assert run_semgrep(str(tmp_path), scope=[]) == []
    assert run_gitleaks(str(tmp_path), scope=[]) == []
    assert calls == []


def test_none_scope_still_scans_target(tmp_path, monkeypatch):
    # None means "full target": the engine must be invoked with the target.
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        import subprocess as sp

        return sp.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(scan_engine, "_run", fake_run)
    # _run is stubbed and writes no output file -> fail closed: the
    # missing report must raise EngineError, never look like a clean scan.
    # The assertion that matters: the target dir reached the engine
    # command line before the failure.
    with pytest.raises(EngineError, match="no parseable report"):
        run_semgrep(str(tmp_path), scope=None)
    assert str(tmp_path) in seen[0]


def _stub_run_with_report(monkeypatch, report_text):
    """Stub _run to write report_text as the engine's JSON output file."""
    import json as _json
    import subprocess as sp

    def fake_run(cmd, **kw):
        out = [a for i, a in enumerate(cmd)
               if a == "-o" and i + 1 < len(cmd)]
        if out:
            with open(cmd[cmd.index("-o") + 1], "w") as f:
                f.write(report_text)
        else:  # gitleaks: --report-path <path>
            rp = cmd[cmd.index("--report-path") + 1]
            with open(rp, "w") as f:
                f.write(report_text)
        return sp.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(scan_engine, "_run", fake_run)


def test_semgrep_corrupt_json_raises_engine_error(tmp_path, monkeypatch):
    _stub_run_with_report(monkeypatch, "{not valid json")
    with pytest.raises(EngineError, match="no parseable report"):
        run_semgrep(str(tmp_path))


def test_semgrep_valid_empty_report_returns_clean(tmp_path, monkeypatch):
    _stub_run_with_report(monkeypatch, '{"results": [], "errors": []}')
    assert run_semgrep(str(tmp_path)) == []


def test_gitleaks_corrupt_json_raises_engine_error(tmp_path, monkeypatch):
    _stub_run_with_report(monkeypatch, "[{broken")
    with pytest.raises(EngineError, match="no parseable report"):
        run_gitleaks(str(tmp_path))


def test_gitleaks_valid_empty_reports_return_clean(tmp_path, monkeypatch):
    # gitleaks writes [] (and older versions null) when no leaks are found:
    # both are legitimate clean scans, not engine failures.
    _stub_run_with_report(monkeypatch, "[]")
    assert run_gitleaks(str(tmp_path)) == []
    _stub_run_with_report(monkeypatch, "null")
    assert run_gitleaks(str(tmp_path)) == []


def test_crashed_semgrep_raises_engine_error(tmp_path, monkeypatch):
    # /bin/false exits 1 immediately and writes no output file.
    monkeypatch.setattr(scan_engine, "SEMGREP_BIN", "/bin/false")
    with pytest.raises(EngineError, match="no parseable report"):
        run_semgrep(str(tmp_path))


def test_missing_semgrep_binary_raises_engine_error(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_engine, "SEMGREP_BIN",
                        "/nonexistent/semgrep-braimsec-test")
    with pytest.raises(EngineError, match="binary not found"):
        run_semgrep(str(tmp_path))
