"""Fail-closed behavior of the scan engines.

- An empty incremental scope must return [] without invoking any engine
  (and must NOT fall back to scanning the whole target).
- A crashed semgrep (non-zero exit, no output file) must raise EngineError,
  never masquerade as a clean scan.
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
    # _run is stubbed; run_semgrep then fails to read the (never written)
    # output file -> {} -> returns [] without raising. The assertion that
    # matters: the target dir reached the engine command line.
    assert run_semgrep(str(tmp_path), scope=None) == []
    assert str(tmp_path) in seen[0]


def test_crashed_semgrep_raises_engine_error(tmp_path, monkeypatch):
    # /bin/false exits 1 immediately and writes no output file.
    monkeypatch.setattr(scan_engine, "SEMGREP_BIN", "/bin/false")
    with pytest.raises(EngineError, match="without results"):
        run_semgrep(str(tmp_path))


def test_missing_semgrep_binary_raises_engine_error(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_engine, "SEMGREP_BIN",
                        "/nonexistent/semgrep-braimsec-test")
    with pytest.raises(EngineError, match="binary not found"):
        run_semgrep(str(tmp_path))
