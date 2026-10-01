"""Unit tests for scanner/docker_runner.py.

No Docker daemon needed: subprocess is mocked. The *real* container
behavior (isolation flags, findings round-trip) is verified separately
by building the actual scan-runner image and running it.
"""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import docker_runner  # noqa: E402
from docker_runner import (ContainerError, build_command,  # noqa: E402
                           run_scan_isolated, sandbox_mode)


def test_sandbox_mode_defaults_local(monkeypatch):
    monkeypatch.delenv("BRAIMSEC_SCAN_SANDBOX", raising=False)
    assert sandbox_mode() == "local"


def test_sandbox_mode_parsing(monkeypatch):
    monkeypatch.setenv("BRAIMSEC_SCAN_SANDBOX", "  DOCKER ")
    assert sandbox_mode() == "docker"


def test_build_command_hardening(tmp_path):
    target = tmp_path / "t"
    out = tmp_path / "o"
    target.mkdir()
    out.mkdir()
    cmd = build_command(str(target), str(out), image="img:test")
    # Isolation flags — every one of these is a security property.
    assert "--network" in cmd and "none" in cmd
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "no-new-privileges" in " ".join(cmd)
    assert "--pids-limit" in cmd
    assert "--memory" in cmd and "--cpus" in cmd
    # Target mounted read-only, output writable.
    assert f"{target}:/target:ro" in cmd
    assert f"{out}:/out" in cmd
    assert cmd[-1] == "img:test"


def _ok_run(monkeypatch, findings):
    def fake_run(cmd, **kw):
        out = [a for a in cmd if a.endswith(":/out")][0].split(":")[0]
        with open(os.path.join(out, "findings.json"), "w") as f:
            json.dump(findings, f)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(docker_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(docker_runner, "_docker_available", lambda: True)


def test_run_isolated_translates_paths(tmp_path, monkeypatch):
    _ok_run(monkeypatch, [{"tool": "semgrep", "rule_id": "r",
                           "file": "/target/sub/a.py"}])
    target = tmp_path / "t"
    target.mkdir()
    out = run_scan_isolated(str(target))
    assert out[0]["file"] == str(target / "sub" / "a.py")


def test_run_isolated_writes_relative_scope(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        out = [a for a in cmd if a.endswith(":/out")][0].split(":")[0]
        with open(os.path.join(out, "scope.json")) as f:
            seen["scope"] = json.load(f)
        with open(os.path.join(out, "findings.json"), "w") as f:
            json.dump([], f)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(docker_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(docker_runner, "_docker_available", lambda: True)
    target = tmp_path / "t"
    target.mkdir()
    run_scan_isolated(str(target), scope=[str(target / "x.py")])
    assert seen["scope"] == ["x.py"]


def test_run_isolated_no_docker_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(docker_runner, "_docker_available", lambda: False)
    target = tmp_path / "t"
    target.mkdir()
    with pytest.raises(ContainerError, match="not found"):
        run_scan_isolated(str(target))


def test_run_isolated_bad_target(tmp_path, monkeypatch):
    monkeypatch.setattr(docker_runner, "_docker_available", lambda: True)
    with pytest.raises(ContainerError, match="not a directory"):
        run_scan_isolated(str(tmp_path / "nope"))


def test_run_isolated_nonzero_rc_fail_closed(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, "", "boom")
    monkeypatch.setattr(docker_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(docker_runner, "_docker_available", lambda: True)
    target = tmp_path / "t"
    target.mkdir()
    with pytest.raises(ContainerError, match="rc=1"):
        run_scan_isolated(str(target))


def test_run_isolated_missing_findings_fail_closed(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(docker_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(docker_runner, "_docker_available", lambda: True)
    target = tmp_path / "t"
    target.mkdir()
    with pytest.raises(ContainerError, match="no findings.json"):
        run_scan_isolated(str(target))


def test_run_isolated_timeout_fail_closed(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)
    monkeypatch.setattr(docker_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(docker_runner, "_docker_available", lambda: True)
    target = tmp_path / "t"
    target.mkdir()
    with pytest.raises(ContainerError, match="timed out"):
        run_scan_isolated(str(target))


def test_build_command_empty_limits_are_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(docker_runner, "CONTAINER_CPUS", "")
    monkeypatch.setattr(docker_runner, "CONTAINER_MEMORY", "")
    monkeypatch.setattr(docker_runner, "CONTAINER_PIDS", "")
    cmd = build_command(str(tmp_path), str(tmp_path))
    assert "--cpus" not in cmd
    assert "--memory" not in cmd
    assert "--pids-limit" not in cmd
    # Hardening that must never be skippable stays.
    assert "--network" in cmd and "none" in cmd
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd


def test_build_command_default_limits_present(tmp_path):
    cmd = build_command(str(tmp_path), str(tmp_path))
    assert "--pids-limit" in cmd
    assert "--memory" in cmd
    assert "--cpus" in cmd
