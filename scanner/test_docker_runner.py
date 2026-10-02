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


def test_resolve_cpus_clamps_to_host_cpus(tmp_path, monkeypatch):
    """Regression (2026-10-02): docker rejects --cpus 2 on a 1-vCPU host
    with rc=125, failing every sandboxed scan. The request must clamp."""
    import os as _os
    monkeypatch.setattr(docker_runner, "CONTAINER_CPUS", "2")
    monkeypatch.setattr(_os, "cpu_count", lambda: 1)
    assert docker_runner.resolve_cpus() == "1"
    cmd = build_command(str(tmp_path), str(tmp_path))
    i = cmd.index("--cpus")
    assert cmd[i + 1] == "1"


def test_resolve_cpus_keeps_request_when_host_has_more(tmp_path, monkeypatch):
    import os as _os
    monkeypatch.setattr(docker_runner, "CONTAINER_CPUS", "2")
    monkeypatch.setattr(_os, "cpu_count", lambda: 8)
    assert docker_runner.resolve_cpus() == "2"


def test_resolve_cpus_empty_returns_none(monkeypatch):
    monkeypatch.setattr(docker_runner, "CONTAINER_CPUS", "")
    assert docker_runner.resolve_cpus() is None


def test_shared_dir_returns_env(monkeypatch):
    monkeypatch.setenv("HOST_DATA_DIR", "/data/x")
    assert docker_runner.shared_dir() == "/data/x"


def test_shared_dir_none_when_unset(monkeypatch):
    monkeypatch.delenv("HOST_DATA_DIR", raising=False)
    assert docker_runner.shared_dir() is None


def test_run_scan_isolated_out_dir_on_shared_volume(tmp_path, monkeypatch):
    """Regression (2026-10-02): the sandbox /out mount is resolved on the
    HOST (sibling container via docker socket). An out_dir under the
    worker's private /tmp mounts as an empty host dir, so findings.json
    is never visible -> 'produced no findings.json' on every scan."""
    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setenv("HOST_DATA_DIR", str(shared))
    monkeypatch.setattr(docker_runner, "_docker_available", lambda: True)

    def fake_run(cmd, **kwargs):
        host_out = None
        for i, a in enumerate(cmd):
            if a == "-v" and cmd[i + 1].endswith(":/out"):
                host_out = cmd[i + 1].rsplit(":", 1)[0]
        assert host_out is not None, cmd
        assert host_out.startswith(str(shared)), host_out
        with open(os.path.join(host_out, "findings.json"), "w") as f:
            json.dump([], f)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(docker_runner.subprocess, "run", fake_run)
    target = tmp_path / "t"
    target.mkdir()
    assert run_scan_isolated(str(target)) == []


def test_build_command_name_flag(tmp_path):
    cmd = build_command(str(tmp_path), str(tmp_path), name="braimsec-scan-abc123")
    assert "--name" in cmd
    i = cmd.index("--name")
    assert cmd[i + 1] == "braimsec-scan-abc123"


def test_build_command_no_name_by_default(tmp_path):
    cmd = build_command(str(tmp_path), str(tmp_path))
    assert "--name" not in cmd


def test_run_isolated_names_container_and_logs(tmp_path, monkeypatch, caplog):
    import re
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        out = [a for a in cmd if a.endswith(":/out")][0].split(":")[0]
        with open(os.path.join(out, "findings.json"), "w") as f:
            json.dump([{"tool": "gitleaks", "rule_id": "r", "file": "/target/a.py"}], f)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(docker_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(docker_runner, "_docker_available", lambda: True)
    target = tmp_path / "t"
    target.mkdir()
    with caplog.at_level("INFO", logger="docker_runner"):
        findings = run_scan_isolated(str(target))
    assert len(findings) == 1
    i = seen["cmd"].index("--name")
    assert re.fullmatch(r"braimsec-scan-[0-9a-f]{12}", seen["cmd"][i + 1])
    assert any("sandbox scan ok" in r.message and "braimsec-scan-" in r.message
               for r in caplog.records)
