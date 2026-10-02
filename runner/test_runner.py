"""Unit tests for runner/runner.py (the dedicated scan-runner service).

No Docker daemon needed: subprocess is faked. The tests prove the
security properties of the narrow API: auth, target containment under
uploads/, scope containment under the target, fixed hardened flags,
and fail-closed behavior.
"""
import io
import json
import os
import sys
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import runner  # noqa: E402


@pytest.fixture()
def uploads(tmp_path, monkeypatch):
    d = tmp_path / "uploads"
    d.mkdir()
    monkeypatch.setattr(runner, "UPLOADS_DIR", str(d))
    monkeypatch.setattr(runner, "HOST_DATA_DIR", str(tmp_path))
    return d


@pytest.fixture()
def target(uploads):
    t = uploads / "braimsec-abc123" / "src"
    t.mkdir(parents=True)
    (t / "app.py").write_text("x = 1\n")
    return t


# --- path validation ----------------------------------------------------

def test_validate_target_ok(uploads, target):
    assert runner.validate_target(str(target)) == os.path.realpath(str(target))


def test_validate_target_rejects_outside_uploads(uploads, tmp_path):
    outside = tmp_path / "evil"
    outside.mkdir()
    with pytest.raises(ValueError, match="outside uploads"):
        runner.validate_target(str(outside))
    with pytest.raises(ValueError, match="outside uploads"):
        runner.validate_target("/etc")


def test_validate_target_rejects_missing(uploads):
    with pytest.raises(ValueError, match="not a directory"):
        runner.validate_target(str(uploads / "nope"))


def test_validate_target_rejects_symlink_escape(uploads, tmp_path):
    # A symlink inside uploads pointing at /etc must not pass.
    link = uploads / "link"
    try:
        link.symlink_to("/etc")
    except OSError:
        pytest.skip("symlinks not permitted here")
    with pytest.raises(ValueError, match="outside uploads"):
        runner.validate_target(str(link))


def test_validate_scope_ok(uploads, target):
    f = os.path.realpath(str(target / "app.py"))
    assert runner.validate_scope([f], os.path.realpath(str(target))) == [f]
    assert runner.validate_scope(None, os.path.realpath(str(target))) == []


def test_validate_scope_rejects_escape(uploads, target):
    other = uploads / "other"
    other.mkdir()
    with pytest.raises(ValueError, match="escapes target"):
        runner.validate_scope([str(other)], os.path.realpath(str(target)))
    with pytest.raises(ValueError, match="escapes target"):
        runner.validate_scope([str(target / ".." / "other")],
                              os.path.realpath(str(target)))


def test_validate_scope_rejects_non_list(uploads, target):
    with pytest.raises(ValueError):
        runner.validate_scope("nope", str(target))


# --- hardened command -----------------------------------------------------

def test_build_command_hardening(uploads, target, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    cmd = runner.build_command(str(target), str(out), name="braimsec-scan-x")
    joined = " ".join(cmd)
    assert "--network" in cmd and "none" in cmd
    assert "--read-only" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "no-new-privileges" in joined
    assert "--pids-limit" in cmd
    assert f"{target}:/target:ro" in cmd
    assert "braimsec-scan-x" in cmd
    # The image is a server-side constant — the API has no way to change it.
    assert runner.RUNNER_IMAGE in cmd
    assert "evil-image" not in joined


# --- fail-closed run_scan ---------------------------------------------------

def test_run_scan_no_docker_binary(uploads, target, monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda *_: None)
    with pytest.raises(runner.RunnerError, match="docker binary not found"):
        runner.run_scan(str(target))


def test_run_scan_bad_target_no_container(uploads, monkeypatch):
    # Validation happens BEFORE any container is spawned: count spawns.
    monkeypatch.setattr(runner.shutil, "which", lambda *_: "/usr/bin/docker")
    spawned = []
    monkeypatch.setattr(runner.subprocess, "run",
                        lambda *a, **k: spawned.append(a) or
                        mock.Mock(returncode=0, stdout="", stderr=""))
    with pytest.raises(ValueError, match="outside uploads"):
        runner.run_scan("/etc")
    assert spawned == []


# --- HTTP layer (real server, faked container) -------------------------------

class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_docker_run(cmd, **kwargs):
    out_dir = next(a.split(":", 1)[0] for a in cmd if a.endswith(":/out"))
    findings = [{"tool": "semgrep", "rule_id": "r",
                 "file": "/target/app.py"}]
    with open(os.path.join(out_dir, "findings.json"), "w") as f:
        json.dump(findings, f)
    return _FakeCompleted()


@pytest.fixture()
def server(monkeypatch):
    monkeypatch.setattr(runner, "API_KEY", "test-key")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), runner.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _post(url, payload, token=None):
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url + "/v1/scans", data=data,
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_health(server):
    with urllib.request.urlopen(server + "/v1/health", timeout=10) as r:
        assert json.load(r)["status"] == "ok"


def test_auth_required(server, target):
    code, _ = _post(server, {"target_dir": str(target)})
    assert code == 401
    code, _ = _post(server, {"target_dir": str(target)}, token="wrong")
    assert code == 401


def test_scan_rejects_outside_target(server, uploads):
    code, body = _post(server, {"target_dir": "/etc"}, token="test-key")
    assert code == 400
    assert "outside uploads" in body["error"]


def test_scan_rejects_scope_escape(server, target):
    code, body = _post(server, {"target_dir": str(target),
                                "scope": ["/etc/passwd"]}, token="test-key")
    assert code == 400
    assert "escapes target" in body["error"]


def test_scan_full_stack(server, target, uploads, monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda *_: "/usr/bin/docker")
    monkeypatch.setattr(runner.subprocess, "run", _fake_docker_run)
    code, body = _post(server, {"target_dir": str(target)},
                       token="test-key")
    assert code == 200
    assert body["container"].startswith("braimsec-scan-")
    assert body["findings"][0]["file"] == "/target/app.py"


def test_scan_container_failure_is_502(server, target, monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda *_: "/usr/bin/docker")
    monkeypatch.setattr(
        runner.subprocess, "run",
        lambda *a, **k: _FakeCompleted(returncode=125,
                                      stderr="docker: invalid arg"))
    code, body = _post(server, {"target_dir": str(target)},
                       token="test-key")
    assert code == 502
    assert "rc=125" in body["error"]


def test_unknown_endpoints_404(server):
    for path in ("/v1/nope", "/"):
        req = urllib.request.Request(server + path, method="GET")
        try:
            urllib.request.urlopen(req, timeout=10)
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404


def test_main_refuses_without_api_key(monkeypatch):
    monkeypatch.setattr(runner, "API_KEY", "")
    with pytest.raises(SystemExit):
        runner.main()
