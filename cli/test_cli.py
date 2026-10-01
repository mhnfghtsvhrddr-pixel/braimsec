"""Tests for the braimsec CLI (cli/braimsec.py) against a local HTTP mock.

Covers: upload + polling flow, --fail-on exit codes, the three output
formats, config priority (CLI > env > file), no API-key leakage, zip
exclusions, `status`, and `--version`.
"""
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

CLI_PATH = Path(__file__).with_name("braimsec.py")
FAKE_KEY = "TESTKEY-zzz-999-SECRET-DO-NOT-LEAK"


def load_cli():
    spec = importlib.util.spec_from_file_location("braimsec_cli", CLI_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cli = load_cli()


# ---------------------------------------------------------------------------
# Mock BraimSec server
# ---------------------------------------------------------------------------

class MockState:
    """Per-test scenario knobs (reset in the fixture)."""
    expected_key = FAKE_KEY
    scan_id = "abc123scan"
    status_sequence = ["queued", "running", "done"]
    status_calls = 0
    findings = []
    fail_scan = False
    fail_upload_with = None  # e.g. 401
    requests = []  # (method, path, headers_dict, body_bytes)


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self, body=b""):
        # Keep the HTTPMessage itself: header lookup stays case-insensitive.
        MockState.requests.append((self.command, self.path, self.headers, body))

    def _send_json(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _auth_ok(self):
        return self.headers.get("X-API-Key") == MockState.expected_key

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self._record(body)
        if self.path == "/api/scans":
            if MockState.fail_upload_with:
                self._send_json(MockState.fail_upload_with, {"detail": "denied"})
                return
            if not self._auth_ok():
                self._send_json(401, {"detail": "Invalid or missing X-API-Key"})
                return
            self._send_json(200, {"scan_id": MockState.scan_id, "status": "queued"})
            return
        self._send_json(404, {"detail": "not found"})

    def do_GET(self):
        self._record()
        if not self._auth_ok():
            self._send_json(401, {"detail": "Invalid or missing X-API-Key"})
            return
        if self.path == f"/api/scans/{MockState.scan_id}":
            idx = min(MockState.status_calls, len(MockState.status_sequence) - 1)
            status = MockState.status_sequence[idx]
            MockState.status_calls += 1
            payload = {"id": MockState.scan_id, "status": status,
                       "target_name": "proj.zip",
                       "severity_summary": {"error": 1, "warning": 0, "note": 0}}
            if MockState.fail_scan:
                payload["status"] = "failed"
                payload["error"] = "engine exploded"
            self._send_json(200, payload)
            return
        if self.path == f"/api/scans/{MockState.scan_id}/results":
            self._send_json(200, MockState.findings)
            return
        self._send_json(404, {"detail": "not found"})

    def log_message(self, *args):  # silence the test server
        pass


@pytest.fixture()
def mock_server(monkeypatch, tmp_path):
    MockState.status_calls = 0
    MockState.requests = []
    MockState.fail_scan = False
    MockState.fail_upload_with = None
    MockState.status_sequence = ["queued", "running", "done"]
    MockState.findings = []
    MockState.expected_key = FAKE_KEY
    srv = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    # Isolate config: point at a nonexistent file, use env for server/key.
    monkeypatch.setenv("BRAIMSEC_CONFIG", str(tmp_path / "no-such-config"))
    monkeypatch.setenv("BRAIMSEC_SERVER", base)
    monkeypatch.setenv("BRAIMSEC_API_KEY", FAKE_KEY)
    monkeypatch.delenv("BRAIMSEC_API_KEY", raising=False)  # set explicitly below
    monkeypatch.setenv("BRAIMSEC_API_KEY", FAKE_KEY)
    yield base
    srv.shutdown()


def make_finding(severity="error", rule="braimsec-sqli", idx=0):
    return {"id": idx, "tool": "semgrep", "rule_id": rule, "severity": severity,
            "message": f"test finding {idx}", "file": "src/app.py",
            "line": 10 + idx, "col": 3}


def run_scan(tmp_path, extra=(), target=None):
    if target is None:
        target = tmp_path / "proj"
        target.mkdir(exist_ok=True)
        (target / "app.py").write_text("print('hi')\n")
    argv = ["scan", str(target), "--poll-interval", "0.01",
            "--timeout", "30", *extra]
    return cli.main(argv)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_scan_table_success(mock_server, tmp_path, capsys):
    MockState.findings = [make_finding("error"), make_finding("warning"),
                          make_finding("note")]
    assert run_scan(tmp_path) == 0
    out = capsys.readouterr().out
    assert "Findings: 3" in out
    assert "CRITICAL" in out and "HIGH" in out and "LOW" in out
    assert FAKE_KEY not in out


def test_upload_sends_zip_and_key_header(mock_server, tmp_path):
    assert run_scan(tmp_path) == 0
    posts = [r for r in MockState.requests if r[0] == "POST"]
    assert posts, "no upload request recorded"
    method, path, headers, body = posts[0]
    assert path == "/api/scans"
    assert headers.get("X-API-Key") == FAKE_KEY
    assert b"application/zip" in body
    assert b"proj.zip" in body


def test_no_wait_prints_scan_id(mock_server, tmp_path, capsys):
    assert run_scan(tmp_path, extra=["--no-wait"]) == 0
    out = capsys.readouterr().out
    assert MockState.scan_id in out
    # No polling happened.
    gets = [r for r in MockState.requests if r[0] == "GET"]
    assert not gets


# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------

def test_fail_on_critical_with_error(mock_server, tmp_path, capsys):
    MockState.findings = [make_finding("error")]
    assert run_scan(tmp_path, extra=["--fail-on", "critical"]) == 2
    err = capsys.readouterr().err
    assert "Quality gate FAILED" in err
    assert FAKE_KEY not in err


def test_fail_on_high_with_warning_only(mock_server, tmp_path):
    MockState.findings = [make_finding("warning")]
    assert run_scan(tmp_path, extra=["--fail-on", "high"]) == 2
    assert run_scan(tmp_path, extra=["--fail-on", "critical"]) == 0


def test_fail_on_low_with_note_only(mock_server, tmp_path):
    MockState.findings = [make_finding("note")]
    assert run_scan(tmp_path, extra=["--fail-on", "low"]) == 2
    assert run_scan(tmp_path, extra=["--fail-on", "never"]) == 0


def test_gate_passes_on_clean_scan(mock_server, tmp_path):
    MockState.findings = []
    assert run_scan(tmp_path, extra=["--fail-on", "critical"]) == 0


# ---------------------------------------------------------------------------
# Formats
# ---------------------------------------------------------------------------

def test_format_json(mock_server, tmp_path, capsys):
    MockState.findings = [make_finding("error"), make_finding("note")]
    assert run_scan(tmp_path, extra=["--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["scan_id"] == MockState.scan_id
    assert doc["total"] == 2
    assert doc["summary"]["error"] == 1
    assert len(doc["findings"]) == 2


def test_format_sarif(mock_server, tmp_path, capsys):
    MockState.findings = [make_finding("warning")]
    assert run_scan(tmp_path, extra=["--format", "sarif"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "BraimSec"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["level"] == "warning"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert "braimsec/v1" in res["fingerprints"]


def test_output_file(mock_server, tmp_path, capsys):
    MockState.findings = [make_finding("error")]
    out_file = tmp_path / "report.json"
    rc = run_scan(tmp_path, extra=["--format", "json", "--output", str(out_file)])
    assert rc == 0
    doc = json.loads(out_file.read_text())
    assert doc["total"] == 1
    # A short summary still goes to stdout.
    assert "Findings: 1" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Config priority + key hygiene
# ---------------------------------------------------------------------------

def test_config_priority_cli_over_env_over_file(mock_server, tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text(json.dumps({"server": "http://file-server:9",
                               "api_key": "FILEKEY"}))
    monkeypatch.setenv("BRAIMSEC_CONFIG", str(cfg))
    # env beats file
    monkeypatch.setenv("BRAIMSEC_SERVER", "http://env-server:9")
    server, key = cli.resolve_config()
    assert server == "http://env-server:9"
    assert key == FAKE_KEY  # BRAIMSEC_API_KEY from env beats the file
    # CLI beats env
    server, key = cli.resolve_config(cli_server="http://cli-server:9",
                                     cli_api_key="CLIKEY")
    assert server == "http://cli-server:9"
    assert key == "CLIKEY"
    # file is the fallback when env is absent
    monkeypatch.delenv("BRAIMSEC_SERVER")
    monkeypatch.delenv("BRAIMSEC_API_KEY")
    server, key = cli.resolve_config()
    assert server == "http://file-server:9"
    assert key == "FILEKEY"


def test_config_file_key_value_format(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text("server = http://kv:9\napi_key = KVKEY\n")
    monkeypatch.setenv("BRAIMSEC_CONFIG", str(cfg))
    monkeypatch.delenv("BRAIMSEC_SERVER", raising=False)
    monkeypatch.delenv("BRAIMSEC_API_KEY", raising=False)
    server, key = cli.resolve_config()
    assert server == "http://kv:9"
    assert key == "KVKEY"


def test_401_never_leaks_key(mock_server, tmp_path, capsys, monkeypatch):
    MockState.expected_key = "something-else"
    rc = run_scan(tmp_path)
    assert rc == 1
    captured = capsys.readouterr()
    assert FAKE_KEY not in captured.out
    assert FAKE_KEY not in captured.err
    assert "401" in captured.err


def test_missing_key_exits_1(mock_server, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("BRAIMSEC_API_KEY")
    assert run_scan(tmp_path) == 1
    assert "API key is required" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Zip exclusions
# ---------------------------------------------------------------------------

def test_zip_excludes_noise(tmp_path):
    proj = tmp_path / "proj"
    (proj / "node_modules" / "pkg").mkdir(parents=True)
    (proj / "node_modules" / "pkg" / "big.js").write_text("x" * 100)
    (proj / ".git" / "objects").mkdir(parents=True)
    (proj / ".git" / "objects" / "blob").write_text("y" * 100)
    (proj / "__pycache__").mkdir()
    (proj / "__pycache__" / "a.pyc").write_bytes(b"z" * 100)
    (proj / "keep.py").write_text("print(1)\n")
    data, name = cli.zip_target(str(proj))
    assert name == "proj.zip"
    import io
    import zipfile as zf
    names = zf.ZipFile(io.BytesIO(data)).namelist()
    assert names == ["keep.py"]


def test_zip_missing_path():
    with pytest.raises(cli.BraimSecError):
        cli.zip_target("/no/such/path/ever")


# ---------------------------------------------------------------------------
# status / version
# ---------------------------------------------------------------------------

def test_status_command(mock_server, capsys):
    MockState.status_sequence = ["done"]
    assert cli.main(["status", MockState.scan_id]) == 0
    out = capsys.readouterr().out
    assert MockState.scan_id in out
    assert "done" in out


def test_status_unknown_scan(mock_server, capsys):
    assert cli.main(["status", "nope"]) == 1
    assert "404" in capsys.readouterr().err


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert cli.__version__ in capsys.readouterr().out


def test_scan_failed_on_server(mock_server, tmp_path, capsys):
    MockState.fail_scan = True
    assert run_scan(tmp_path) == 3
    assert "failed on the server" in capsys.readouterr().err
