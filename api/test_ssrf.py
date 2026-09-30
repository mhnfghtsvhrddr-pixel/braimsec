"""Tests for the SSRF guard on webhook delivery.

- validate_webhook_url: fail-fast rejection of deterministically bad URLs
- safe_webhook_post: pinned-IP delivery, correct Host header, no redirects,
  fail-closed on blocked ranges (incl. DNS-rebinding simulation)
- API level: POST /api/scans rejects SSRF targets with 400
"""
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-test-ssrf-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import ssrf_guard  # noqa: E402
from ssrf_guard import safe_webhook_post, validate_webhook_url  # noqa: E402

init_db_done = False


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture(scope="module", autouse=True)
def _db():
    from database import init_db
    init_db()


# ---------- validate_webhook_url ----------

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata
    "http://127.0.0.1:8080/hook",
    "http://localhost:8080/hook",  # loopback by name
    "http://10.0.0.5/x",
    "http://192.168.1.1/x",
    "http://172.16.0.9/x",
    "http://[::1]/x",
    "http://0.0.0.0/x",
    "ftp://example.com/x",          # bad scheme
    "http://user:pass@example.com/",  # userinfo
    "http:///no-host",
])
def test_validate_rejects_bad(url):
    with pytest.raises(ValueError):
        validate_webhook_url(url)


def test_validate_allows_unresolvable_but_wellformed():
    # Fail-fast only on deterministic badness; transient DNS stays
    # best-effort at delivery time.
    assert validate_webhook_url("https://hooks.example.test/x")


def test_validate_rejects_hostname_resolving_private(monkeypatch):
    def fake_getaddrinfo(host, port, **kw):
        return [(2, 1, 6, "", ("10.9.9.9", 0))]
    monkeypatch.setattr(ssrf_guard.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError, match="blocked"):
        validate_webhook_url("https://evil.example.com/hook")


# ---------- safe_webhook_post ----------

def test_post_refuses_blocked_without_connecting(monkeypatch):
    called = []
    monkeypatch.setattr(ssrf_guard.socket, "create_connection",
                        lambda *a, **k: called.append(a) or 1 / 0)
    with pytest.raises(ValueError, match="blocked"):
        safe_webhook_post("http://169.254.169.254/", b"{}", {}, 5)
    assert called == [], "must not attempt any connection to blocked target"


def test_post_refuses_rebinding(monkeypatch):
    # Hostname looks public but resolves private -> whole URL refused.
    def fake_getaddrinfo(host, port, **kw):
        return [(2, 1, 6, "", ("192.168.99.99", 0))]
    monkeypatch.setattr(ssrf_guard.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError, match="blocked"):
        safe_webhook_post("https://rebind.example.com/", b"{}", {}, 5)


class _Handler(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        _Handler.seen.append({
            "path": self.path,
            "host": self.headers.get("Host"),
            "body": body,
        })
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/stolen")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture()
def _local_server(monkeypatch):
    # Allow loopback for this test only (blocked by default in prod),
    # and pin resolution to IPv4 127.0.0.1 (the test server is v4-only).
    monkeypatch.setattr(ssrf_guard, "_blocked_ip", lambda ip: False)
    monkeypatch.setattr(ssrf_guard.socket, "getaddrinfo",
                        lambda *a, **kw: [(2, 1, 6, "", ("127.0.0.1", a[1]))])
    _Handler.seen = []
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def test_post_pins_ip_sends_original_host(_local_server):
    port = _local_server
    status = safe_webhook_post(f"http://localhost:{port}/hook?x=1",
                               b'{"a":1}',
                               {"Content-Type": "application/json"}, 5)
    assert status == 200
    assert len(_Handler.seen) == 1
    hit = _Handler.seen[0]
    assert hit["path"] == "/hook?x=1"
    assert hit["host"] == f"localhost:{port}", hit["host"]
    assert hit["body"] == b'{"a":1}'


def test_post_does_not_follow_redirects(_local_server):
    port = _local_server
    status = safe_webhook_post(f"http://localhost:{port}/redirect",
                               b"{}", {}, 5)
    assert status == 302
    assert len(_Handler.seen) == 1, \
        "must not follow the redirect to the metadata address"


# ---------- API level ----------

def test_api_rejects_ssrf_webhook_url(tmp_path):
    from pathlib import Path
    d = Path(main.SCAN_ROOT) / "pytest-ssrf"
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.py").write_text("x = 1\n")
    with TestClient(main.app) as c:
        for bad in ("http://169.254.169.254/x", "http://127.0.0.1:9/x",
                    "http://10.1.2.3/hook"):
            r = c.post("/api/scans", headers={"x-api-key": "test-key-123"},
                       data={"target_path": str(d), "webhook_url": bad})
            assert r.status_code == 400, (bad, r.text)
