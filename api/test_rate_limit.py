"""Rate-limiting tests for the BraimSec API (slowapi).

- POST /api/scans        -> 60/minute per API key
- POST /api/scans/{id}/ai-review -> 30/minute (LLM cost)
- everything else        -> 600/minute default (SlowAPIMiddleware, runs before auth)
"""
import os
import sys

os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

HEADERS = {"x-api-key": "test-key-123"}


def _client():
    with TestClient(main.app) as client:
        yield client


def test_scan_endpoint_rate_limited():
    for c in _client():
        statuses = []
        for _ in range(61):
            # No target_path/file -> 400, but the request still counts
            # toward the limit (scan never starts, so this is cheap).
            r = c.post("/api/scans", headers=HEADERS)
            statuses.append(r.status_code)
        assert statuses[:60] == [400] * 60, statuses[:60]
        assert statuses[60] == 429, f"expected 429 on 61st request, got {statuses[60]}"
        r = c.post("/api/scans", headers=HEADERS)
        assert r.status_code == 429
        assert "retry-after" in {k.lower() for k in r.headers}, \
            "429 must carry a Retry-After header"


def test_unauthenticated_still_rejected():
    for c in _client():
        r = c.post("/api/scans")  # no key
        assert r.status_code == 401


def test_rate_limit_key_prefers_api_key():
    from starlette.requests import Request

    def req(headers, ip="1.2.3.4"):
        scope = {"type": "http", "headers": [
            (k.lower().encode(), v.encode()) for k, v in headers.items()],
            "client": (ip, 1234)}
        return Request(scope)

    k1 = main._rate_limit_key(req({"x-api-key": "abcdefghijklmnop"}))
    k2 = main._rate_limit_key(req({"x-api-key": "abcdefghijklmnop"}))
    k3 = main._rate_limit_key(req({"x-api-key": "zzzzzzzzzzzzzzzz"}))
    kip = main._rate_limit_key(req({}))
    assert k1 == k2 and k1.startswith("apikey:") and len(k1) < 20
    assert k1 != k3, "different keys must get different buckets"
    assert kip.startswith("ip:"), "keyless requests fall back to client IP"
