"""Tests for the public API documentation (GET /docs, GET /api/openapi.json).

The spec is generated from the LIVE app routes and fails closed when it
drifts: every registered route must have a DOCS entry in api/openapi.py,
and every DOCS entry must map to a real route. The strongest test here
parses the @limiter.limit decorators out of api/main.py and compares them
against the registry, so a rate-limit change that forgets the docs fails
the suite.

pytest-style (imported by the unified suite); no env hard-sets here —
test_async_queue.py owns BRAIMSEC_DB / BRAIMSEC_API_KEY.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import openapi  # noqa: E402

client = TestClient(main.app)

MAIN_SRC = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "main.py"), encoding="utf-8").read()

DEFAULT_RATE_LIMIT = "600/minute"  # slowapi @limiter default


# ---------------------------------------------------------------------------
# Spec construction
# ---------------------------------------------------------------------------

def test_spec_byte_deterministic():
    """Two builds of the same app produce byte-identical JSON."""
    a = openapi.spec_to_json(main.app)
    b = openapi.spec_to_json(main.app)
    assert a == b
    json.loads(a)  # must be valid JSON


def test_all_routes_documented_and_no_stale_entries():
    """Live routes and the DOCS registry must be the same set.

    This is the fail-closed guarantee: adding a route without docs (or
    removing a route without removing its docs) breaks this test AND
    raises OpenAPIError at build time.
    """
    live = openapi._live_routes(main.app)
    assert set(openapi.DOCS) == live


def test_undocumented_route_fails_closed():
    """A route missing from the registry raises instead of shipping silent."""
    stray = FastAPI()

    @stray.get("/api/secret-thing")
    def secret_thing():  # pragma: no cover - never wired
        return {}

    with pytest.raises(openapi.OpenAPIError):
        openapi.build_openapi_spec(stray)


def test_rate_limits_match_source():
    """The registry's x-rate-limit must equal the @limiter.limit decorators.

    Parsing the decorators out of main.py keeps this honest: a changed
    limit that isn't updated in api/openapi.py fails the suite.
    """
    found = {}
    # @app.<method>("<path>") immediately followed by @limiter.limit("<v>")
    pat = re.compile(
        r'@app\.(get|post|put|patch|delete)\("([^"]+)"\)\s*\n'
        r'\s*@limiter\.limit\("([^"]+)"\)')
    for method, path, limit in pat.findall(MAIN_SRC):
        found[(method.upper(), path)] = limit
    assert found, "no decorated routes parsed — regex drift?"

    mismatches = []
    for (method, path), entry in openapi.DOCS.items():
        expected = found.get((method, path), DEFAULT_RATE_LIMIT)
        if entry["rate_limit"] != expected:
            mismatches.append(
                f"{method} {path}: docs={entry['rate_limit']} "
                f"source={expected}")
    assert not mismatches, "rate-limit drift:\n" + "\n".join(mismatches)


def test_security_marking_matches_auth():
    """Public ops carry no security; key ops require ApiKeyAuth."""
    for (method, path), entry in openapi.DOCS.items():
        op = openapi._operation(entry)
        if entry["auth"] == "public":
            assert op["security"] == [], f"{method} {path} is public"
            assert "ApiKeyAuth" not in json.dumps(op)
        else:
            assert op["security"] == [{"ApiKeyAuth": []}], \
                f"{method} {path} missing ApiKeyAuth"


def test_key_endpoints_document_401_and_all_document_429():
    """401 on every key-auth endpoint; 429 everywhere (slowapi is global)."""
    for (method, path), entry in openapi.DOCS.items():
        op = openapi._operation(entry)
        codes = set(op["responses"])
        assert "429" in codes, f"{method} {path} missing 429"
        if entry["auth"] == "key":
            assert "401" in codes, f"{method} {path} missing 401"


def test_all_examples_json_serializable():
    """Every example in the document must survive a JSON round-trip."""
    spec = openapi.build_openapi_spec(main.app)
    blob = json.dumps(spec)  # raises TypeError on non-serializable
    assert '"openapi":"3.1.0"' in blob.replace(" ", "")


def test_spec_has_required_openapi_shape():
    spec = openapi.build_openapi_spec(main.app)
    assert spec["openapi"] == "3.1.0"
    assert spec["info"]["title"] == "BraimSec API"
    assert spec["components"]["securitySchemes"]["ApiKeyAuth"]["in"] \
        == "header"
    assert spec["components"]["securitySchemes"]["ApiKeyAuth"]["name"] \
        == "X-API-Key"
    for tag in ("Scans", "Findings", "Triage", "Reports", "Schedules",
                "VCS", "Webhooks", "Alerts", "Keys", "Projects", "Audit",
                "Billing", "Docs"):
        assert any(t["name"] == tag for t in spec["tags"]), tag


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

def test_openapi_json_is_public_and_current():
    """/api/openapi.json needs no key and reflects the live routes."""
    r = client.get("/api/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    assert spec["openapi"] == "3.1.0"
    live = openapi._live_routes(main.app)
    doc_paths = {(m.upper(), p) for p, item in spec["paths"].items()
                 for m in item}
    assert doc_paths == {(m, p) for (m, p) in live}
    assert "ApiKeyAuth" in spec["components"]["securitySchemes"]


def test_docs_page_renders():
    """/docs is a self-contained HTML page needing no key and no CDN."""
    r = client.get("/docs")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    html = r.text
    assert "BraimSec API" in html
    assert "/api/openapi.json" in html
    # Self-contained: no CDN, no external stylesheets/scripts in <head>.
    head = html.split("<body>")[0]
    assert 'src="http' not in head and 'href="http' not in head, \
        "docs page must be CDN-free"


def test_builtin_docs_disabled():
    """FastAPI's built-in /docs,/redoc,/openapi.json must not compete."""
    for path in ("/redoc", "/openapi.json"):
        r = client.get(path)
        assert r.status_code == 404, path
