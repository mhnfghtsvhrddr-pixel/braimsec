"""SARIF 2.1.0 export tests (GET /api/scans/{id}/sarif + builder).

Builder (pure, no DB):
- valid SARIF 2.1.0 structure: $schema, version, driver name/version,
  rules[] (id/name/shortDescription/helpUri), results[] with
  level/locations/fingerprints
- severity mapping: error/warning/note pass through, unknown -> warning
- line/column coercion to >= 1
- fingerprints stable across two builds, distinct per finding content
- validate_sarif rejects malformed documents (fail-closed)

API:
- 200 + application/sarif+json + Content-Disposition download header
- body parses and passes validate_sarif
- 401 without key, viewer role may read, 404 for missing scan and for a
  scan belonging to another org (isolation)

DB isolation: setdefault only (test_async_queue.py pins these first in the
unified run — see AGENTS.md); fixtures use random ids.
"""
import json
import os
import sys
import tempfile

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_tmp = tempfile.mkdtemp(prefix="braimsec-test-sarif-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-sarif-master-key")
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_REPO, "api"))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from sarif import (  # noqa: E402
    SARIF_SCHEMA,
    SarifError,
    build_sarif,
    finding_fingerprint,
    validate_sarif,
)
from billing import create_org, ensure_owner_org, provision_key  # noqa: E402
from database import get_db, init_db  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


def _uid():
    import uuid as _u
    return _u.uuid4().hex[:8]


def _h(key):
    return {"X-API-Key": key}


def _findings():
    return [
        {"tool": "semgrep", "rule_id": "x.braimsec.taint.ssrf-requests",
         "severity": "error", "message": "ssrf via requests",
         "file": "app.py", "line": 6, "col": 5},
        {"tool": "semgrep", "rule_id": "x.braimsec.taint.ssrf-requests",
         "severity": "error", "message": "ssrf again",
         "file": "other.py", "line": 2, "col": 1},
        {"tool": "gitleaks", "rule_id": "generic-api-key",
         "severity": "warning", "message": "leaked secret",
         "file": ".env", "line": 3, "col": 1},
        {"tool": "semgrep", "rule_id": "some.note.rule",
         "severity": "note", "message": "minor", "file": "a.py",
         "line": 1, "col": 1},
        {"tool": "custom", "rule_id": "weird",
         "severity": "CRITICAL", "message": "unknown sev",
         "file": "b.py", "line": 0, "col": None},
    ]


# --- builder --------------------------------------------------------------

def test_structure_and_driver():
    doc = build_sarif(_findings(), scan_id="s1", target_name="acme")
    assert validate_sarif(doc) is True
    assert doc["$schema"] == SARIF_SCHEMA
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "BraimSec"
    assert driver["version"]
    auto = run["automationDetails"]
    assert auto["id"] == "braimsec/s1"
    assert "acme" in auto["description"]["text"]


def test_rules_dedup_and_fields():
    doc = build_sarif(_findings())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    # ssrf rule appears in two findings but once in rules[]
    assert ids.count("semgrep/x.braimsec.taint.ssrf-requests") == 1
    assert len(ids) == 4
    for r in rules:
        assert r["name"]
        assert r["shortDescription"]["text"]
    # known CWE rule gets a MITRE help link
    ssrf = next(r for r in rules
                if r["id"] == "semgrep/x.braimsec.taint.ssrf-requests")
    assert ssrf["helpUri"].startswith("https://cwe.mitre.org/")


def test_results_levels_locations_fingerprints():
    doc = build_sarif(_findings())
    results = doc["runs"][0]["results"]
    assert len(results) == 5
    by_file = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r
               for r in results}
    assert by_file["app.py"]["level"] == "error"
    assert by_file[".env"]["level"] == "warning"
    assert by_file["a.py"]["level"] == "note"
    # unknown severity falls back to warning, never dropped
    assert by_file["b.py"]["level"] == "warning"
    # ruleIndex points at the right rule
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    for r in results:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]
    # regions are 1-based even for 0/None input
    region = by_file["b.py"]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1
    assert region["startColumn"] == 1
    # fingerprints present and well-formed
    fps = [r["fingerprints"]["braimsec/v1"] for r in results]
    assert all(len(fp) == 32 and all(c in "0123456789abcdef" for c in fp)
               for fp in fps)


def test_fingerprints_stable_and_distinct():
    a = build_sarif(_findings())
    b = build_sarif(_findings())
    fa = [r["fingerprints"]["braimsec/v1"] for r in a["runs"][0]["results"]]
    fb = [r["fingerprints"]["braimsec/v1"] for r in b["runs"][0]["results"]]
    assert fa == fb, "same findings -> same fingerprints"
    assert len(set(fa)) == len(fa), "distinct findings -> distinct fingerprints"
    assert finding_fingerprint("t", "r", "f", "m") == \
        finding_fingerprint("t", "r", "f", "m")


def test_empty_findings_valid():
    doc = build_sarif([])
    assert validate_sarif(doc) is True
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_validate_rejects_malformed():
    good = build_sarif(_findings()[:1])

    def mutate(fn):
        import copy
        d = copy.deepcopy(good)
        fn(d)
        return d

    cases = [
        lambda d: d.pop("$schema"),
        lambda d: d.update(version="2.0.0"),
        lambda d: d.update(runs=[]),
        lambda d: d["runs"][0].pop("results"),
        lambda d: d["runs"][0]["results"][0].pop("ruleId"),
        lambda d: d["runs"][0]["results"][0].update(level="critical"),
        lambda d: d["runs"][0]["results"][0].update(locations=[]),
        lambda d: d["runs"][0]["results"][0]["locations"][0]
                  ["physicalLocation"]["region"].update(startLine=0),
        lambda d: d["runs"][0]["tool"]["driver"].update(name=""),
    ]
    for i, fn in enumerate(cases):
        try:
            with pytest.raises(SarifError):
                validate_sarif(mutate(fn))
        except AssertionError:
            raise AssertionError(f"case {i} did not raise SarifError")
    with pytest.raises(SarifError):
        validate_sarif("not a dict")


# --- API ------------------------------------------------------------------

@pytest.fixture()
def seeded():
    init_db()
    ensure_owner_org()
    uid = _uid()
    org = create_org(f"SarifCo_{uid}", plan="pro")
    headers = _h(provision_key(org, f"sarif-{uid}", actor="owner"))
    viewer = _h(provision_key(org, f"sarif-view-{uid}", actor="owner",
                             role="viewer"))
    other_org = create_org(f"SarifOther_{uid}", plan="pro")
    other_scan = f"scan_sarif_other_{uid}"
    # NOTE: all billing calls above open+close their own connections; the
    # raw db handle below must be the only writer from here on (an
    # uncommitted write blocks any second connection for 30s -> locked).
    db = get_db()
    scan_id = f"scan_sarif_{uid}"
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " finished_at) VALUES (?,?,?,?,?,?)",
        (scan_id, org, "acme", "done",
         "2026-10-01T00:00:00+00:00", "2026-10-01T00:01:00+00:00"))
    for i, f in enumerate(_findings()):
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, f["tool"], f["rule_id"], f["severity"],
             f["message"], f["file"], f["line"], f["col"]))
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        (other_scan, other_org, "acme", "done", "2026-10-01T00:00:00+00:00"))
    db.commit()
    db.close()
    return {"headers": headers, "viewer": viewer, "scan_id": scan_id,
            "other_scan": other_scan}


def test_endpoint_ok_headers_and_body(seeded):
    with TestClient(main.app) as c:
        r = c.get(f"/api/scans/{seeded['scan_id']}/sarif",
                  headers=seeded["headers"])
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/sarif+json"
    assert "attachment" in r.headers["content-disposition"]
    assert ".sarif" in r.headers["content-disposition"]
    doc = json.loads(r.content.decode("utf-8"))
    assert validate_sarif(doc) is True
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "BraimSec"
    assert len(doc["runs"][0]["results"]) == 5


def test_endpoint_deterministic(seeded):
    with TestClient(main.app) as c:
        b1 = c.get(f"/api/scans/{seeded['scan_id']}/sarif",
                   headers=seeded["headers"]).content
        b2 = c.get(f"/api/scans/{seeded['scan_id']}/sarif",
                   headers=seeded["headers"]).content
    assert b1 == b2, "same scan -> same bytes"


def test_endpoint_viewer_may_read(seeded):
    with TestClient(main.app) as c:
        r = c.get(f"/api/scans/{seeded['scan_id']}/sarif",
                  headers=seeded["viewer"])
    assert r.status_code == 200, r.text


def test_endpoint_401_and_404s(seeded):
    with TestClient(main.app) as c:
        r = c.get(f"/api/scans/{seeded['scan_id']}/sarif")
        assert r.status_code == 401
        r = c.get("/api/scans/scan_nope_missing/sarif",
                  headers=seeded["headers"])
        assert r.status_code == 404
        # another org's scan is invisible (isolation)
        r = c.get(f"/api/scans/{seeded['other_scan']}/sarif",
                  headers=seeded["headers"])
        assert r.status_code == 404
