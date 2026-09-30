"""Tests for scanner/sca.py (OSV-based dependency scanning)."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import sca
from sca import (Package, parse_requirements, parse_package_lock,
                 parse_go_mod, parse_cargo_lock, parse_gemfile_lock,
                 vuln_to_finding, run_sca, discover_manifests)


@pytest.fixture()
def target(tmp_path):
    return str(tmp_path)


def write(target, name, content):
    p = os.path.join(target, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(content)
    return p


# ------------------------------------------------------------------ discovery

def test_discover_manifests(target):
    write(target, "requirements.txt", "django==3.2.0\n")
    write(target, "backend/package-lock.json", '{"packages": {}}')
    write(target, "node_modules/pkg/package.json", "{}")  # not a manifest
    found = discover_manifests(target)
    kinds = sorted(e for _, e in found)
    assert kinds == ["PyPI", "npm"]
    # node_modules dir is pruned
    assert not any("node_modules" in p for p, _ in found)


def test_discover_none(target):
    assert discover_manifests(target) == []


# ------------------------------------------------------------------ requirements.txt

def test_requirements_pins_and_skips(target):
    p = write(target, "requirements.txt",
              "# comment\n"
              "Django==3.2.0\n"
              "requests[security]>=2.28.0\n"   # range -> skipped
              "flask~=2.0.0\n"                  # range -> skipped
              "numpy\n"                         # no version -> skipped
              "urllib3===1.26.5\n"               # arbitrary equality -> pinned
              "gunicorn==20.1.0 ; python_version > '3.8'\n")
    pkgs = parse_requirements(p, "requirements.txt")
    got = {(x.name, x.version, x.line) for x in pkgs}
    assert got == {("django", "3.2.0", 2),
                   ("urllib3", "1.26.5", 6),
                   ("gunicorn", "20.1.0", 7)}


def test_requirements_includes_and_continuations(target):
    write(target, "base.txt", "django==3.2.0\n")
    p = write(target, "requirements.txt",
              "-r base.txt\n"
              "celery==5.3.0 \\\n"
              "    # trailing comment after continuation\n")
    pkgs = parse_requirements(p, "requirements.txt")
    got = {(x.name, x.version, x.file) for x in pkgs}
    assert ("django", "3.2.0", "base.txt") in got
    assert ("celery", "5.3.0", "requirements.txt") in got


def test_requirements_name_normalization(target):
    p = write(target, "requirements.txt", "My_Package.Name==1.0\n")
    pkgs = parse_requirements(p, "requirements.txt")
    assert pkgs[0].name == "my-package-name"


# ------------------------------------------------------------------ package-lock.json

def test_package_lock_v2_lines(target):
    content = """{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    },
    "node_modules/@babel/core": {
      "version": "7.22.0"
    }
  }
}
"""
    p = write(target, "package-lock.json", content)
    pkgs = parse_package_lock(p, "package-lock.json")
    got = {(x.name, x.version) for x in pkgs}
    assert got == {("lodash", "4.17.20"), ("@babel/core", "7.22.0")}
    lines = {x.name: x.line for x in pkgs}
    assert lines["lodash"] == 7
    assert lines["@babel/core"] == 11


def test_package_lock_v1_structural(target):
    content = json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {"version": "4.17.20",
                       "dependencies": {"nested": {"version": "1.0.0"}}},
        },
    })
    p = write(target, "package-lock.json", content)
    pkgs = parse_package_lock(p, "package-lock.json")
    got = {(x.name, x.version) for x in pkgs}
    assert got == {("lodash", "4.17.20"), ("nested", "1.0.0")}


def test_package_lock_bad_json(target):
    p = write(target, "package-lock.json", "{nope")
    assert parse_package_lock(p, "package-lock.json") == []


# ------------------------------------------------------------------ go.mod

def test_go_mod(target):
    p = write(target, "go.mod",
              "module example.com/app\n\n"
              "go 1.21\n\n"
              "require (\n"
              "\tgithub.com/gin-gonic/gin v1.9.1\n"
              "\tgolang.org/x/text v0.14.0 // indirect\n"
              ")\n\n"
              "require github.com/sirupsen/logrus v1.9.3\n\n"
              "replace golang.org/x/text => ../local\n")
    pkgs = parse_go_mod(p, "go.mod")
    got = {(x.name, x.version) for x in pkgs}
    # x/text is replaced -> skipped
    assert got == {("github.com/gin-gonic/gin", "v1.9.1"),
                   ("github.com/sirupsen/logrus", "v1.9.3")}
    assert pkgs[0].line == 6


# ------------------------------------------------------------------ Cargo.lock

def test_cargo_lock(target):
    p = write(target, "Cargo.lock",
              '[[package]]\nname = "serde"\nversion = "1.0.188"\n\n'
              '[[package]]\nname = "rand"\nversion = "0.8.5"\n'
              'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
    pkgs = parse_cargo_lock(p, "Cargo.lock")
    got = {(x.name, x.version, x.line) for x in pkgs}
    assert got == {("serde", "1.0.188", 3), ("rand", "0.8.5", 7)}


# ------------------------------------------------------------------ Gemfile.lock

def test_gemfile_lock(target):
    p = write(target, "Gemfile.lock",
              "GEM\n"
              "  remote: https://rubygems.org/\n"
              "  specs:\n"
              "    rake (13.0.6)\n"
              "    rails (7.0.8)\n"
              "      actionpack (= 7.0.8)\n"
              "\n"
              "PLATFORMS\n"
              "  ruby\n")
    pkgs = parse_gemfile_lock(p, "Gemfile.lock")
    got = {(x.name, x.version, x.line) for x in pkgs}
    assert ("rake", "13.0.6", 4) in got
    assert ("rails", "7.0.8", 5) in got
    # nested dep at 6-space indent is not a top-level spec entry
    assert not any(x[0] == "actionpack" for x in got)


# ------------------------------------------------------------------ OSV mapping

DJANGO_VULN = {
    "id": "GHSA-2gwj-7jmv-h26r",
    "aliases": ["CVE-2022-28346", "PYSEC-2022-190"],
    "summary": "SQL Injection in Django",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{
        "package": {"name": "django", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "2.2"}, {"fixed": "2.2.28"}]}],
    }, {
        "package": {"name": "django", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "3.2"}, {"fixed": "3.2.25"}]}],
    }],
}


def test_vuln_to_finding():
    pkg = Package("django", "3.2.0", "PyPI", "requirements.txt", 2)
    f = vuln_to_finding(DJANGO_VULN, pkg)
    assert f["tool"] == "osv"
    assert f["rule_id"] == "GHSA-2gwj-7jmv-h26r"
    assert f["severity"] == "error"          # CRITICAL -> error
    assert f["file"] == "requirements.txt" and f["line"] == 2
    assert "CVE-2022-28346" in f["message"]
    assert "3.2.25" in f["message"]          # branch-matched fixed version
    assert "django 3.2.0" in f["message"]


def test_severity_fallback_unknown():
    pkg = Package("x", "1.0", "PyPI", "requirements.txt", 1)
    f = vuln_to_finding({"id": "GHSA-xxxx", "affected": []}, pkg)
    assert f["severity"] == "warning"
    assert f["message"].startswith("x 1.0:")


# ------------------------------------------------------------------ run_sca

def _canned_batch(url, payload, timeout):
    # realistic trimmed shape: id + modified only
    assert url.endswith("/v1/querybatch")
    results = []
    for q in payload["queries"]:
        name = q["package"]["name"]
        if name == "django" and q["version"] == "3.2.0":
            results.append({"vulns": [{"id": "GHSA-2gwj-7jmv-h26r",
                                       "modified": "2023-01-01T00:00:00Z"}]})
        else:
            results.append({})
    return {"results": results}


def _canned_details(ids, deadline, max_workers=10):
    return {"GHSA-2gwj-7jmv-h26r": DJANGO_VULN}


def test_run_sca_end_to_end(target, monkeypatch):
    write(target, "requirements.txt", "django==3.2.0\nrequests==2.31.0\n")
    monkeypatch.setattr(sca, "_post_json", _canned_batch)
    monkeypatch.setattr(sca, "fetch_vuln_details", _canned_details)
    findings = run_sca(target)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "GHSA-2gwj-7jmv-h26r"
    assert findings[0]["severity"] == "error"


def test_run_sca_dedups_identical_pins(target, monkeypatch):
    write(target, "requirements.txt", "django==3.2.0\n")
    write(target, "backend/requirements.txt", "django==3.2.0\n")
    monkeypatch.setattr(sca, "_post_json", _canned_batch)
    monkeypatch.setattr(sca, "fetch_vuln_details", _canned_details)
    findings = run_sca(target)
    # same package+version pinned twice -> queried once -> one finding
    assert len(findings) == 1


def test_run_sca_skips_vuln_when_details_fail(target, monkeypatch):
    # batch says "vulnerable" but detail fetch fails -> no invented finding
    write(target, "requirements.txt", "django==3.2.0\n")
    monkeypatch.setattr(sca, "_post_json", _canned_batch)
    monkeypatch.setattr(sca, "fetch_vuln_details", lambda *a, **k: {})
    assert run_sca(target) == []


def test_run_sca_fail_soft_on_network_error(target, monkeypatch):
    write(target, "requirements.txt", "django==3.2.0\n")

    def boom(url, payload, timeout):
        raise ConnectionError("net down")

    monkeypatch.setattr(sca, "_post_json", boom)
    assert run_sca(target) == []


def test_run_sca_offline(target, monkeypatch):
    write(target, "requirements.txt", "django==3.2.0\n")
    monkeypatch.setattr(sca, "SCA_OFFLINE", True)
    assert run_sca(target) == []


def test_run_sca_no_manifests(target):
    assert run_sca(target) == []


# ------------------------------------------------------------------ live API

def test_live_osv_query_django():
    """Contract check against the real OSV API; skips if net is down."""
    try:
        resp = sca._post_json(
            "https://api.osv.dev/v1/querybatch",
            {"queries": [{"package": {"name": "django", "ecosystem": "PyPI"},
                          "version": "3.2.0"}]},
            timeout=25)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"OSV unreachable: {e}")
    vulns = resp["results"][0].get("vulns", [])
    assert len(vulns) > 0
    ids = [v["id"] for v in vulns]
    assert any(i.startswith("GHSA-") for i in ids)
