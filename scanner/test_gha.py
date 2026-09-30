"""Tests for the BraimSec GitHub Actions security pack
(scanner/rules/braimsec-gha.yaml).

- Pack hygiene: 3 rules, expected IDs, yaml language, sane severities.
- Behavior: vulnerable workflow snippets fire / safe snippets stay silent
  (needs semgrep; skipped otherwise).
- Engine wiring: run_semgrep picks the GHA pack up via --config alongside
  `--config auto` (needs semgrep).

DO NOT tune the rules against old holdout data (SPEC v1.0 §4).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "rules", "braimsec-gha.yaml")


def _semgrep():
    for cand in (os.environ.get("SEMGREP_BIN"),
                 shutil.which("semgrep"),
                 os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


SG = _semgrep()
needs_sg = pytest.mark.skipif(SG is None, reason="semgrep binary not found")


def _run_rules(files):
    """Run ONLY the braimsec GHA pack on {name: source} -> [(rule, file)]."""
    d = tempfile.mkdtemp(prefix="gha-test-")
    for name, src in files.items():
        p = os.path.join(d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(src)
    out = os.path.join(d, "out.json")
    subprocess.run([SG, "--config", RULES, "--json", "-o", out, d],
                   capture_output=True, timeout=300)
    with open(out) as f:
        data = json.load(f)
    res = []
    for r in data.get("results", []):
        rid = r["check_id"]
        i = rid.find("braimsec.gha.")
        if i != -1:
            res.append((rid[i:], os.path.basename(r["path"])))
    return res


# ---------------------------------------------------------------------------
# pack hygiene (no binary)
# ---------------------------------------------------------------------------

def test_pack_has_three_gha_rules():
    with open(RULES) as f:
        pack = yaml.safe_load(f)
    rules = pack["rules"]
    assert len(rules) == 3
    ids = sorted(r["id"] for r in rules)
    assert ids == ["braimsec.gha.broad-permissions",
                   "braimsec.gha.script-injection",
                   "braimsec.gha.unpinned-action"]
    assert all("yaml" in r["languages"] for r in rules)
    sev = {r["id"]: r["severity"] for r in rules}
    assert sev["braimsec.gha.script-injection"] == "ERROR"
    assert sev["braimsec.gha.unpinned-action"] == "WARNING"
    assert sev["braimsec.gha.broad-permissions"] == "WARNING"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

VULN_INJECTION = """\
name: ci
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: greet
        run: |
          echo "Issue: ${{ github.event.issue.title }}"
"""

VULN_INJECTION_HEAD_REF = """\
name: deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "deploying ${{ github.head_ref }} to prod"
"""

VULN_INJECTION_INPUT = """\
name: manual
on:
  workflow_dispatch:
    inputs:
      tag:
        required: true
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: ./release.sh ${{ inputs.tag }}
"""

SAFE_SECRETS = """\
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "sha=${{ github.sha }} run=${{ github.run_id }}"
      - run: curl -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" https://api.example.com
"""

VULN_UNPINNED = """\
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-vendor/deploy-action@main
"""

SAFE_PINNED = """\
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: ./local-action
"""

VULN_PERMS = """\
name: ci
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""

SAFE_PERMS = """\
name: ci
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""


# ---------------------------------------------------------------------------
# behavior (needs binary)
# ---------------------------------------------------------------------------

@needs_sg
def test_script_injection_fires():
    res = _run_rules({".github/workflows/vuln.yml": VULN_INJECTION})
    rules = [r for r, _ in res]
    assert "braimsec.gha.script-injection" in rules


@needs_sg
def test_script_injection_head_ref_and_inputs_fire():
    res = _run_rules({
        ".github/workflows/a.yml": VULN_INJECTION_HEAD_REF,
        ".github/workflows/b.yml": VULN_INJECTION_INPUT,
    })
    by_file = {}
    for rule, fname in res:
        by_file.setdefault(fname, []).append(rule)
    assert "braimsec.gha.script-injection" in by_file["a.yml"]
    assert "braimsec.gha.script-injection" in by_file["b.yml"]


@needs_sg
def test_safe_contexts_stay_silent():
    res = _run_rules({".github/workflows/safe.yml": SAFE_SECRETS})
    assert res == [], f"false positive on safe contexts: {res}"


@needs_sg
def test_unpinned_actions_fire():
    res = _run_rules({".github/workflows/vuln.yml": VULN_UNPINNED})
    rules = [r for r, _ in res]
    assert rules.count("braimsec.gha.unpinned-action") == 2, res


@needs_sg
def test_pinned_and_local_actions_stay_silent():
    res = _run_rules({".github/workflows/safe.yml": SAFE_PINNED})
    assert res == [], f"false positive on pinned actions: {res}"


@needs_sg
def test_broad_permissions_fires():
    res = _run_rules({".github/workflows/vuln.yml": VULN_PERMS})
    rules = [r for r, _ in res]
    assert "braimsec.gha.broad-permissions" in rules


@needs_sg
def test_scoped_permissions_stay_silent():
    res = _run_rules({".github/workflows/safe.yml": SAFE_PERMS})
    assert res == [], f"false positive on scoped permissions: {res}"


@needs_sg
def test_engine_wires_gha_pack(monkeypatch):
    """run_semgrep loads braimsec-gha.yaml via --config (like the taint pack)."""
    import scan_engine
    monkeypatch.setattr(scan_engine, "SEMGREP_BIN", SG)
    d = tempfile.mkdtemp(prefix="gha-engine-")
    wf = os.path.join(d, "w.yml")
    with open(wf, "w") as f:
        f.write(VULN_INJECTION)
    findings = scan_engine.run_semgrep(d, scope=[wf])
    rule_ids = {fl.get("rule_id", "") for fl in findings}
    assert any("braimsec.gha.script-injection" in r for r in rule_ids), \
        f"GHA pack not wired into engine; got: {sorted(rule_ids)[:5]}"
