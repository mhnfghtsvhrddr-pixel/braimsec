#!/usr/bin/env python3
"""
BraimSec Scan Engine (prototype v0.1.0)
--------------------------------------
Orchestrates Semgrep + gitleaks + OSV-based SCA on a target code directory
and produces a unified SARIF 2.1.0 report.

Usage:
    python3 scan_engine.py /path/to/code -o results.sarif

Env overrides:
    SEMGREP_BIN   path to semgrep binary
    GITLEAKS_BIN  path to gitleaks binary
    BRAIMSEC_TAINT_RULES  path to the custom taint rule pack
                          (default: scanner/rules/braimsec-taint.yaml;
                           empty string disables it)
    BRAIMSEC_FULL_RULES=1 force the full semgrep rule set (disables
                          language scoping; see scanner/rule_scope.py)
    BRAIMSEC_RULE_SCOPING=0 disable language scoping entirely
    (SCA)         see sca.py: OSV_API_URL, OSV_TIMEOUT, SCA_TIMEOUT, SCA_OFFLINE
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile

from sca import run_sca
from rule_scope import select_rule_configs

log = logging.getLogger(__name__)

SEMGREP_BIN = os.environ.get("SEMGREP_BIN", "semgrep")
GITLEAKS_BIN = os.environ.get("GITLEAKS_BIN", "gitleaks")

# BraimSec custom taint rules (SSRF / file-upload / path-traversal gaps that
# the open-source registry does not cover). Shipped with the engine; loaded
# alongside `--config auto`. Env override for tests: BRAIMSEC_TAINT_RULES=path
# (empty string disables the custom pack).
_TAINT_RULES_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "rules", "braimsec-taint.yaml")
BRAIMSEC_TAINT_RULES = os.environ.get("BRAIMSEC_TAINT_RULES",
                                      _TAINT_RULES_DEFAULT)

# BraimSec GitHub Actions security rules (script injection / unpinned
# actions / broad permissions in .github/workflows/*.yml). Loaded alongside
# `--config auto` like the taint pack. Env override for tests:
# BRAIMSEC_GHA_RULES=path (empty string disables the pack).
_GHA_RULES_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "rules", "braimsec-gha.yaml")
BRAIMSEC_GHA_RULES = os.environ.get("BRAIMSEC_GHA_RULES",
                                    _GHA_RULES_DEFAULT)

# BraimSec injection rules (OS command injection / XXE / deserialization /
# SQLi / XSS / JS code injection — the highest-value OWASP Top 10 families).
# Loaded alongside `--config auto` like the other packs. Env override for
# tests: BRAIMSEC_INJECT_RULES=path (empty string disables the pack).
_INJECT_RULES_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "rules", "braimsec-inject.yaml")
BRAIMSEC_INJECT_RULES = os.environ.get("BRAIMSEC_INJECT_RULES",
                                       _INJECT_RULES_DEFAULT)

# BraimSec Dockerfile rules (root user / remote ADD / :latest / baked-in
# secrets / uncleaned apt cache / sensitive EXPOSE / curl-piped-to-shell).
# Loaded alongside `--config auto` like the other packs. Env override for
# tests: BRAIMSEC_DOCKERFILE_RULES=path (empty string disables the pack).
_DOCKERFILE_RULES_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "rules",
    "braimsec-dockerfile.yaml")
BRAIMSEC_DOCKERFILE_RULES = os.environ.get("BRAIMSEC_DOCKERFILE_RULES",
                                           _DOCKERFILE_RULES_DEFAULT)

# BraimSec Terraform rules (world-open security groups / public S3 ACLs /
# unencrypted RDS-EBS / disabled RDS backups). Loaded alongside
# `--config auto` like the other packs. Env override for tests:
# BRAIMSEC_TERRAFORM_RULES=path (empty string disables the pack).
_TERRAFORM_RULES_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "rules",
    "braimsec-terraform.yaml")
BRAIMSEC_TERRAFORM_RULES = os.environ.get("BRAIMSEC_TERRAFORM_RULES",
                                          _TERRAFORM_RULES_DEFAULT)

ENGINE_NAME = "BraimSec Scanner"
ENGINE_VERSION = "0.1.0"

SEMGREP_SEVERITY = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}


def _custom_pack_specs():
    """(name, path, languages) for each BraimSec custom rule pack.

    Read from the module constants at call time (not import time) so
    tests can monkeypatch individual packs. Languages are the semgrep
    language names the pack's rules target (verified from each pack's
    `languages:` fields, 2026-10-02).
    """
    return [
        ("taint", BRAIMSEC_TAINT_RULES, {"python"}),
        ("gha", BRAIMSEC_GHA_RULES, {"yaml"}),
        ("inject", BRAIMSEC_INJECT_RULES,
         {"python", "javascript", "typescript"}),
        ("dockerfile", BRAIMSEC_DOCKERFILE_RULES, {"dockerfile"}),
        ("terraform", BRAIMSEC_TERRAFORM_RULES, {"terraform"}),
    ]


class EngineError(RuntimeError):
    """A scanner binary is missing or timed out.

    Raised instead of sys.exit() so the engine is safe to embed in a
    long-lived process (the API server): a SystemExit inside a background
    task would hang the request instead of failing the scan cleanly.
    """

    def __init__(self, message, exit_code=2):
        super().__init__(message)
        self.exit_code = exit_code


def _run(cmd, timeout=600):
    """Run a command, never raise on non-zero exit (scanners signal findings)."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise EngineError(f"binary not found: {cmd[0]}", exit_code=2)
    except subprocess.TimeoutExpired:
        raise EngineError(f"timed out: {' '.join(cmd)}", exit_code=3)


def run_semgrep(target, scope=None, base_configs=None):
    """Run Semgrep and return normalized findings.

    scope: optional list of absolute file paths to scan instead of the whole
    target directory (incremental scans). None = full target.

    base_configs: configs replacing the default ``auto`` registry lookup
    (which needs the network). Used by the sandboxed scan runner, whose
    image vendors a pinned ruleset snapshot at build time. None = ["auto"].
    Both the base configs and the custom packs are narrowed to the
    target's detected languages (see scanner/rule_scope.py); pass
    BRAIMSEC_FULL_RULES=1 to force the full rule set.
    """
    if scope is not None and len(scope) == 0:
        return []  # incremental scan with no changed files: nothing to do
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    raw_base = base_configs if base_configs is not None else ["auto"]
    base, packs = select_rule_configs(raw_base, _custom_pack_specs(),
                                      target, scope)
    cmd = [SEMGREP_BIN]
    for cfg in base:
        cmd += ["--config", cfg]
    for _pack_name, pack_path in packs:
        cmd += ["--config", pack_path]
    targets = list(scope) if scope is not None else [target]
    cmd += ["--json", "-o", out_path] + targets
    try:
        proc = _run(cmd)
        try:
            with open(out_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            # Fail closed: semgrep always writes valid JSON on success
            # (verified: rc=0 on a clean target writes a full report).
            # A missing/corrupt report means the engine malfunctioned —
            # it must never masquerade as a clean scan.
            raise EngineError(
                f"semgrep produced no parseable report "
                f"(rc={proc.returncode}): {e}",
                exit_code=4,
            )
        if proc.returncode != 0 and not data.get("results"):
            # Fail closed: a crashed semgrep must never look like a clean
            # scan. (A non-zero exit WITH parseable findings is still
            # honored; only an engine that died without results raises.)
            raise EngineError(
                f"semgrep exited {proc.returncode} without results: "
                f"{(proc.stderr or '')[-500:]}",
                exit_code=4,
            )
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)

    findings = []
    for r in data.get("results", []):
        findings.append({
            "tool": "semgrep",
            "rule_id": r.get("check_id", "unknown"),
            "severity": SEMGREP_SEVERITY.get(r.get("extra", {}).get("severity"), "warning"),
            "message": r.get("extra", {}).get("message", "").strip(),
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 1),
            "col": r.get("start", {}).get("col", 1),
        })
    return findings


def run_gitleaks(target, scope=None):
    """Run gitleaks and return normalized findings.

    scope: optional list of absolute file paths to scan instead of the whole
    target directory (incremental scans). None = full target.
    """
    if scope is not None and len(scope) == 0:
        return []  # incremental scan with no changed files: nothing to do
    targets = list(scope) if scope is not None else [target]
    findings = []
    for t in targets:
        findings.extend(_run_gitleaks_one(t))
    return findings


def _run_gitleaks_one(target):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        # gitleaks exits 1 when leaks are found -> handled by _run
        _run([GITLEAKS_BIN, "detect", "--source", target, "--no-git",
              "--report-format", "json", "--report-path", out_path])
        try:
            with open(out_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            # Fail closed: gitleaks always writes valid JSON on success
            # (verified: rc=0 on a clean target writes `[]`).
            # A missing/corrupt report means the engine malfunctioned —
            # it must never masquerade as a clean scan.
            raise EngineError(
                f"gitleaks produced no parseable report: {e}",
                exit_code=4,
            )
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)

    findings = []
    for r in data or []:
        findings.append({
            "tool": "gitleaks",
            "rule_id": r.get("RuleID", "secret"),
            "severity": "error",  # leaked secrets are critical by default
            "message": f"Possible secret: {r.get('Description', r.get('RuleID', ''))}",
            "file": r.get("File", ""),
            "line": r.get("StartLine", 1),
            "col": r.get("StartColumn", 1),
        })
    return findings


def to_sarif(findings):
    """Convert normalized findings to SARIF 2.1.0."""
    rules = {}
    results = []
    for f in findings:
        rule_id = f"{f['tool']}/{f['rule_id']}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f["rule_id"],
                "shortDescription": {"text": f["message"][:200]},
            }
        results.append({
            "ruleId": rule_id,
            "level": f["severity"],
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {
                        "startLine": f["line"],
                        "startColumn": f["col"],
                    },
                }
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": ENGINE_NAME,
                    "version": ENGINE_VERSION,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def print_summary(findings):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"\n{'=' * 50}")
    print(f"  {ENGINE_NAME} v{ENGINE_VERSION} — scan complete")
    print(f"{'=' * 50}")
    print(f"  Total findings: {len(findings)}")
    for sev in ("error", "warning", "note"):
        if sev in counts:
            print(f"    {sev}: {counts[sev]}")
    print(f"{'=' * 50}\n")
    for f in findings:
        print(f"[{f['severity'].upper():7}] {f['tool']}/{f['rule_id']}")
        print(f"         {f['file']}:{f['line']}")
    print()


def main():
    parser = argparse.ArgumentParser(description="BraimSec Scan Engine")
    parser.add_argument("target", help="directory of code to scan")
    parser.add_argument("-o", "--output", default="results.sarif",
                        help="SARIF output path (default: results.sarif)")
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"ERROR: not a directory: {args.target}", file=sys.stderr)
        sys.exit(2)

    print(f"[*] Scanning {args.target} with Semgrep...", flush=True)
    try:
        findings = run_semgrep(args.target)
        print(f"[*] Scanning {args.target} with gitleaks...", flush=True)
        findings += run_gitleaks(args.target)
        print(f"[*] Scanning dependencies with OSV (SCA)...", flush=True)
        findings += run_sca(args.target)
    except EngineError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(e.exit_code)

    sarif = to_sarif(findings)
    with open(args.output, "w") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    print_summary(findings)
    print(f"[+] SARIF report written to {args.output}")


if __name__ == "__main__":
    main()
