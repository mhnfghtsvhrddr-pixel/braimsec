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
    (SCA)         see sca.py: OSV_API_URL, OSV_TIMEOUT, SCA_TIMEOUT, SCA_OFFLINE
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

from sca import run_sca

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

ENGINE_NAME = "BraimSec Scanner"
ENGINE_VERSION = "0.1.0"

SEMGREP_SEVERITY = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}


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


def run_semgrep(target, scope=None):
    """Run Semgrep and return normalized findings.

    scope: optional list of absolute file paths to scan instead of the whole
    target directory (incremental scans). None = full target.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    cmd = [SEMGREP_BIN, "--config", "auto"]
    if BRAIMSEC_TAINT_RULES and os.path.isfile(BRAIMSEC_TAINT_RULES):
        cmd += ["--config", BRAIMSEC_TAINT_RULES]
    if BRAIMSEC_GHA_RULES and os.path.isfile(BRAIMSEC_GHA_RULES):
        cmd += ["--config", BRAIMSEC_GHA_RULES]
    targets = list(scope) if scope else [target]
    cmd += ["--json", "-o", out_path] + targets
    try:
        _run(cmd)
        with open(out_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        data = {}
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
    targets = list(scope) if scope else [target]
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
        except (json.JSONDecodeError, FileNotFoundError):
            data = []
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
