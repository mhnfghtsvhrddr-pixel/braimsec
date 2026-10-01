#!/usr/bin/env python3
"""Runs INSIDE the braimsec/scan-runner container.

Reads the untrusted target from /target (mounted read-only), runs
semgrep (vendored rules + our custom rules) and gitleaks, and writes
normalized findings to /out/findings.json.

Exit codes: 0 = findings written (possibly empty); 1 = infrastructure
failure (engines crashed, /out not writable). A scan that completes with
zero findings still exits 0 with an empty list.
"""
import json
import os
import sys
import traceback

# Paths baked into the image by scan-runner.Dockerfile.
SEMGREP_BIN = os.environ.get("SEMGREP_BIN", "/opt/engines/bin/semgrep")
GITLEAKS_BIN = os.environ.get("GITLEAKS_BIN", "/opt/engines/bin/gitleaks")
VENDORED_RULES = os.environ.get("BRAIMSEC_VENDORED_RULES", "/opt/rules")
TAINT_RULES = os.environ.get("BRAIMSEC_TAINT_RULES",
                             "/opt/rules-braimsec/braimsec-taint.yaml")
GHA_RULES = os.environ.get("BRAIMSEC_GHA_RULES",
                           "/opt/rules-braimsec/braimsec-gha.yaml")
INJECT_RULES = os.environ.get("BRAIMSEC_INJECT_RULES",
                              "/opt/rules-braimsec/braimsec-inject.yaml")

sys.path.insert(0, "/opt/scanner")
os.environ["SEMGREP_BIN"] = SEMGREP_BIN
os.environ["GITLEAKS_BIN"] = GITLEAKS_BIN
os.environ["BRAIMSEC_TAINT_RULES"] = TAINT_RULES
os.environ["BRAIMSEC_GHA_RULES"] = GHA_RULES
os.environ["BRAIMSEC_INJECT_RULES"] = INJECT_RULES
# The sandbox runs with --network none: no metrics, no registry, no proxy.
os.environ["SEMGREP_SEND_METRICS"] = "off"
for _proxy_var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                   "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"):
    os.environ.pop(_proxy_var, None)

from scan_engine import run_gitleaks, run_semgrep  # noqa: E402


def _load_scope():
    p = "/out/scope.json"
    if os.path.isfile(p):
        with open(p) as f:
            rels = json.load(f)
        return [os.path.join("/target", r) for r in rels]
    return None


def main() -> int:
    target = "/target"
    out_path = "/out/findings.json"
    try:
        if not os.path.isdir(VENDORED_RULES):
            # Fail closed: a runner image without the vendored ruleset
            # would silently scan with (almost) no rules.
            raise RuntimeError(
                f"vendored rules missing at {VENDORED_RULES}: refusing "
                "to run a rule-less scan")
        scope = _load_scope()
        if scope is not None:
            # Incremental scan: only the files that still exist. An empty
            # scope means "nothing changed" -> zero engine findings, NOT a
            # full-target scan (fail closed against scope confusion).
            code_scope = [p for p in scope if os.path.isfile(p)]
            findings = (run_semgrep(target, code_scope,
                                    base_configs=[VENDORED_RULES])
                        + run_gitleaks(target, code_scope))
        else:
            findings = (run_semgrep(target, base_configs=[VENDORED_RULES])
                        + run_gitleaks(target))
        with open(out_path, "w") as f:
            json.dump(findings, f)
        return 0
    except Exception:  # noqa: BLE001 - report, don't leak a traceback-only exit
        try:
            with open("/out/error.txt", "w") as f:
                f.write(traceback.format_exc()[-2000:])
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
