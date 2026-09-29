#!/usr/bin/env python3
"""Fresh-holdout evaluator for the BraimSec custom taint rules.

Runs Semgrep with ONLY the braimsec pack (not --config auto — we measure
OUR rules here) over fresh-holdout-v1/ and compares (rule, line) findings
against cases.json.

Usage:
    python3 run_eval.py [--rules PATH] [--holdout DIR]

Exit code 0 iff every case matches exactly. Prints TP/FP/FN + precision
+ recall at rule level. n is small by design: report it as an early
indicator, never as a marketing metric.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES = os.path.join(HERE, "..", "rules", "braimsec-taint.yaml")
DEFAULT_HOLDOUT = os.path.join(HERE, "fresh-holdout-v1")
SEMGREP_BIN = os.environ.get("SEMGREP_BIN", "semgrep")


def short_id(check_id):
    idx = check_id.find("braimsec.taint.")
    return check_id[idx:] if idx != -1 else check_id


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=DEFAULT_RULES)
    ap.add_argument("--holdout", default=DEFAULT_HOLDOUT)
    args = ap.parse_args()

    with open(os.path.join(args.holdout, "cases.json")) as f:
        manifest = json.load(f)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    try:
        p = subprocess.run(
            [SEMGREP_BIN, "--config", args.rules, "--json", "-o", out,
             args.holdout],
            capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("SKIP: semgrep binary not found", file=sys.stderr)
        return 2
    finally:
        pass
    with open(out) as f:
        data = json.load(f)
    os.unlink(out)

    got = {}
    for r in data.get("results", []):
        rid = short_id(r["check_id"])
        if not rid.startswith("braimsec.taint."):
            continue
        got.setdefault(os.path.basename(r["path"]), set()).add(
            (rid, r["start"]["line"]))

    tp = fp = fn = 0
    failures = []
    for case in manifest["cases"]:
        fname = case["file"]
        exp = {(e["rule"], e["line"]) for e in case["expected"]}
        actual = got.get(fname, set())
        ok = exp == actual
        tp += len(exp & actual)
        fp += len(actual - exp)
        fn += len(exp - actual)
        print(("PASS " if ok else "FAIL ") + fname +
              ("" if ok else f"  expected={sorted(exp)} actual={sorted(actual)}"))
        if not ok:
            failures.append(fname)

    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    print(f"\nrule-level: TP={tp} FP={fp} FN={fn} "
          f"precision={prec:.3f} recall={rec:.3f} "
          f"(n={len(manifest['cases'])} cases)")
    if failures:
        print("FAILED cases:", ", ".join(failures))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
