"""
CI benchmark harness: measures F1 on the labeled corpus on every run,
appends to history.jsonl, and FAILS on regression vs baseline.

Usage:
    python3 ci_benchmark.py [--tool ours|bandit|both] [--baseline 0.80]
                            [--update-baseline]

In CI (GitHub Actions) this gates merges: F1 must not drop below baseline.
Portable: history/baseline live next to this file; binaries via PATH/env.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
from run_benchmark import evaluate, engine_findings, bandit_findings  # noqa: E402

HISTORY = os.path.join(BASE, "history.jsonl")


def git_commit():
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=10,
                           cwd=os.path.dirname(BASE))
        return r.stdout.strip() or "nogit"
    except Exception:
        return "nogit"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", default="ours", choices=["ours", "bandit", "both"])
    ap.add_argument("--baseline", type=float, default=0.80)
    ap.add_argument("--update-baseline", action="store_true",
                    help="rewrite baseline.json with the measured F1")
    args = ap.parse_args()

    tools = {"ours": [("BraimSec engine", engine_findings)],
             "bandit": [("Bandit", bandit_findings)],
             "both": [("BraimSec engine", engine_findings), ("Bandit", bandit_findings)]}[args.tool]

    results = []
    failed = False
    for name, fn in tools:
        print(f"Benchmarking {name}...")
        r = evaluate(fn, name)
        results.append(r)
        entry = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "commit": git_commit(), "tool": name,
                 "f1": r["f1"], "precision": r["precision"], "recall": r["recall"],
                 "tp": r["tp"], "fp": r["fp"], "tn": r["tn"], "fn": r["fn"]}
        with open(HISTORY, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"  F1={r['f1']} P={r['precision']} R={r['recall']} "
              f"(TP={r['tp']} FP={r['fp']} FN={r['fn']})")
        if name == "BraimSec engine":
            if r["f1"] < args.baseline:
                print(f"  ❌ REGRESSION: F1 {r['f1']} < baseline {args.baseline}")
                failed = True
            else:
                print(f"  ✅ F1 {r['f1']} >= baseline {args.baseline}")
            if args.update_baseline:
                json.dump({"f1_baseline": r["f1"], "updated": entry["ts"],
                           "commit": entry["commit"]},
                          open(os.path.join(BASE, "baseline.json"), "w"), indent=2)
                print("  baseline.json updated")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
