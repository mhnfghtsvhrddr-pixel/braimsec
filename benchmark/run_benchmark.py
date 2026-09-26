"""
Benchmark harness: our engine (Semgrep+gitleaks) vs Bandit
on the hand-labeled corpus. File-level scoring, documented methodology.

Portable: all paths are relative to this file's directory or come from
environment variables. No machine-specific absolute paths.

Env overrides:
    SEMGREP_BIN   path to semgrep binary (default: "semgrep" from PATH)
    GITLEAKS_BIN  path to gitleaks binary (default: "gitleaks" from PATH)
    BANDIT_BIN    path to bandit binary   (default: "bandit" from PATH)
    BRAIMSEC_CORPUS  corpus directory     (default: ./corpus)
"""
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.environ.get("BRAIMSEC_CORPUS", os.path.join(BASE, "corpus"))
LABELS = os.path.join(BASE, "labels.json")
SEMGREP = os.environ.get("SEMGREP_BIN", "semgrep")
GITLEAKS = os.environ.get("GITLEAKS_BIN", "gitleaks")
BANDIT = os.environ.get("BANDIT_BIN", "bandit")


def engine_findings(path):
    """Our engine: semgrep auto + gitleaks on a single file. Returns finding count."""
    n = 0
    try:
        r = subprocess.run([SEMGREP, "--config", "auto", "--json", "--quiet", path],
                           capture_output=True, text=True, timeout=180)
        n += len(json.loads(r.stdout).get("results", []))
    except Exception as e:
        print(f"  [semgrep err {os.path.basename(path)}: {e}]", file=sys.stderr)
    try:
        r = subprocess.run([GITLEAKS, "detect", "--no-git", "--source", path,
                            "--report-format", "json", "--report-path", "-",
                            "--exit-code", "0"],
                           capture_output=True, text=True, timeout=60)
        out = r.stdout.strip()
        if out:
            n += len(json.loads(out))
    except Exception as e:
        print(f"  [gitleaks err {os.path.basename(path)}: {e}]", file=sys.stderr)
    return n


def bandit_findings(path):
    """Bandit on a single file. Returns issue count."""
    try:
        r = subprocess.run([BANDIT, "-f", "json", "-q", path],
                           capture_output=True, text=True, timeout=120)
        data = json.loads(r.stdout or "{}")
        return len(data.get("results", []))
    except Exception as e:
        print(f"  [bandit err {os.path.basename(path)}: {e}]", file=sys.stderr)
        return 0


def evaluate(detect_fn, name):
    labels = json.load(open(LABELS))
    tp = fp = tn = fn = 0
    details = {"missed": [], "false_alarms": []}
    for fname in sorted(labels):
        label = labels[fname]
        hits = detect_fn(os.path.join(CORPUS, fname))
        detected = hits > 0
        if label == "VULN" and detected:
            tp += 1
        elif label == "VULN":
            fn += 1
            details["missed"].append(fname)
        elif detected:
            fp += 1
            details["false_alarms"].append((fname, hits))
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tool": name, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3), **details}


if __name__ == "__main__":
    print("Running our engine (Semgrep+gitleaks)...")
    ours = evaluate(engine_findings, "BraimSec engine")
    print("Running Bandit...")
    theirs = evaluate(bandit_findings, "Bandit")
    for r in (ours, theirs):
        print(f"\n{r['tool']}: TP={r['tp']} FP={r['fp']} TN={r['tn']} FN={r['fn']}")
        print(f"  Precision={r['precision']} Recall={r['recall']} F1={r['f1']}")
        print(f"  missed: {r['missed']}")
        print(f"  false_alarms: {r['false_alarms']}")
