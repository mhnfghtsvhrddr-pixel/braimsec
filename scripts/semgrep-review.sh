#!/usr/bin/env bash
#
# BraimSec canonical semgrep review.
#
# Runs the project's own rule packs over product code and prints a
# comparable summary (findings per pack + files scanned), so every review
# pass is directly comparable with the last one.
#
#   scripts/semgrep-review.sh          # project rules (gating)
#   scripts/semgrep-review.sh --audit  # + a second --config auto pass
#                                      #   (informational only)
#
# The target is the repo root: .semgrepignore (which excludes
# scanner/eval/ and the other non-product paths) is discovered relative
# to the scan root, so explicit subdir targets must NOT be used here.
# SEMGREP_BIN env override is respected.
#
# Exit code: 0 iff the project-rules pass has zero findings (CI/review
# can gate on it); 1 on findings; 2 on infrastructure failure (semgrep
# missing or an engine error — a broken engine must never report
# "0 findings").
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SEMGREP="${SEMGREP_BIN:-$HOME/workspace/venvs/sgvenv/bin/semgrep}"
if [[ ! -x "$SEMGREP" ]]; then
  SEMGREP="$(command -v semgrep || true)"
fi
if [[ -z "${SEMGREP}" || ! -x "$SEMGREP" ]]; then
  echo "ERROR: semgrep binary not found" >&2
  exit 2
fi
export SEMGREP_SEND_METRICS=off

PACKS=(taint gha inject dockerfile terraform)

AUDIT=0
if [[ "${1:-}" == "--audit" ]]; then
  AUDIT=1
elif [[ -n "${1:-}" ]]; then
  echo "usage: $(basename "$0") [--audit]" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

count_json() {
  # $1 = report path -> prints "<findings> <files_scanned>"
  python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
print(len(d['results']), len(d['paths']['scanned']))
" "$1"
}

echo "== BraimSec semgrep review =="
echo "semgrep : $("$SEMGREP" --version 2>/dev/null | head -n 1)"
echo "target  : repo root (product code; .semgrepignore excludes fixtures)"
echo

total_findings=0
files_scanned=0
printf '%-26s %8s %10s\n' "pack" "findings" "files"
for p in "${PACKS[@]}"; do
  pack="scanner/rules/braimsec-${p}.yaml"
  out="$tmpdir/${p}.json"
  rc=0
  "$SEMGREP" --config "$pack" --json -o "$out" . \
    >/dev/null 2>"$tmpdir/${p}.err" || rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "ERROR: semgrep engine failed on $pack (rc=$rc):" >&2
    tail -n 5 "$tmpdir/${p}.err" >&2
    exit 2
  fi
  counts="$(count_json "$out")"
  n="${counts%% *}"
  f="${counts##* }"
  printf '%-26s %8d %10d\n' "braimsec-${p}.yaml" "$n" "$f"
  total_findings=$((total_findings + n))
  if [[ "$f" -gt "$files_scanned" ]]; then
    files_scanned=$f
  fi
done
echo "------------------------------------------------------"
printf 'TOTAL (%d packs, up to %d files scanned): %d finding(s)\n' \
  "${#PACKS[@]}" "$files_scanned" "$total_findings"
echo

if [[ $AUDIT -eq 1 ]]; then
  echo "-- audit pass: --config auto (informational, does not gate) --"
  # The registry 'auto' config needs metrics enabled; allow them for this
  # pass only.
  rc=0
  env -u SEMGREP_SEND_METRICS "$SEMGREP" --config auto --json \
    -o "$tmpdir/audit.json" . >/dev/null 2>"$tmpdir/audit.err" || rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "warning: --config auto pass failed (rc=$rc; needs network?)" >&2
    tail -n 3 "$tmpdir/audit.err" >&2
  else
    counts="$(count_json "$tmpdir/audit.json")"
    echo "auto findings: ${counts%% *} (${counts##* } files scanned)"
  fi
  echo
fi

if [[ $total_findings -gt 0 ]]; then
  echo "REVIEW FAILED: $total_findings finding(s) with project rules" >&2
  exit 1
fi
echo "REVIEW PASSED: 0 findings with project rules"
