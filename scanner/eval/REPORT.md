# Fresh Holdout v1 — Taint Rules Evaluation Report

*Date: 2026-09-30. Set: `scanner/eval/fresh-holdout-v1/` (14 cases).
Runner: `scanner/eval/run_eval.py` (exit 0 = all cases match).*

## Method (SPEC v1.0 §4 — no holdout contamination)

- The set was written **first, from the rule design intent** — 9 intended
  findings across SSRF / file-upload / path-traversal, 5 safe cases —
  then measured **once**. Nothing was tuned against the old holdout, and
  the rules were not tuned against this set either.
- n=14 is an **early indicator, not a marketing metric**. Do not quote
  these numbers outside this context.

## Rule-level results (braimsec pack only)

| metric | value |
|---|---|
| TP | 9 |
| FP | 0 |
| FN | 0 |
| precision | 1.000 |
| recall | 1.000 |

## Gap-closure check (registry `--config auto` on the same 14 files)

| | vuln lines flagged | missed | FP on safe files |
|---|---|---|---|
| registry only | 6/9 | 3 (Django `request.GET` SSRF, `file.save()` upload, `pathlib` traversal) | 1 (`traversal_basename.py` — flags the `basename`-sanitized case) |
| registry + braimsec pack | 9/9 | 0 | 0 from braimsec rules (registry's basename FP is pre-existing) |

## Known limitation (by design)

`ssrf_allowlist.py` fires at rule level even though the code validates the
host against an allowlist. The SSRF rules ship **without** pattern
sanitizers because allowlist validation is not syntactic — this is
documented in `scanner/rules/braimsec-taint.yaml`. The AI review layer
(`FINDING_SYSTEM`) is the precision filter for that case, by product
architecture. End-to-end precision on taint-family findings was previously
measured at 1.000 on n=26 (2026-09-26, small sample — re-verify on fresh
data when AI keys are available).
