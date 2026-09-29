# BraimSec PR Review Bot

GitHub Action that reviews the **diff**, not the repo. Copy
`braimsec.yml` into your repository at `.github/workflows/braimsec.yml`.

## What it does

On every pull request the bot:

1. Diffs `base...head` and scans **only changed files** (Semgrep +
   BraimSec taint rules + gitleaks).
2. Keeps a finding only if its line is an **added** line **and** the same
   rule doesn't fire on the same code in the base revision (a legacy line
   moved by refactoring is not "new"). Overlapping findings on one line
   collapse to a single comment (our taint rules first).
3. Applies the gates — a comment is posted only for:
   - severity `error`, **and**
   - `gitleaks` (leaked secret — deterministic), **or**
   - AI verdict `vulnerable` from BraimSec's AI-review layer.
   
   Warnings never comment. If the AI fails or times out, the bot stays
   silent and logs instead of commenting unreviewed.
4. Posts one inline review comment per finding, with the AI explanation
   and — for taint findings — the exploitation path (Part 3 trace).

## Setup

1. Copy the workflow file.
2. *(Recommended)* Add repository secrets so the AI gate works:
   - `BRAIMSEC_AI_API_URL` — OpenAI-compatible endpoint
   - `BRAIMSEC_AI_API_KEY`
   - `BRAIMSEC_AI_MODEL` (optional)
   
   Without them, only leaked secrets can produce comments — by design.

## Local dry-run

```bash
python scanner/prbot.py /path/to/repo --base HEAD~1 --head HEAD
```

Prints the JSON report without posting. Add `--post --repo-slug
owner/repo --pr 123` with `GITHUB_TOKEN` set to actually post.

## Honest limits (v1)

- Python taint traces are intra-file (Part 3 v1 limit propagates here).
- SCA (dependency) findings are not reviewed on diffs yet.
- The bot needs full git history (`fetch-depth: 0`); shallow clones break
  the base-branch dedup.
