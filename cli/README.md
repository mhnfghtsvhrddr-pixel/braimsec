# braimsec CLI

Command-line client for the BraimSec security scanner, designed as a
**CI/CD quality gate**: scan a directory, wait for results, and fail the
build when findings exceed a severity threshold.

Standard library only — no `pip install` of third-party packages needed.

## Install

```bash
# Option 1: run directly
python3 cli/braimsec.py --version

# Option 2: put it on your PATH
install -m755 cli/braimsec.py ~/.local/bin/braimsec
braimsec --version
```

Requires Python 3.9+.

## Configuration

The API key is **never printed** — not in output, errors, or logs.

Priority: CLI flag > environment variable > config file.

| Setting  | Flag        | Env var            | Config file (`~/.braimsec/config`) |
|----------|-------------|--------------------|------------------------------------|
| Server   | `--server`  | `BRAIMSEC_SERVER`  | `server`                           |
| API key  | `--api-key` | `BRAIMSEC_API_KEY` | `api_key`                          |

The config file is either JSON or `KEY=VALUE` lines:

```json
{"server": "https://api.braimsec.world", "api_key": "bs_your_key_here"}
```

```bash
chmod 600 ~/.braimsec/config   # it holds a secret - keep it private
```

## Usage

```bash
# Scan the current directory, print a table
braimsec scan .

# Fail the build on any critical (error-level) finding -> exit code 2
braimsec scan ./src --fail-on critical

# Fail on high (warning) or worse, write a JSON report to disk
braimsec scan ./src --fail-on high --format json --output report.json

# SARIF output (upload to GitHub code scanning, see reports/SARIF.md)
braimsec scan ./src --format sarif --output results.sarif

# Scan one file under a project, don't wait for results
braimsec scan ./app.py --project <project-id> --no-wait
# abc123scan

# Check a scan later
braimsec status abc123scan
```

Severity mapping for `--fail-on`: `critical` = BraimSec `error`,
`high` = `warning`, `low`/`medium` = any finding, `never` = never fail.

Exit codes: `0` ok / gate passed, `1` usage/auth/network error,
`2` quality gate failed, `3` the scan itself failed on the server.

## GitHub Actions - fail the build on critical findings

```yaml
name: security-gate
on: [push, pull_request]

jobs:
  braimsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run BraimSec scan
        env:
          BRAIMSEC_SERVER: https://api.braimsec.world
          BRAIMSEC_API_KEY: ${{ secrets.BRAIMSEC_API_KEY }}
        run: |
          curl -sSL https://raw.githubusercontent.com/mhnfghtsvhrddr-pixel/braimsec/main/cli/braimsec.py \
            -o braimsec.py
          chmod +x braimsec.py
          # Fails the job (exit 2) when a critical finding is present,
          # and keeps a SARIF report as a build artifact.
          ./braimsec.py scan . --fail-on critical \
            --format sarif --output braimsec.sarif

      - name: Upload SARIF to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: braimsec.sarif
          category: braimsec
```

Store your key once at *Settings → Secrets → Actions* as `BRAIMSEC_API_KEY`.
