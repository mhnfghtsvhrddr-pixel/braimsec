# BraimSec production deploy (Hetzner CX22)

Production stack: **Caddy → FastAPI → Redis ← Celery worker**, all on one
CX22 (2 vCPU / 4 GB RAM / 40 GB SSD). SQLite and scan targets live in a host
directory (`HOST_DATA_DIR`, default `/data/braimsec`) mounted at the same
path in api+worker — it survives redeploys, unlike Railway-style ephemeral
disks, and lets the worker spawn sibling sandbox containers by absolute path.

## Scan sandbox (Docker isolation)

semgrep and gitleaks analyze **untrusted code**, so in production they run
inside throwaway `braimsec/scan-runner` containers, not in the worker
process. Each container is locked down: `--network none`, `--read-only`,
target mounted `:ro`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
`--pids-limit 256`, 2 GB RAM, 2 CPUs, `/tmp` as tmpfs. The vendored ruleset
is frozen into the image (no `--config auto`, which needs the network).
SCA stays on the host (manifest parsing + OSV lookups need the network and
never execute target code).

BraimSec's own rule packs (`scanner/rules/braimsec-{taint,gha,inject}.yaml`)
are also frozen into the image at `/opt/rules-braimsec/` (copied by
`docker/scan-runner.Dockerfile`, wired via `runner-entrypoint.py`, and
**validated at build time** with `semgrep --validate` — a broken pack fails
the build). After changing any rule file, rebuild the runner image on the
server: `deploy.sh --rebuild-runner` (the image is cached otherwise, so
rule edits do NOT take effect until you rebuild).

- `BRAIMSEC_SCAN_SANDBOX=docker` (default in compose; `local` = dev only)
- `BRAIMSEC_SCAN_RUNNER_IMAGE=braimsec/scan-runner:1.0`
- Fail-closed: a container error fails the scan loudly — never a silent
  fallback to un-isolated engines.
- Security note: the worker mounts `/var/run/docker.sock` to spawn the
  sandbox. A compromised worker with that socket is host-root equivalent.
  Accepted for phase 1 (the worker already runs the engines); revisit with
  a socket proxy or a dedicated runner service before multi-tenant
  production.

## Files

| File | Purpose |
|---|---|
| `Dockerfile.prod` | Full image: API + worker + semgrep 1.178.0 + gitleaks 8.28.0 (both pinned to the versions our rules/evals were validated against) + Docker CLI (worker spawns the sandbox) + all code (`api/`, `scanner/`, `ai/`, `reports/`, `dashboard/`). The old root `Dockerfile` only copied `api/`+`dashboard/` and no engines — it cannot run a real scan. |
| `docker/scan-runner.Dockerfile` | Minimal sandbox image: semgrep 1.178.0 + gitleaks 8.28.0 (both sha256-pinned) + vendored ruleset snapshot + `runner-entrypoint.py`. Built once per server (see Deploy stages). |
| `docker-compose.prod.yml` | `redis` (AOF persistence), `api` (uvicorn), `worker` (celery, concurrency 2), `beat` (celery beat — fires the scan scheduler every 60s), `caddy` (auto-TLS reverse proxy). api+worker share the host data dir at the same path (required: worker must see the same scan targets and the same `BRAIMSEC_DB`, and sandbox mounts use absolute paths). |
| `deploy.sh` | **One-command provision + deploy + smoke test** (run as root on the server): installs Docker (official repo), bootstraps `.env` (auto-detects the public IP for stage 1, generates the master API key), creates the data dir, builds the scan-runner image, starts the stack, waits for health, then runs the smoke test (health, plans, end-to-end scan with findings, sandbox proof from worker logs). `--domain api.braimsec.world` for stage 2, `--rebuild-runner`, `--skip-smoke`, `--smoke-only`. |
| `Caddyfile` | Templated by `SITE_ADDRESS`: `http://<ip>` for smoke test, `api.braimsec.world` for production (automatic Let's Encrypt). |
| `.env.example` | Copy to `.env`; never commit real secrets. |

## Deploy stages

1. **Server**: Hetzner CX22, Ubuntu 24.04, Falkenstein. SSH as root.
   Copy the repo's `deploy/` to the server (or clone the repo), then:
   ```sh
   cd deploy && sudo ./deploy.sh
   ```
   The script installs Docker, creates `/data/braimsec`, builds the
   scan-runner image, starts the stack and runs the full smoke test.
2. **Stage 1 — smoke test on IP**: `SITE_ADDRESS=http://<server-ip>`,
   `sudo ./deploy.sh` (provisions Docker, builds the runner image, starts
   the stack and runs the smoke test), then verify: `GET /api/health`
   must return 200 with `"status": "ok"` (it checks the DB and the Redis
   broker), `GET /api/plans` must return 200, and a small scan must
   complete end-to-end (queued → done, engines produce findings **from
   inside the sandbox** — the worker logs a `sandbox scan ok:
   container=braimsec-scan-*` line per scan; the containers are `--rm`,
   so `docker ps -a` cannot show them afterwards).
3. **Stage 2 — production domain**: point `api.braimsec.world` (A record) at the
   server IP, set `SITE_ADDRESS=api.braimsec.world`, `docker compose up -d`
   (Caddy fetches the TLS certificate automatically).
4. **Stage 3 — payments** (only after stage 2 is stable): fill
   `NOWPAYMENTS_API_KEY` / `NOWPAYMENTS_IPN_SECRET` in `.env`, set the IPN
   callback URL in the NowPayments dashboard to the production backend, then run
   the full checkout → IPN → subscription-activation cycle with Mahmoud's
   explicit approval before any real money moves.

## Notes

- AI review degrades gracefully with no LLM keys (AI-gated findings stay silent
  instead of guessing) — keys can be added later without a rebuild.
- `SINK_AUDIT_OFF=1` / `SCA_OFFLINE=1` are available as kill switches.
- Celery is real here (`BRAIMSEC_BROKER_URL` set); the inline fallback only
  applies to dev.

## Backups

- `deploy/backup.sh` runs nightly from root's crontab
  (`0 2 * * * /root/braimsec-backup.sh`): online SQLite snapshot via the
  backup API (WAL-safe, zero downtime) + `uploads/` and `scans/`, with
  `PRAGMA integrity_check` on every snapshot and 7-daily / 4-weekly
  (Mondays) retention under `/root/backups/`.
- Restore: `tar -xzf /root/backups/daily/braimsec-YYYY-MM-DD.tar.gz -C /tmp/r`
  then point the stack at `/tmp/r/braimsec-backup.db` (or copy it over
  `/data/braimsec/braimsec.db` while the stack is stopped).

## Scheduled scans + alerts

- Customers create schedules in the dashboard (⏰ tab) or via
  `POST /api/schedules`: daily/weekly at a chosen time + timezone,
  alert threshold (error/warning/note) and a Slack/Discord webhook URL.
- The `beat` service runs `braimsec.check_schedules` every 60s; each due
  schedule is claimed atomically (one conditional UPDATE — no double runs)
  and a worker scan is queued against the previous run as its baseline
  (incremental, engines are spared).
- After each scheduled scan finishes, the worker diffs the new findings
  against the previous run (fingerprint ignores line numbers, so a moved
  finding is not "new") and posts to the webhook on new results ≥ the
  threshold — max 3 attempts with backoff, recorded in `notifications`.
  First run is a silent baseline; a **failed** scheduled scan also alerts
  (`schedule.failed`) so a blind spot is never silent. Email is
  deliberately not implemented — webhooks only.
- Webhook URLs are SSRF-guarded (no private/loopback targets) at creation
  and at delivery (re-resolved + pinned, best-effort).
