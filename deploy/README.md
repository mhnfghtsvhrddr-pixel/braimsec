# BraimSec production deploy (Hetzner CX22)

Production stack: **Caddy → FastAPI → Redis ← Celery worker**, all on one
CX22 (2 vCPU / 4 GB RAM / 40 GB SSD). SQLite lives on a named Docker volume
(`braimsec-data`) — it survives redeploys, unlike Railway-style ephemeral disks.

## Files

| File | Purpose |
|---|---|
| `Dockerfile.prod` | Full image: API + worker + semgrep 1.178.0 + gitleaks 8.28.0 (both pinned to the versions our rules/evals were validated against) + all code (`api/`, `scanner/`, `ai/`, `reports/`, `dashboard/`). The old root `Dockerfile` only copied `api/`+`dashboard/` and no engines — it cannot run a real scan. |
| `docker-compose.prod.yml` | `redis` (AOF persistence), `api` (uvicorn), `worker` (celery, concurrency 2), `caddy` (auto-TLS reverse proxy). api+worker share the image and the data volume (required: worker must see the same scan targets and the same `BRAIMSEC_DB`). |
| `Caddyfile` | Templated by `SITE_ADDRESS`: `http://<ip>` for smoke test, `api.braimsec.world` for production (automatic Let's Encrypt). |
| `.env.example` | Copy to `.env`; never commit real secrets. |

## Deploy stages

1. **Server**: Hetzner CX22, Ubuntu 24.04, Falkenstein. SSH as root.
2. **Stage 1 — smoke test on IP**: `SITE_ADDRESS=http://<server-ip>`,
   `docker compose up -d --build`, then `GET /api/plans` must return 200 and a
   small scan must complete end-to-end (queued → done, engines produce findings).
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
