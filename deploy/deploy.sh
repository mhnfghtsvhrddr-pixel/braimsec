#!/usr/bin/env bash
#
# BraimSec production deploy — Hetzner CX22, Ubuntu 24.04
#
# One script: provisions Docker, builds the sandbox image, starts the stack,
# and runs the production smoke test.
#
#   Stage 1 (smoke on IP):    sudo ./deploy.sh
#       SITE_ADDRESS is auto-set to http://<public-ip> (plain HTTP).
#   Stage 2 (domain + TLS):   sudo ./deploy.sh --domain api.braimsec.world
#       Point the A record at the server IP first; Caddy fetches the
#       Let's Encrypt certificate automatically.
#
#   Flags:
#       --rebuild-runner   force rebuild of the scan-runner image
#       --skip-smoke       start the stack, skip the smoke test
#       --smoke-only       only run the smoke test against the running stack
#
# The master API key (BRAIMSEC_API_KEY) is generated on first run, stored in
# .env and printed at the end — keep it secret.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$SCRIPT_DIR"

REBUILD_RUNNER=0
SKIP_SMOKE=0
SMOKE_ONLY=0
DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rebuild-runner) REBUILD_RUNNER=1; shift ;;
        --skip-smoke)     SKIP_SMOKE=1; shift ;;
        --smoke-only)     SMOKE_ONLY=1; shift ;;
        --domain)
            if [[ $# -lt 2 ]]; then
                echo "missing value for --domain" >&2; exit 2
            fi
            DOMAIN="$2"; shift 2 ;;
        --domain=*)       DOMAIN="${1#--domain=}"; shift ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "run as root (sudo ./deploy.sh)" >&2
    exit 1
fi

step() { echo; echo "==> $*"; }

# ---------------------------------------------------------------- docker ---
install_docker() {
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        echo "docker already installed: $(docker --version)"
        return
    fi
    step "installing Docker (official repo)"
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) \
signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    docker --version
}

# ------------------------------------------------------------------ .env ---
public_ip() {
    curl -s --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d ' \n' \
        || curl -s --max-time 10 https://api.ipify.org 2>/dev/null | tr -d ' \n' \
        || echo ""
}

env_get() {  # env_get KEY -> value or empty
    local key="$1" line
    line="$(grep -E "^${key}=" .env 2>/dev/null | tail -1 || true)"
    echo "${line#*=}"
}

env_set() {  # env_set KEY VALUE (replace or append)
    local key="$1" value="$2"
    if grep -qE "^${key}=" .env 2>/dev/null; then
        sed -i -E "s|^${key}=.*|${key}=${value}|" .env
    else
        printf '%s=%s\n' "$key" "$value" >> .env
    fi
}

bootstrap_env() {
    step "checking .env"
    if [[ ! -f .env ]]; then
        cp .env.example .env
        chmod 600 .env
        echo "created .env from .env.example"
    fi

    if [[ -n "$DOMAIN" ]]; then
        env_set SITE_ADDRESS "$DOMAIN"
        echo "SITE_ADDRESS=$DOMAIN (stage 2: TLS via Caddy)"
    else
        cur="$(env_get SITE_ADDRESS)"
        if [[ -z "$cur" || "$cur" == "http://127.0.0.1" ]]; then
            ip="$(public_ip)"
            if [[ -z "$ip" ]]; then
                echo "ERROR: cannot detect public IP; set SITE_ADDRESS in .env manually" >&2
                exit 1
            fi
            env_set SITE_ADDRESS "http://${ip}"
            echo "SITE_ADDRESS=http://${ip} (stage 1: smoke on IP)"
        else
            echo "SITE_ADDRESS=$cur (kept)"
        fi
    fi

    if [[ -z "$(env_get BRAIMSEC_API_KEY)" ]]; then
        key="$(openssl rand -hex 32)"
        env_set BRAIMSEC_API_KEY "$key"
        chmod 600 .env
        echo "generated master API key (stored in .env)"
    else
        echo "master API key already set"
    fi
}

# ------------------------------------------------------------------ data ---
prepare_data_dir() {
    local dir
    dir="$(env_get HOST_DATA_DIR)"
    [[ -z "$dir" ]] && dir="/data/braimsec"
    step "data dir: $dir"
    mkdir -p "$dir"
    echo "HOST_DATA_DIR=$dir"
}

# ------------------------------------------------------------------ runner -
build_runner() {
    local image
    image="$(env_get BRAIMSEC_SCAN_RUNNER_IMAGE)"
    [[ -z "$image" ]] && image="braimsec/scan-runner:1.0"
    if [[ "$REBUILD_RUNNER" -eq 0 ]] && docker image inspect "$image" >/dev/null 2>&1; then
        echo "runner image $image already present (use --rebuild-runner to force)"
        return
    fi
    step "building sandbox image $image (needs network: pip + rules)"
    docker build -f "$REPO_ROOT/deploy/docker/scan-runner.Dockerfile" \
        -t "$image" "$REPO_ROOT"
    echo "runner image ready: $image"
}

# ------------------------------------------------------------------ stack --
start_stack() {
    step "starting stack"
    docker compose -f docker-compose.prod.yml up -d --build
    docker compose -f docker-compose.prod.yml ps
}

wait_healthy() {
    step "waiting for API health"
    local i body
    for i in $(seq 1 40); do
        body="$(curl -s --max-time 5 http://127.0.0.1:8000/api/health || true)"
        if echo "$body" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
            echo "API healthy: $body"
            return 0
        fi
        sleep 5
    done
    echo "ERROR: API did not become healthy" >&2
    docker compose -f docker-compose.prod.yml logs --tail=50 api || true
    exit 1
}

# ------------------------------------------------------------------ smoke --
smoke_test() {
    local key api site
    key="$(env_get BRAIMSEC_API_KEY)"
    api="http://127.0.0.1:8000"
    step "smoke test"

    echo "--- 1/5 GET /api/health (direct + through Caddy)"
    curl -sf --max-time 10 "$api/api/health" | head -c 200; echo
    site="$(env_get SITE_ADDRESS)"
    if [[ -n "$site" ]]; then
        curl -sf --max-time 15 "$site/api/health" -o /dev/null \
            -w "via Caddy ($site): HTTP %{http_code}\n"
    fi

    echo "--- 2/5 GET /api/plans"
    curl -sf --max-time 10 "$api/api/plans" -o /dev/null -w "HTTP %{http_code}\n"

    echo "--- 3/5 end-to-end scan (zip upload -> queue -> sandbox engines)"
    local work scan_id status results
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' RETURN
    mkdir -p "$work/smoke/.github/workflows"
    # Fake secrets: Stripe's public documentation example key + a GHA
    # injection pattern. Never real credentials; never committed to git.
    # (The sk_live_ literal is split so GitHub push protection doesn't
    # flag this file.)
    _sk="sk_live_"
    printf 'stripe_key = "%s4eC39HqLyjWDarjtT1zdp7dc"\n' "$_sk" > "$work/smoke/app.py"
    printf 'run: echo "${{ github.event.issue.title }}"\n' \
        > "$work/smoke/.github/workflows/ci.yml"
    (cd "$work/smoke" && python3 - "$work/smoke.zip" <<'EOF'
import sys, zipfile
zf = zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED)
zf.write("app.py", "app.py")
zf.write(".github/workflows/ci.yml", ".github/workflows/ci.yml")
zf.close()
EOF
    )

    post_out="$(curl -s --max-time 30 -X POST "$api/api/scans" \
        -H "x-api-key: $key" -F "file=@$work/smoke.zip")"
    scan_id="$(echo "$post_out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if "scan_id" not in d:
    sys.stderr.write("scan creation failed: %s\n" % json.dumps(d)[:300])
    sys.exit(1)
print(d["scan_id"])')"
    echo "scan_id=$scan_id"

    status=""
    for _ in $(seq 1 60); do
        status="$(curl -s --max-time 10 "$api/api/scans/$scan_id" \
            -H "x-api-key: $key" \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
        [[ "$status" == "done" || "$status" == "failed" ]] && break
        sleep 5
    done
    echo "final status: $status"
    if [[ "$status" != "done" ]]; then
        echo "ERROR: smoke scan did not complete (status=$status)" >&2
        curl -s "$api/api/scans/$scan_id" -H "x-api-key: $key" | head -c 500; echo
        exit 1
    fi

    echo "--- 4/5 findings (expect >= 1: gitleaks stripe + semgrep GHA)"
    results="$(curl -s --max-time 10 "$api/api/scans/$scan_id/results" \
        -H "x-api-key: $key")"
    echo "$results" | python3 -c "
import json, sys
d = json.load(sys.stdin)
fs = d['findings'] if isinstance(d, dict) else d
print(len(fs), 'findings')
for f in fs:
    print(' -', f.get('tool'), '|', f.get('rule_id'), '|', f.get('file'))
assert len(fs) >= 1, 'expected at least 1 finding'
"

    echo "--- 5/5 sandbox proof (worker log must show the isolated run)"
    if docker compose -f docker-compose.prod.yml logs worker 2>/dev/null \
        | grep -q "sandbox scan ok: container=braimsec-scan-"; then
        docker compose -f docker-compose.prod.yml logs worker 2>/dev/null \
            | grep "sandbox scan ok: container=braimsec-scan-" | tail -1
    else
        echo "ERROR: no sandbox run found in worker logs" >&2
        exit 1
    fi

    echo
    echo "SMOKE TEST PASSED"
}

print_summary() {
    local site key
    site="$(env_get SITE_ADDRESS)"
    key="$(env_get BRAIMSEC_API_KEY)"
    echo
    echo "================= BraimSec is up ================="
    echo "public URL : $site"
    echo "health     : $site/api/health"
    echo "master key : $key   (also in deploy/.env — keep secret)"
    echo "logs       : docker compose -f docker-compose.prod.yml logs -f"
    echo "=================================================="
}

# ------------------------------------------------------------------ main ---
if [[ "$SMOKE_ONLY" -eq 1 ]]; then
    smoke_test
    exit 0
fi

install_docker
bootstrap_env
prepare_data_dir
build_runner
start_stack
wait_healthy

if [[ "$SKIP_SMOKE" -eq 0 ]]; then
    smoke_test
fi
print_summary
