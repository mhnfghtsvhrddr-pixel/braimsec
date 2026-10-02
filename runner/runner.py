"""BraimSec scan-runner service: a narrow scan-only API in front of Docker.

The Celery worker NEVER talks to the Docker API directly. It POSTs a scan
request here; this service is the only component allowed to spawn sandbox
containers, and only with fixed hardened flags:

  - image pinned server-side (never client-controlled)
  - --network none, --read-only, --cap-drop ALL, no-new-privileges
  - target mounted read-only at /target; a fresh out dir at /out
  - resource caps (--memory/--cpus/--pids-limit)

Attack surface is intentionally tiny:

  - stdlib only (http.server) — no framework, no extra dependencies
  - two endpoints: GET /v1/health, POST /v1/scans
  - Bearer-token auth on /v1/scans (constant-time compare)
  - target_dir must live under HOST_DATA_DIR/uploads (no /etc mounts,
    no escapes via symlinks — realpath is resolved before the check)
  - scope entries must live under target_dir (no ../ escapes)
  - concurrency cap: 429 when saturated instead of fork-bombing the host
  - binds all interfaces but is reachable only on the internal compose
    network (no Caddy route, no published port)

Any failure is loud (4xx/5xx): the worker treats runner errors as scan
failures, never as a reason to scan outside the sandbox.
"""
import hashlib
import hmac
import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

log = logging.getLogger("runner")

DOCKER_BIN = os.environ.get("BRAIMSEC_DOCKER_BIN", "docker")
RUNNER_IMAGE = os.environ.get("BRAIMSEC_SCAN_RUNNER_IMAGE",
                              "braimsec/scan-runner:1.0")
CONTAINER_TIMEOUT = int(os.environ.get("BRAIMSEC_SCAN_CONTAINER_TIMEOUT",
                                       "600"))
CONTAINER_MEMORY = os.environ.get("BRAIMSEC_SCAN_CONTAINER_MEMORY", "2g")
CONTAINER_CPUS = os.environ.get("BRAIMSEC_SCAN_CONTAINER_CPUS", "2")
CONTAINER_PIDS = os.environ.get("BRAIMSEC_SCAN_CONTAINER_PIDS", "256")
HOST_DATA_DIR = os.environ.get("HOST_DATA_DIR", "/data/braimsec")
MAX_CONCURRENT = int(os.environ.get("RUNNER_MAX_CONCURRENT", "4"))
PORT = int(os.environ.get("RUNNER_PORT", "8001"))
API_KEY = os.environ.get("RUNNER_API_KEY", "")

UPLOADS_DIR = os.path.join(HOST_DATA_DIR, "uploads")

_slots = threading.Semaphore(MAX_CONCURRENT)
_active = 0
_active_lock = threading.Lock()


def _within(child: str, parent: str) -> bool:
    """True if realpath(child) is parent or lives under it."""
    try:
        return os.path.commonpath(
            [os.path.realpath(child), os.path.realpath(parent)]
        ) == os.path.realpath(parent)
    except (OSError, ValueError):
        return False


def validate_target(target_dir: str) -> str:
    """Return the real absolute target dir or raise ValueError."""
    if not target_dir or not isinstance(target_dir, str):
        raise ValueError("target_dir is required")
    real = os.path.realpath(os.path.abspath(target_dir))
    if not _within(real, UPLOADS_DIR):
        raise ValueError("target_dir outside uploads dir")
    if not os.path.isdir(real):
        raise ValueError("target_dir is not a directory")
    return real


def validate_scope(scope, target_real: str) -> list:
    """Scope entries must be files/dirs under the target. Returns [] if none."""
    if not scope:
        return []
    if not isinstance(scope, list):
        raise ValueError("scope must be a list")
    out = []
    for entry in scope:
        if not isinstance(entry, str):
            raise ValueError("scope entries must be strings")
        real = os.path.realpath(os.path.abspath(entry))
        if not _within(real, target_real):
            raise ValueError(f"scope entry escapes target: {entry!r}")
        out.append(real)
    return out


def resolve_cpus() -> str | None:
    """Clamp the sandbox --cpus request to what the host actually has."""
    if not CONTAINER_CPUS:
        return None
    try:
        requested = float(CONTAINER_CPUS)
    except ValueError:
        return CONTAINER_CPUS
    available = os.cpu_count() or 1
    if requested > available:
        log.warning("sandbox cpus clamped: requested=%s available=%d",
                    CONTAINER_CPUS, available)
    clamped = max(0.01, min(requested, float(available)))
    return str(int(clamped)) if clamped == int(clamped) else str(clamped)


def build_command(target_dir: str, out_dir: str,
                  name: str | None = None) -> list:
    """The hardened `docker run` invocation. Pure function, unit-tested.

    NOTE: flags are server-side constants — the HTTP API exposes no way
    to change the image, mounts, network mode or privileges.
    """
    cmd = [DOCKER_BIN, "run", "--rm"]
    if name:
        cmd += ["--name", name]
    cmd += [
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
    ]
    if CONTAINER_PIDS:
        cmd += ["--pids-limit", CONTAINER_PIDS]
    if CONTAINER_MEMORY:
        cmd += ["--memory", CONTAINER_MEMORY]
    cpus = resolve_cpus()
    if cpus:
        cmd += ["--cpus", cpus]
    cmd += [
        "-v", f"{target_dir}:/target:ro",
        "-v", f"{out_dir}:/out",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
        "-e", "HOME=/tmp",
        RUNNER_IMAGE,
    ]
    return cmd


class RunnerError(Exception):
    """A scan could not run. Maps to an HTTP 502 for the worker."""


def run_scan(target_dir: str, scope: list | None = None) -> dict:
    """Run the sandbox container. Returns {container, findings, duration_s}."""
    # Validate input BEFORE touching Docker: bad requests get a 400 even
    # if the daemon is down, and no container is ever spawned for them.
    target_real = validate_target(target_dir)
    scope_real = validate_scope(scope, target_real)
    if not shutil.which(DOCKER_BIN):
        raise RunnerError(f"docker binary not found ({DOCKER_BIN!r})")

    out_base = os.path.join(HOST_DATA_DIR, "sandbox-out")
    os.makedirs(out_base, exist_ok=True)
    out_dir = tempfile.mkdtemp(prefix="braimsec-sandbox-out-", dir=out_base)
    container_name = f"braimsec-scan-{uuid.uuid4().hex[:12]}"
    try:
        if scope_real:
            rel_scope = [os.path.relpath(p, target_real) for p in scope_real]
            with open(os.path.join(out_dir, "scope.json"), "w") as f:
                json.dump(rel_scope, f)
        cmd = build_command(target_real, out_dir, name=container_name)
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=CONTAINER_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise RunnerError(
                f"sandboxed scan timed out after {CONTAINER_TIMEOUT}s")
        if proc.returncode != 0:
            raise RunnerError(
                f"sandboxed scan failed (rc={proc.returncode}): "
                f"{proc.stderr.strip()[-500:]}")
        findings_path = os.path.join(out_dir, "findings.json")
        if not os.path.isfile(findings_path):
            raise RunnerError(
                "sandboxed scan produced no findings.json "
                f"(stdout: {proc.stdout.strip()[-300:]})")
        with open(findings_path) as f:
            findings = json.load(f)
        duration = time.time() - started
        log.info("scan ok: container=%s image=%s target=%s findings=%d "
                 "(%.1fs)", container_name, RUNNER_IMAGE, target_real,
                 len(findings), duration)
        return {"container": container_name,
                "image": RUNNER_IMAGE,
                "findings": findings,
                "duration_s": round(duration, 1)}
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "braimsec-runner/1.0"

    def log_message(self, fmt, *args):  # route through logging
        log.info("%s %s", self.address_string(), fmt % args)

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = auth[len("Bearer "):].strip()
        return hmac.compare_digest(token, API_KEY) if API_KEY else False

    def do_GET(self):
        if urlparse(self.path).path == "/v1/health":
            with _active_lock:
                busy = _active
            self._send(200, {"status": "ok", "busy_slots": busy,
                             "max_slots": MAX_CONCURRENT})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/v1/scans":
            self._send(404, {"error": "not found"})
            return
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 1_000_000:
            self._send(400, {"error": "invalid body"})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(400, {"error": "invalid JSON"})
            return
        if not isinstance(body, dict):
            self._send(400, {"error": "body must be an object"})
            return
        if not _slots.acquire(blocking=False):
            self._send(429, {"error": "runner saturated, retry later"})
            return
        global _active
        with _active_lock:
            _active += 1
        try:
            try:
                result = run_scan(body.get("target_dir"),
                                  body.get("scope"))
            except ValueError as e:
                self._send(400, {"error": str(e)})
                return
            except RunnerError as e:
                self._send(502, {"error": str(e)})
                return
            except Exception:
                # Never leave the worker hanging: unexpected bugs are
                # loud 500s, which fail the scan closed client-side.
                log.exception("unexpected runner error")
                self._send(500, {"error": "internal runner error"})
                return
            self._send(200, result)
        finally:
            with _active_lock:
                _active -= 1
            _slots.release()


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if not API_KEY:
        raise SystemExit("RUNNER_API_KEY is not set — refusing to start")
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    if not shutil.which(DOCKER_BIN):
        log.warning("docker binary %r not found at startup", DOCKER_BIN)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log.info("runner listening on :%d (image=%s max_concurrent=%d)",
             PORT, RUNNER_IMAGE, MAX_CONCURRENT)
    srv.serve_forever()


if __name__ == "__main__":
    main()
