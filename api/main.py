"""
BraimSec API (prototype v0.1.0)
------------------------------
REST API for the vulnerability scanning platform.

Endpoints:
    POST /api/scans            start a scan (target_path or uploaded zip)
    GET  /api/scans            list all scans
    GET  /api/scans/{id}       scan status + severity summary
    GET  /api/scans/{id}/results   findings list
    GET  /api/scans/{id}/sarif     SARIF 2.1.0 report
"""
import os
import csv
import io
import json
import logging
import secrets
import sqlite3
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from database import get_db, init_db
from audit import (archive_events, list_archives, log_event, read_events,  # noqa: E402
                   verify_archive)


def _audit(request: Request, action: str, resource_type: str = "",
           resource_id: str = "", detail: dict | None = None):
    """Write one audit-trail record for the caller's org and API key.

    Fail-closed: if the audit write fails, the API action fails too.
    An enterprise audit trail that silently drops records is worse than
    a 500 — a CISO must be able to trust that every recorded action
    really happened and every action really got recorded.
    """
    try:
        ip = request.client.host if request.client else ""
    except Exception:  # noqa: BLE001 - defensive: client info is best-effort
        ip = ""
    log_event(request.state.org_id, getattr(request.state, "actor", ""),
              action, resource_type, str(resource_id), detail or {}, ip)


def require_role(request: Request, minimum: str):
    """Enforce RBAC: the caller's key role must rank at or above ``minimum``.

    Raises 403 otherwise. Roles: viewer < member < admin < owner.
    """
    role = getattr(request.state, "role", "viewer")
    if role_rank(role) < role_rank(minimum):
        raise HTTPException(
            403, f"Requires '{minimum}' role or higher (this key: '{role}')")
    return role


def require_org_scope(request: Request):
    """Org-level surfaces (billing, audit trail) reject project-scoped keys.

    A key scoped to project P must not see the org's billing or the
    audit trail of other projects.
    """
    if getattr(request.state, "project_id", None):
        raise HTTPException(
            403, "Project-scoped keys cannot access org-level resources")


def _scan_scope(request: Request, alias: str = "s"):
    """SQL predicate + params restricting scans to the caller's visibility.

    Org-wide keys see the whole org; project-scoped keys see only their
    own project's scans (including unscoped legacy scans? No — a scoped
    key sees ONLY its project; legacy NULL-project scans stay visible
    to org-wide keys only).
    """
    pid = getattr(request.state, "project_id", None)
    prefix = f"{alias}." if alias else ""
    if pid:
        return f"{prefix}org_id=? AND {prefix}project_id=?", \
            [request.state.org_id, pid]
    return f"{prefix}org_id=?", [request.state.org_id]
from billing import (  # noqa: E402
    OWNER_ORG_ID, ROLES, cancel_subscription, consume_scan, create_org,
    create_project, delete_project, effective_plan, ensure_owner_org,
    ensure_subscription, get_subscription, list_plans, list_projects,
    provision_key, quota_check, quota_status, record_usage,
    revoke_key, role_rank, rotate_key, run_expiry, seed_plans, start_trial,
    usage_count, verify_key,
)
import nowpayments_pay as nowpay  # noqa: E402

# Reuse the scan engine prototype
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "reports"))
from sarif import SarifError, build_sarif, validate_sarif  # noqa: E402
from scan_badge import build_badge_svg  # noqa: E402
from builder import ReportError, build_report, compliance_map, lookup_compliance  # noqa: E402
from pdf import render_pdf  # noqa: E402
from executive import build_executive_report  # noqa: E402
from executive_pdf import render_executive_pdf  # noqa: E402
from sink_audit import (  # noqa: E402
    audit_candidates,
    discover_sinks,
    enabled as sink_audit_enabled,
)
from groq_provider import make_llm_client, sanitize_text  # noqa: E402
from taintflow import extract_taint_path  # noqa: E402
from fix_suggestions import (  # noqa: E402
    extract_fix_context,
    generate_fix,
    validate_fix,
)
from patch_verify import verify_patch  # noqa: E402

# Durable queue (Celery + Redis); falls back to inline BackgroundTasks
# when BRAIMSEC_BROKER_URL is unset.
from tasks import (celery_app, enqueue_ai_review, enqueue_scan,
                   queue_enabled, SCAN_SOFT_LIMIT_S)  # noqa: E402


log = logging.getLogger(__name__)


def now():
    return datetime.now(timezone.utc).isoformat()


app = FastAPI(title="BraimSec API", version="0.1.0",
                # Built-in docs are disabled: the curated, fail-closed API
                # reference lives at GET /docs (+ /api/openapi.json),
                # generated from api/openapi.py.
                docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------------------
# Security hardening (prototype-grade — not a substitute for production auth)
# ---------------------------------------------------------------------------
MAX_ZIP_BYTES = 50 * 1024 * 1024  # 50 MB upload cap (compressed size)
# Decompression-bomb guards: the 50MB cap above measures compressed bytes only.
MAX_ZIP_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB total extracted
MAX_ZIP_MEMBERS = 10_000
MAX_ZIP_MEMBER_BYTES = 100 * 1024 * 1024  # 100 MB per member
MAX_ZIP_COMPRESSION_RATIO = 100  # file_size / compress_size
# Sandbox for target_path: server-local scans may only read inside this root.
# Prevents LFI (e.g. target_path=/etc). Override with BRAIMSEC_SCAN_ROOT.
SCAN_ROOT = os.path.realpath(os.environ.get("BRAIMSEC_SCAN_ROOT", "/tmp/braimsec_scans"))
os.makedirs(SCAN_ROOT, exist_ok=True)
API_KEY_ENV = "BRAIMSEC_API_KEY"

API_KEY = os.environ.get(API_KEY_ENV)
if not API_KEY:
    # Secure by default: an unset key means a random ephemeral one.
    # Printed to the operator's console only — never written to files.
    API_KEY = secrets.token_urlsafe(32)
    print(f"[braimsec] {API_KEY_ENV} not set — generated ephemeral API key (console only).")


@app.middleware("http")
async def api_key_gate(request: Request, call_next):
    """Require X-API-Key on every /api/* route. Dashboard static files stay open.

    Two key types:
    - the master key (BRAIMSEC_API_KEY env): maps to the built-in 'owner' org.
    - per-customer keys (api_keys table, hashed): map to their org + plan.
    Sets request.state.org_id / request.state.plan for downstream handlers,
    plus request.state.actor (API key prefix, or 'owner' for the master key)
    for the audit trail. The full key secret never leaves this middleware.
    /api/plans is public (pricing catalog for the marketing page).
    /api/checkout/crypto is public (new-customer crypto checkout; rate-limited).
    /api/webhooks/nowpayments is public (NOWPayments IPN; secured by HMAC).
    /api/webhooks/github and /api/webhooks/gitlab are public (push receivers;
    secured by HMAC-SHA256 / token respectively).
    """
    public_paths = ("/api/plans", "/api/checkout/crypto",
                    "/api/checkout/status", "/api/webhooks/nowpayments",
                    "/api/webhooks/github", "/api/webhooks/gitlab",
                    "/api/openapi.json",
                    "/api/health")
    path = request.url.path
    # The scan badge is public by design (README embedding): it exposes only
    # aggregate severity counts, never scan metadata (see scan_badge.py).
    is_badge = (path.startswith("/api/scans/") and path.endswith("/badge.svg"))
    if path.startswith("/api/") and path not in public_paths and not is_badge:
        presented = request.headers.get("x-api-key", "")
        org = None
        actor = ""
        role = "viewer"
        if presented:
            if secrets.compare_digest(presented, API_KEY):
                org = {"org_id": OWNER_ORG_ID, "plan": "team"}
                actor = "owner"
                role = "owner"
            else:
                org = verify_key(presented)
                actor = (org or {}).get("key_prefix", "")
                role = (org or {}).get("role", "viewer")
        if not org:
            return JSONResponse(
                {"detail": "Invalid or missing X-API-Key header"}, status_code=401
            )
        request.state.org_id = org["org_id"]
        request.state.plan = org["plan"]
        request.state.actor = actor
        request.state.role = role
        request.state.key_id = (org or {}).get("key_id")  # None for master key
        # Project scope: None = org-wide key; otherwise the key only sees
        # its own project's data.
        request.state.project_id = (org or {}).get("project_id")
    return await call_next(request)


# ---------------------------------------------------------------------------
# Rate limiting (slowapi). Added after api_key_gate so it runs FIRST:
# abuse is throttled before authentication is even checked.
# ---------------------------------------------------------------------------
def _rate_limit_key(request: Request) -> str:
    """Rate-limit identity: API key when present, client IP otherwise.

    Only a key prefix is used — the full secret never enters logs or storage.
    """
    presented = request.headers.get("x-api-key", "")
    if presented:
        return f"apikey:{presented[:8]}"
    return f"ip:{get_remote_address(request)}"


limiter = Limiter(key_func=_rate_limit_key, default_limits=["600/minute"])
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    # slowapi's default handler omits Retry-After; clients need it to back off.
    # All windows here are per-minute, so 60s is the honest conservative value.
    return JSONResponse(
        {"detail": f"Rate limit exceeded: {exc.detail}"},
        status_code=429,
        headers={"Retry-After": "60"},
    )


app.add_middleware(SlowAPIMiddleware)


def _safe_extract(z: zipfile.ZipFile, dest: str):
    """Extract a zip archive with Zip Slip + decompression-bomb guards."""
    dest_real = os.path.realpath(dest)
    members = z.infolist()
    if len(members) > MAX_ZIP_MEMBERS:
        raise HTTPException(400, f"ZIP has too many entries ({len(members)})")
    total = 0
    for member in members:
        # Symlinks can escape the sandbox on extraction: refuse them.
        if (member.external_attr >> 16) & 0o170000 == 0o120000:
            raise HTTPException(400, f"Symlinks not allowed in ZIP: {member.filename}")
        if member.file_size > MAX_ZIP_MEMBER_BYTES:
            raise HTTPException(400, f"ZIP member too large: {member.filename}")
        if member.file_size > 0 and member.compress_size > 0:
            if member.file_size / member.compress_size > MAX_ZIP_COMPRESSION_RATIO:
                raise HTTPException(400, f"Suspicious compression ratio: {member.filename}")
        total += member.file_size
        if total > MAX_ZIP_UNCOMPRESSED_BYTES:
            raise HTTPException(400, "ZIP uncompressed size exceeds limit")
        target = os.path.realpath(os.path.join(dest, member.filename))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            raise HTTPException(400, f"Unsafe path in zip archive: {member.filename}")
    z.extractall(dest)


def _resolve_scan_target(target_path: str) -> str:
    """Resolve target_path inside the scan sandbox (LFI fix).

    realpath resolves '..' and symlinks; anything escaping SCAN_ROOT
    is rejected with 403. Without this, target_path allowed reading
    arbitrary server-local paths (e.g. /etc/passwd).
    """
    real = os.path.realpath(target_path)
    if real != SCAN_ROOT and not real.startswith(SCAN_ROOT + os.sep):
        raise HTTPException(403, "target_path must be inside the scan sandbox")
    if not os.path.isdir(real):
        raise HTTPException(400, f"Not a directory: {target_path}")
    return real


# Orphaned-scan recovery. A scan left in 'running'/'queued' across an API
# restart means its worker died (crash, OOM-kill, deploy) and will never
# report back — without recovery the client polls forever on a scan that
# can never complete. On every API startup such scans are failed honestly
# instead.
#
# Grace periods (not timeouts — the worker's own soft time limit already
# bounds a healthy scan):
# - 'running': the worker's full time budget + margin. A live worker can
#   never exceed SCAN_SOFT_LIMIT_S in 'running' (the soft limit fails the
#   scan from inside the task), so anything older had its worker die.
# - 'queued': 24h. A healthy durable queue delivers in seconds; after a
#   day nobody is coming for the scan.
ORPHAN_RUNNING_GRACE_S = SCAN_SOFT_LIMIT_S + 900
ORPHAN_QUEUED_GRACE_S = 86400


def _recover_orphaned_scans() -> int:
    """Fail scans whose worker died mid-flight. Returns the count recovered.

    Audit-logged per scan (actor 'system', action 'scan.failed') and
    fail-closed like the rest of main.py: a recovery that silently drops
    its audit records would be worse than a loud boot failure.
    Quota stays consumed — consistent with genuinely-failed scans: the
    attempt, not the outcome, is what the quota meters.
    """
    cutoff_running = (datetime.now(timezone.utc)
                      - timedelta(seconds=ORPHAN_RUNNING_GRACE_S)).isoformat()
    cutoff_queued = (datetime.now(timezone.utc)
                     - timedelta(seconds=ORPHAN_QUEUED_GRACE_S)).isoformat()
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, org_id, status FROM scans WHERE"
            " (status='running' AND COALESCE(started_at, created_at) < ?)"
            " OR (status='queued' AND created_at < ?)",
            (cutoff_running, cutoff_queued),
        ).fetchall()
        for r in rows:
            error = (
                f"worker lost: scan was '{r['status']}' with no completion "
                f"signal (recovered on API startup after grace period); "
                f"no findings were stored"
            )
            db.execute(
                "UPDATE scans SET status='failed', finished_at=?, error=?"
                " WHERE id=?",
                (now(), error, r["id"]),
            )
            # Same connection/transaction: a second connection here would
            # hit "database is locked" while the UPDATE holds the write
            # lock, and splitting them would break atomicity.
            log_event(r["org_id"], "system", "scan.failed", "scan", r["id"],
                      {"reason": "orphan_recovery",
                       "previous_status": r["status"]}, "", db=db)
        db.commit()
        if rows:
            log.warning("orphan recovery: failed %d worker-lost scan(s)",
                        len(rows))
        return len(rows)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@app.on_event("startup")
def startup():
    init_db()
    seed_plans()
    ensure_owner_org()
    ensure_subscription(OWNER_ORG_ID)
    _recover_orphaned_scans()


def _new_scan(org_id: str, target_name: str, target_dir: str,
              cleanup_dir, background_tasks: BackgroundTasks,
              webhook_url: str | None = None,
              webhook_secret: str | None = None,
              baseline_scan_id: str | None = None,
              project_id: str | None = None,
              scan_id: str | None = None,
              vcs_repo_id: str | None = None,
              commit_sha: str | None = None):
    """Create a scan owned by org_id. Consumes one unit of monthly quota.

    Raises HTTPException(402) when the org's plan quota is exhausted,
    HTTPException(503) when the durable queue is configured but unreachable.
    """
    if not consume_scan(org_id):
        allowed, used, quota = quota_status(org_id)
        raise HTTPException(
            402,
            f"Monthly scan quota exceeded ({used}/{quota} used). "
            "Upgrade your plan to continue scanning.",
        )
    scan_id = scan_id or uuid.uuid4().hex[:12]
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " webhook_url, webhook_secret, target_dir, project_id,"
        " vcs_repo_id, commit_sha)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, org_id, target_name, "queued", now(),
         webhook_url, webhook_secret, target_dir, project_id,
         vcs_repo_id, commit_sha))
    db.commit()
    db.close()
    try:
        enqueue_scan(scan_id, target_dir, cleanup_dir, background_tasks,
                     baseline_scan_id)
    except Exception as e:  # noqa: BLE001 - e.g. broker unreachable
        db = get_db()
        db.execute("UPDATE scans SET status='failed', finished_at=?, error=?"
                   " WHERE id=?", (now(), f"queue unavailable: {e}", scan_id))
        db.commit()
        db.close()
        raise HTTPException(503, "Scan queue unavailable, try again shortly.")
    result = {"scan_id": scan_id, "status": "queued"}
    if webhook_secret:
        result["webhook_secret"] = webhook_secret
    return result


def _check_baseline(request: Request, baseline_scan_id: str) -> None:
    """Validate a baseline_scan_id for incremental scans (fail fast, no quota)."""
    from database import get_db
    org_id = request.state.org_id
    pid = getattr(request.state, "project_id", None)
    db = get_db()
    row = db.execute("SELECT org_id, project_id, status FROM scans WHERE id=?",
                     (baseline_scan_id,)).fetchone()
    db.close()
    if row is None:
        raise HTTPException(404, "baseline scan not found")
    if row["org_id"] != org_id:
        raise HTTPException(403, "baseline scan belongs to another organization")
    if pid and row["project_id"] != pid:
        raise HTTPException(403, "baseline scan belongs to another project")
    if row["status"] != "done":
        raise HTTPException(400,
                            f"baseline scan is not complete (status={row['status']})")


@app.post("/api/scans")
@limiter.limit("60/minute")
async def create_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    target_path: str | None = Form(None),
    file: UploadFile | None = File(None),
    webhook_url: str | None = Form(None),
    baseline_scan_id: str | None = Form(None),
    project_id: str | None = Form(None),
):
    """Start a scan from a server-local path or an uploaded zip.

    Quota is checked before any expensive work, and consumed only when a
    scan is actually created (validation failures cost nothing).

    Optional ``webhook_url`` (http/https): the worker POSTs a signed JSON
    payload (``X-BraimSec-Signature: sha256=...``) when the scan reaches a
    terminal state. The signing secret is returned once in the response.

    Optional ``baseline_scan_id``: run an incremental (diff-based) rescan
    against that scan's fingerprint baseline. Requires ``target_path`` —
    zip uploads are always full scans.

    Optional ``project_id``: file the scan under a project. A
    project-scoped key is always filed under its own project.
    """
    require_role(request, "member")  # scans consume quota: not for viewers
    org_id = request.state.org_id
    # Resolve the scan's project: scoped keys are pinned to their own
    # project; org-wide keys may name one (must belong to the org).
    key_pid = getattr(request.state, "project_id", None)
    if key_pid:
        if project_id and project_id != key_pid:
            raise HTTPException(
                403, "This key is scoped to its own project and cannot"
                     " file scans elsewhere")
        project_id = key_pid
    elif project_id:
        db = get_db()
        try:
            ok = db.execute("SELECT 1 FROM projects WHERE id=? AND org_id=?",
                            (project_id, org_id)).fetchone()
        finally:
            db.close()
        if not ok:
            raise HTTPException(400, "Unknown project_id for this org")
    allowed, used, quota = quota_status(org_id)
    if not allowed:
        raise HTTPException(
            402,
            f"Monthly scan quota exceeded ({used}/{quota} used). "
            "Upgrade your plan to continue scanning.",
        )
    webhook_secret = None
    if webhook_url:
        from ssrf_guard import validate_webhook_url
        try:
            validate_webhook_url(webhook_url)
        except ValueError as e:
            raise HTTPException(400, str(e))
        webhook_secret = secrets.token_hex(16)
    if file is not None:
        if baseline_scan_id:
            raise HTTPException(
                400, "baseline_scan_id requires target_path: zip uploads"
                " are always full scans")
        # Enforce the size cap while streaming (Content-Length headers can lie).
        chunks, size = [], 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_ZIP_BYTES:
                raise HTTPException(
                    413, f"ZIP exceeds {MAX_ZIP_BYTES // (1024 * 1024)} MB limit")
            chunks.append(chunk)
        workdir = tempfile.mkdtemp(prefix="braimsec-")
        # Sanitize the client-supplied filename: a value like "../../evil"
        # would otherwise escape workdir (path traversal on the upload itself).
        # basename() strips every directory component; "." / ".." / empty
        # fall back to a safe default.
        filename = os.path.basename((file.filename or "").strip()) or "upload.zip"
        if filename in (".", ".."):
            filename = "upload.zip"
        dest = os.path.join(workdir, filename)
        with open(dest, "wb") as f:
            f.write(b"".join(chunks))
        if zipfile.is_zipfile(dest):
            extract_dir = os.path.join(workdir, "src")
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(dest) as z:
                _safe_extract(z, extract_dir)
            target_dir = extract_dir
        else:
            raise HTTPException(400, "Uploaded file must be a zip archive")
        result = _new_scan(org_id, filename, target_dir, workdir,
                           background_tasks, webhook_url, webhook_secret,
                           project_id=project_id)
        _audit(request, "scan.created", "scan", result["scan_id"],
               {"target": filename, "via": "upload", "project_id": project_id})
        return result

    if target_path:
        target_dir = _resolve_scan_target(target_path)
        if baseline_scan_id:
            _check_baseline(request, baseline_scan_id)
        result = _new_scan(org_id, os.path.basename(target_dir.rstrip("/")) or target_dir,
                           target_dir, None, background_tasks,
                           webhook_url, webhook_secret, baseline_scan_id,
                           project_id=project_id)
        _audit(request, "scan.created", "scan", result["scan_id"],
               {"target": target_dir, "via": "target_path",
                "baseline": bool(baseline_scan_id), "project_id": project_id})
        return result

    raise HTTPException(400, "Provide target_path or upload a zip file")


@app.get("/api/scans")
def list_scans(request: Request):
    # Org-scoped: a customer only ever sees their own scans.
    db = get_db()
    pred, params = _scan_scope(request, "")
    rows = db.execute(
        f"SELECT * FROM scans WHERE {pred} ORDER BY created_at DESC",
        params).fetchall()
    db.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------


@app.get("/api/scans/{scan_id}")
def scan_status(request: Request, scan_id: str):
    db = get_db()
    pred, params = _scan_scope(request, "")
    row = db.execute(f"SELECT * FROM scans WHERE id=? AND {pred}",
                     (scan_id, *params)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Scan not found")
    scan = dict(row)
    summary = db.execute(
        "SELECT severity, COUNT(*) c FROM findings WHERE scan_id=? GROUP BY severity",
        (scan_id,)).fetchall()
    db.close()
    scan["severity_summary"] = {r["severity"]: r["c"] for r in summary}
    return scan


@app.get("/api/scans/{scan_id}/results")
def scan_results(request: Request, scan_id: str, severity: str | None = None,
                 triage_status: str | None = None,
                 assigned_to: str | None = None):
    db = get_db()
    pred, params = _scan_scope(request, "")
    exists = db.execute(f"SELECT 1 FROM scans WHERE id=? AND {pred}",
                        (scan_id, *params)).fetchone()
    if not exists:
        db.close()
        raise HTTPException(404, "Scan not found")
    q = ("SELECT f.id, f.tool, f.rule_id, f.severity, f.message, f.file,"
         " f.line, f.col, f.ai_verdict, f.ai_confidence, f.ai_explanation,"
         " f.ai_fix, (f.fix_generated_at IS NOT NULL) AS has_fix, "
         "COALESCE(t.status,'open') AS triage_status,"
         " t.assigned_to AS triage_assignee, t.note AS triage_note "
         "FROM findings f LEFT JOIN finding_triage t"
         " ON t.finding_id=f.id WHERE f.scan_id=?")
    params = [scan_id]
    if severity:
        q += " AND f.severity=?"
        params.append(severity)
    if triage_status:
        if triage_status not in TRIAGE_STATUSES:
            db.close()
            raise HTTPException(400, f"triage_status: one of {TRIAGE_STATUSES}")
        q += " AND COALESCE(t.status,'open')=?"
        params.append(triage_status)
    if assigned_to:
        q += " AND t.assigned_to=?"
        params.append(assigned_to)
    rows = db.execute(q, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


CSV_COLUMNS = ("id", "tool", "rule_id", "severity", "file", "line", "col",
               "message", "triage_status", "triage_assignee",
               "ai_verdict", "ai_confidence")


@app.get("/api/scans/{scan_id}/results.csv")
@limiter.limit("30/minute")
def scan_results_csv(request: Request, scan_id: str,
                     severity: str | None = None):
    """CSV export of a scan's findings (auditor-friendly).

    Same filters/visibility as GET /api/scans/{id}/results (org-scoped,
    RBAC, 404 for a missing or foreign scan). RFC 4180 quoting via the
    csv module — messages with commas/quotes/newlines stay intact.
    Downloads as ``braimsec-<scan_id>-results.csv``.
    """
    findings = scan_results(request, scan_id, severity=severity)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for f in findings:
        w.writerow([f.get(c, "") for c in CSV_COLUMNS])
    body = buf.getvalue().encode("utf-8")
    return Response(
        content=body, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="braimsec-{scan_id}-results.csv"'})


@app.get("/api/trends")
@limiter.limit("60/minute")
def scan_trends(request: Request, days: int = 90,
                project_id: str | None = None):
    """Vulnerability trends over time for the caller's completed scans.

    One point per completed scan, chronological. ``new``/``fixed`` are
    computed against the immediately previous completed scan in the same
    scope, using the stable finding identity (tool|rule_id|file|message —
    line/column insensitive, same as the alerting path). ``days=0`` means
    all time. Viewers may read; project-scoped keys see only their own
    project.
    """
    from scheduler import finding_fingerprint  # noqa: E402
    if days < 0:
        raise HTTPException(400, "days: >= 0 (0 = all time)")
    key_pid = getattr(request.state, "project_id", None)
    if key_pid and project_id and project_id != key_pid:
        raise HTTPException(
            403, "Project-scoped keys cannot query other projects")
    db = get_db()
    eff_project = key_pid or project_id
    if eff_project and not key_pid:
        prow = db.execute(
            "SELECT id FROM projects WHERE id=? AND org_id=?",
            (eff_project, request.state.org_id)).fetchone()
        if not prow:
            db.close()
            raise HTTPException(404, "Project not found")
    pred, params = _scan_scope(request, "s")
    q = (f"SELECT s.id, s.target_name, s.project_id, s.created_at FROM scans s"
         f" WHERE {pred} AND s.status='done'")
    if eff_project and not key_pid:
        q += " AND s.project_id=?"
        params.append(eff_project)
    q += " ORDER BY s.created_at ASC"
    rows = db.execute(q, params).fetchall()
    if days > 0:
        cutoff = (datetime.now(timezone.utc) -
                  timedelta(days=days)).isoformat()
        rows = [r for r in rows if (r["created_at"] or "") >= cutoff]
    points = []
    prev_fps: set[str] = set()
    for r in rows:
        fr = db.execute(
            "SELECT tool, rule_id, severity, message, file FROM findings"
            " WHERE scan_id=?", (r["id"],)).fetchall()
        by_sev: dict[str, int] = {}
        fps: set[str] = set()
        for f in fr:
            sev = f["severity"] or "note"
            by_sev[sev] = by_sev.get(sev, 0) + 1
            fps.add(finding_fingerprint(f["tool"], f["rule_id"],
                                        f["file"], f["message"]))
        total = len(fr)
        for canon in ("error", "warning", "note"):
            by_sev.setdefault(canon, 0)
        points.append({
            "scan_id": r["id"],
            "target_name": r["target_name"],
            "project_id": r["project_id"],
            "created_at": r["created_at"],
            "total": total,
            "by_severity": by_sev,
            "new": len(fps - prev_fps),
            "fixed": len(prev_fps - fps),
        })
        prev_fps = fps
    db.close()
    if len(points) >= 2:
        delta = points[-1]["total"] - points[-2]["total"]
        trend = ("improving" if delta < 0
                 else "worsening" if delta > 0 else "stable")
    else:
        delta = 0
        trend = "insufficient"
    return {
        "points": points,
        "summary": {
            "scans": len(points),
            "period_days": days,
            "project_id": eff_project,
            "latest_total": points[-1]["total"] if points else 0,
            "previous_total": points[-2]["total"] if len(points) > 1 else None,
            "delta": delta,
            "trend": trend,
        },
    }


@app.get("/api/scans/{scan_id}/diff")
@limiter.limit("60/minute")
def scan_diff(request: Request, scan_id: str, against: str):
    """Diff two completed scans: new / fixed / persisting findings.

    Findings are matched by the stable fingerprint (tool|rule_id|file|message
    — line/column insensitive), the same identity used by alerting, trends
    and SARIF. ``scan_id`` is the newer scan, ``against`` the baseline.

    Both scans must be visible to the caller (404 otherwise) and completed
    (400 otherwise). They must target the same project/target — a mismatch
    is a 400, never a silent apples-to-oranges comparison. Viewers may read.
    """
    from scheduler import finding_fingerprint  # noqa: E402
    db = get_db()
    pred, params = _scan_scope(request, "")

    def _load(sid):
        row = db.execute(
            "SELECT id, target_name, project_id, status, created_at,"
            " total_findings FROM scans WHERE id=? AND " + pred,
            (sid, *params)).fetchone()
        return dict(row) if row else None

    if against == scan_id:
        db.close()
        raise HTTPException(400, "Cannot diff a scan against itself")
    newer = _load(scan_id)
    older = _load(against)
    if not newer or not older:
        db.close()
        raise HTTPException(404, "Scan not found")
    for s in (newer, older):
        if s["status"] != "done":
            db.close()
            raise HTTPException(
                400, f"Scan {s['id']} is not completed "
                     f"(status={s['status']})")
    if (newer["project_id"] or older["project_id"]) and \
            newer["project_id"] != older["project_id"]:
        db.close()
        raise HTTPException(400, "Scans belong to different projects")
    if newer["target_name"] != older["target_name"]:
        db.close()
        raise HTTPException(
            400, "Scans target different codebases "
                 f"({newer['target_name']!r} vs {older['target_name']!r})")

    def _rows(sid):
        return db.execute(
            "SELECT id, tool, rule_id, severity, message, file, line, col"
            " FROM findings WHERE scan_id=?", (sid,)).fetchall()

    new_rows = _rows(scan_id)
    old_rows = _rows(against)
    db.close()

    def _fp(f):
        return finding_fingerprint(f["tool"], f["rule_id"], f["file"],
                                   f["message"])

    def _dedup(rows):
        seen = {}
        for f in rows:  # first occurrence wins — deterministic
            seen.setdefault(_fp(f), dict(f))
        return seen

    new_map = _dedup(new_rows)
    old_map = _dedup(old_rows)
    new_only = [new_map[k] for k in new_map if k not in old_map]
    fixed_only = [old_map[k] for k in old_map if k not in new_map]
    persisting = [new_map[k] for k in new_map if k in old_map]

    def _by_sev(rows):
        d: dict[str, int] = {}
        for f in rows:
            sev = f.get("severity") or "note"
            d[sev] = d.get(sev, 0) + 1
        return d

    old_total = len(old_rows)
    fix_rate = round(len(fixed_only) / old_total, 3) if old_total else 0.0
    return {
        "scan": {"id": scan_id, "target_name": newer["target_name"],
                 "created_at": newer["created_at"], "total": len(new_rows)},
        "against": {"id": against, "target_name": older["target_name"],
                    "created_at": older["created_at"], "total": old_total},
        "summary": {
            "new": len(new_only),
            "fixed": len(fixed_only),
            "persisting": len(persisting),
            "fix_rate": fix_rate,
            "new_by_severity": _by_sev(new_only),
            "fixed_by_severity": _by_sev(fixed_only),
        },
        "new": new_only,
        "fixed": fixed_only,
        "persisting": persisting,
    }


@app.post("/api/scans/{scan_id}/ai-review")
@limiter.limit("30/minute")  # LLM calls are expensive — stricter budget
def start_ai_review(request: Request, scan_id: str, background_tasks: BackgroundTasks):
    require_role(request, "member")  # LLM calls cost money: not for viewers
    org_id = request.state.org_id
    db = get_db()
    pred, params = _scan_scope(request, "")
    scan = db.execute(f"SELECT target_dir FROM scans WHERE id=? AND {pred}",
                      (scan_id, *params)).fetchone()
    if not scan:
        db.close()
        raise HTTPException(404, "Scan not found")
    # AI reviews are the real variable cost: gate on the monthly AI quota.
    # Reserve one unit per finding still awaiting review...
    pending = db.execute(
        "SELECT COUNT(*) c FROM findings WHERE scan_id=? AND ai_verdict IS NULL",
        (scan_id,)).fetchone()["c"]
    db.close()
    # ...plus the worst case for high-risk sink auditing: one unit per
    # candidate sink (capped per scan). Discovery is AST-only, no LLM cost.
    sink_budget = 0
    sink_status = "disabled" if not sink_audit_enabled() else "skipped_no_sources"
    target_dir = scan["target_dir"]
    if sink_audit_enabled() and target_dir and os.path.isdir(target_dir):
        try:
            sink_budget = len(audit_candidates(discover_sinks(target_dir)))
            sink_status = "queued"
        except Exception:  # noqa: BLE001 - fail-soft: findings review proceeds
            sink_budget = 0
    allowed, used, quota = quota_check(org_id, "ai_review",
                                       max(pending, 1) + sink_budget)
    if not allowed:
        raise HTTPException(
            402,
            f"Monthly AI-review quota exceeded ({used}/{quota} used). "
            "Upgrade your plan to continue.",
        )
    try:
        enqueue_ai_review(scan_id, background_tasks)
    except Exception:  # noqa: BLE001 - e.g. broker unreachable
        raise HTTPException(503, "Review queue unavailable, try again shortly.")
    _audit(request, "ai_review.requested", "scan", scan_id,
           {"pending_findings": pending, "sink_budget": sink_budget})
    return {"scan_id": scan_id, "ai_review": "queued",
            "sink_audit": {"status": sink_status, "budget": sink_budget}}


@app.get("/api/audit-log")
def get_audit_log(request: Request, limit: int = 50, offset: int = 0,
                  action: str | None = None):
    """Enterprise audit trail: newest-first records for the caller's org.

    Org-scoped — a customer only ever sees their own trail. Optional
    ``action`` filter (e.g. ``scan.created``). Project-scoped keys are
    rejected: the trail covers the whole org.
    """
    require_org_scope(request)
    return read_events(request.state.org_id, limit=limit, offset=offset,
                       action=action)


@app.get("/api/audit-log/export.csv")
@limiter.limit("10/minute")
def export_audit_log_csv(request: Request, action: str | None = None):
    """CSV export of the org's audit trail (compliance handoff).

    Newest-first, up to 5,000 rows per export (use archives for deeper
    history). Same visibility as GET /api/audit-log: org-scoped, viewers
    may read; project-scoped keys are rejected. ``detail`` is embedded as
    a JSON string in its column (RFC 4180 quoting). Downloads as
    ``braimsec-audit-<org_id>.csv``.
    """
    require_org_scope(request)
    events = read_events(request.state.org_id, limit=5000, action=action)
    cols = ("id", "created_at", "actor", "action", "detail")
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(cols)
    for e in events:
        w.writerow([e.get("id", ""), e.get("created_at", ""),
                    e.get("actor", ""), e.get("action", ""),
                    json.dumps(e.get("detail") or {},
                               ensure_ascii=False, sort_keys=True)])
    body = buf.getvalue().encode("utf-8")
    return Response(
        content=body, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="braimsec-audit-'
                 f'{request.state.org_id}.csv"'})



@app.post("/api/audit-log/archive")
@limiter.limit("10/minute")
async def archive_audit_log(request: Request):
    """Archive audit events older than N days (owner only).

    Body: {"older_than_days": 90} (default from BRAIMSEC_AUDIT_RETENTION_DAYS,
    default 90; minimum 1). Old rows move to a gzipped, sha256-manifested
    archive file and leave the hot table; the run itself is logged as
    ``audit_log.archived``. Owner-only: archiving deletes audit history,
    so it must never be a routine admin action. Project-scoped keys are
    rejected — the trail covers the whole org.
    """
    require_org_scope(request)
    require_role(request, "owner")
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    raw_days = body.get("older_than_days")
    if raw_days is None:
        days = None
    else:
        try:
            days = int(raw_days)
        except (TypeError, ValueError):
            raise HTTPException(400, "older_than_days must be an integer")
    try:
        return archive_events(request.state.org_id, request.state.actor, days)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(409, str(e))


@app.get("/api/audit-log/archives")
@limiter.limit("60/minute")
def list_audit_archives(request: Request):
    """List the org's audit archive manifests (admin and above)."""
    require_org_scope(request)
    require_role(request, "admin")
    return list_archives(request.state.org_id)


@app.get("/api/audit-log/archives/{archive_id}/verify")
@limiter.limit("60/minute")
def verify_audit_archive(request: Request, archive_id: str):
    """Re-hash an archive file against its manifest (admin and above)."""
    require_org_scope(request)
    require_role(request, "admin")
    try:
        return verify_archive(request.state.org_id, archive_id)
    except KeyError:
        raise HTTPException(404, "Archive not found")


@app.post("/api/keys")
@limiter.limit("30/minute")
async def create_api_key(request: Request):
    """Provision a new API key for the caller's org (admin and above).

    Body: {"name": "...", "role": "viewer|member|admin|owner",
           "project_id": "..." (optional)}.
    Only an 'owner' key may grant 'admin' or 'owner' — an admin can only
    mint viewer/member keys. A project-scoped key may only mint keys
    inside its own project (no scope escape). Returns the raw key ONCE;
    it is never stored and cannot be retrieved again.
    """
    require_role(request, "admin")
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    name = (body.get("name") or "").strip()[:80]
    role = (body.get("role") or "member").strip()
    if role not in ROLES:
        raise HTTPException(400, f"Unknown role {role!r} (expected one of {ROLES})")
    if role_rank(role) >= role_rank("admin") and request.state.role != "owner":
        raise HTTPException(403, "Only an 'owner' key can grant 'admin'/'owner' roles")
    key_pid = getattr(request.state, "project_id", None)
    project_id = body.get("project_id")
    if key_pid:
        # Scoped key: pinned to its own project, no org-wide minting.
        # Explicit rejection (not silent re-scoping): the caller asked
        # for something this key must never create.
        if project_id != key_pid:
            raise HTTPException(
                403, "This key is scoped to its own project: pass its "
                     "project_id explicitly, org-wide minting is forbidden")
        project_id = key_pid
    try:
        raw = provision_key(request.state.org_id, name,
                            actor=request.state.actor, role=role,
                            project_id=project_id)
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))
    return {"key": raw, "key_prefix": raw[:8], "name": name, "role": role,
            "project_id": project_id,
            "warning": "Store this key now — it will never be shown again."}


@app.get("/api/keys")
@limiter.limit("60/minute")
def list_api_keys(request: Request):
    """List the org's API keys (admin and above). Hashes are never exposed.

    A project-scoped key sees only its own project's keys.
    """
    require_role(request, "admin")
    key_pid = getattr(request.state, "project_id", None)
    db = get_db()
    try:
        if key_pid:
            rows = db.execute(
                """SELECT id, key_prefix, name, role, project_id, created_at,
                          last_used_at, revoked FROM api_keys
                   WHERE org_id=? AND project_id=? ORDER BY created_at""",
                (request.state.org_id, key_pid)).fetchall()
        else:
            rows = db.execute(
                """SELECT id, key_prefix, name, role, project_id, created_at,
                          last_used_at, revoked FROM api_keys
                   WHERE org_id=? ORDER BY created_at""",
                (request.state.org_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


@app.delete("/api/keys/{key_id}")
@limiter.limit("30/minute")
def delete_api_key(request: Request, key_id: str):
    """Revoke an API key (admin and above). Cannot revoke the key in use.

    A project-scoped key can only revoke keys inside its own project.
    """
    require_role(request, "admin")
    if key_id == getattr(request.state, "key_id", None):
        raise HTTPException(400, "Cannot revoke the key you are calling with")
    key_pid = getattr(request.state, "project_id", None)
    db = get_db()
    try:
        if key_pid:
            row = db.execute(
                "SELECT id FROM api_keys WHERE id=? AND org_id=? AND project_id=?",
                (key_id, request.state.org_id, key_pid)).fetchone()
        else:
            row = db.execute("SELECT id FROM api_keys WHERE id=? AND org_id=?",
                             (key_id, request.state.org_id)).fetchone()
    finally:
        db.close()
    if not row:
        raise HTTPException(404, "Key not found")
    revoke_key(key_id, actor=request.state.actor)
    return {"key_id": key_id, "revoked": True}


@app.post("/api/keys/{key_id}/rotate")
@limiter.limit("30/minute")
def rotate_api_key(request: Request, key_id: str):
    """Rotate an API key: atomically issue a replacement, revoke the old.

    A key may always rotate itself (self-service — the replacement
    inherits org, name, role and project, so no privilege changes hands).
    Rotating another key requires admin or above; project-scoped keys
    stay inside their own project. The raw replacement is returned ONCE
    and never stored. The old key dies in the same transaction, so there
    is no window with zero or two valid keys. The env-configured master
    key is not a database row and cannot be rotated here.
    """
    key_pid = getattr(request.state, "project_id", None)
    is_self = key_id == getattr(request.state, "key_id", None)
    if not is_self:
        require_role(request, "admin")
    db = get_db()
    try:
        if key_pid:
            row = db.execute(
                "SELECT id, revoked FROM api_keys"
                " WHERE id=? AND org_id=? AND project_id=?",
                (key_id, request.state.org_id, key_pid)).fetchone()
        else:
            row = db.execute(
                "SELECT id, revoked FROM api_keys WHERE id=? AND org_id=?",
                (key_id, request.state.org_id)).fetchone()
    finally:
        db.close()
    if not row:
        raise HTTPException(404, "Key not found")
    if row["revoked"]:
        raise HTTPException(400, "Key is already revoked")
    try:
        raw, new_id = rotate_key(key_id, actor=request.state.actor)
    except KeyError:
        raise HTTPException(404, "Key not found")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"key": raw, "key_id": new_id, "key_prefix": raw[:8],
            "rotated_from": key_id,
            "warning": "Store this key now — it will never be shown again."}


@app.post("/api/projects")
@limiter.limit("30/minute")
async def create_project_endpoint(request: Request):
    """Create a project inside the caller's org (admin and above).

    A project-scoped key cannot create projects — projects are an
    org-level construct.
    """
    require_role(request, "admin")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    try:
        pid = create_project(request.state.org_id, body.get("name", ""),
                             actor=request.state.actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"project_id": pid, "name": (body.get("name") or "").strip()[:80]}


@app.get("/api/projects")
@limiter.limit("60/minute")
def list_projects_endpoint(request: Request):
    """List the caller's projects. A project-scoped key sees only its own."""
    pid = getattr(request.state, "project_id", None)
    projects = list_projects(request.state.org_id)
    if pid:
        projects = [p for p in projects if p["id"] == pid]
    return projects


@app.delete("/api/projects/{project_id}")
@limiter.limit("30/minute")
def delete_project_endpoint(request: Request, project_id: str):
    """Delete an empty project (admin and above, org scope).

    Refuses while scans or active keys still reference the project —
    nothing is orphaned implicitly.
    """
    require_role(request, "admin")
    require_org_scope(request)
    try:
        delete_project(request.state.org_id, project_id,
                       actor=request.state.actor)
    except KeyError:
        raise HTTPException(404, "Project not found")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"project_id": project_id, "deleted": True}


# ---------------------------------------------------------------------------
# Scheduled scans + new-findings alerts (webhooks)
# ---------------------------------------------------------------------------

def _validate_schedule_body(body: dict, partial: bool = False) -> dict:
    """Validate schedule fields; returns cleaned values. Raises 400."""
    from scheduler import (VALID_FREQUENCIES, VALID_SEVERITIES,  # noqa: E402
                           compute_next_run)
    from ssrf_guard import validate_webhook_url  # noqa: E402

    body = body or {}
    out: dict = {}

    def need(key, cond, msg):
        if key in body:
            if not cond(body[key]):
                raise HTTPException(400, f"{key}: {msg}")
            return body[key]
        if not partial:
            raise HTTPException(400, f"{key}: required")
        return None

    name = need("name", lambda v: isinstance(v, str) and 1 <= len(v.strip()) <= 80,
                "1-80 characters")
    if name is not None:
        out["name"] = name.strip()
    tp = need("target_path", lambda v: isinstance(v, str) and v.strip(),
              "non-empty string")
    if tp is not None:
        out["target_path"] = tp.strip()
    freq = need("frequency", lambda v: v in VALID_FREQUENCIES,
                f"one of {VALID_FREQUENCIES}")
    if freq is not None:
        out["frequency"] = freq
    rt = need("run_time", lambda v: isinstance(v, str),
              "HH:MM (00:00-23:59)")
    if rt is not None:
        out["run_time"] = rt.strip()
    if "weekday" in body:
        wd = body["weekday"]
        if wd is not None and not (isinstance(wd, int) and 0 <= wd <= 6):
            raise HTTPException(400, "weekday: 0=Monday..6=Sunday or null")
        out["weekday"] = wd
    elif not partial:
        out["weekday"] = None
    tz = need("timezone", lambda v: isinstance(v, str) and v.strip(),
              "IANA timezone name")
    if tz is not None:
        out["timezone"] = tz.strip()
    sev = need("alert_severity", lambda v: v in VALID_SEVERITIES,
               f"one of {VALID_SEVERITIES}")
    if sev is not None:
        out["alert_severity"] = sev
    if "webhook_url" in body or not partial:
        url = (body.get("webhook_url") or "").strip()
        if url:
            try:
                validate_webhook_url(url)
            except ValueError as e:
                raise HTTPException(400, f"webhook_url: {e}")
        # "" = webhook alerts disabled for this schedule (email-only).
        out["webhook_url"] = url
    if "enabled" in body:
        out["enabled"] = 1 if body["enabled"] else 0
    # Spec coherence: weekly needs a weekday; run_time/timezone must parse.
    freq_v = out.get("frequency")
    if freq_v == "weekly" and out.get("weekday") is None and not partial:
        raise HTTPException(400, "weekday: required for weekly schedules")
    if not partial or any(k in out for k in ("frequency", "run_time",
                                            "weekday", "timezone")):
        probe = {
            "frequency": out.get("frequency", body.get("frequency", "daily")),
            "run_time": out.get("run_time", body.get("run_time", "02:00")),
            "weekday": out.get("weekday", body.get("weekday")),
            "timezone": out.get("timezone", body.get("timezone", "UTC")),
        }
        try:
            compute_next_run(probe["frequency"], probe["run_time"],
                             probe["weekday"], probe["timezone"])
        except ValueError as e:
            raise HTTPException(400, str(e))
    return out


def _schedule_row(row) -> dict:
    return dict(row)


@app.post("/api/schedules")
@limiter.limit("30/minute")
async def create_schedule(request: Request):
    """Create a scheduled scan (member+, org scope).

    ``target_path`` must resolve inside the scan sandbox (same guard as
    ``POST /api/scans``); ``webhook_url`` is optional — when empty the
    schedule alerts by email only (see ``/api/alert-emails``).
    """
    from scheduler import compute_next_run  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    spec = _validate_schedule_body(body)
    # Fail fast on a bad target: reuse the scan sandbox guard.
    _resolve_scan_target(spec["target_path"])
    sid = uuid.uuid4().hex[:12]
    nxt = compute_next_run(spec["frequency"], spec["run_time"],
                           spec.get("weekday"), spec["timezone"])
    db = get_db()
    db.execute(
        "INSERT INTO schedules (id, org_id, name, target_path, frequency,"
        " run_time, weekday, timezone, alert_severity, webhook_url, enabled,"
        " next_run_at, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, request.state.org_id, spec["name"], spec["target_path"],
         spec["frequency"], spec["run_time"], spec.get("weekday"),
         spec["timezone"], spec["alert_severity"], spec["webhook_url"],
         spec.get("enabled", 1), nxt, now()))
    db.commit()
    db.close()
    _audit(request, "schedule.created", "schedule", sid,
           {"name": spec["name"], "frequency": spec["frequency"]})
    return {"schedule_id": sid, "next_run_at": nxt}


@app.get("/api/schedules")
@limiter.limit("60/minute")
def list_schedules(request: Request):
    """List the org's schedules (viewer+, org scope)."""
    require_org_scope(request)
    db = get_db()
    rows = db.execute(
        "SELECT * FROM schedules WHERE org_id=? ORDER BY created_at DESC",
        (request.state.org_id,)).fetchall()
    db.close()
    return [_schedule_row(r) for r in rows]


@app.get("/api/schedules/{schedule_id}")
@limiter.limit("60/minute")
def get_schedule(request: Request, schedule_id: str):
    """Fetch one schedule (viewer+, org scope)."""
    require_org_scope(request)
    db = get_db()
    row = db.execute("SELECT * FROM schedules WHERE id=? AND org_id=?",
                     (schedule_id, request.state.org_id)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Schedule not found")
    return _schedule_row(row)


@app.patch("/api/schedules/{schedule_id}")
@limiter.limit("30/minute")
async def update_schedule(request: Request, schedule_id: str):
    """Update a schedule (member+, org scope). Changing the cadence or
    timezone recomputes the next run from now."""
    from scheduler import compute_next_run  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    db = get_db()
    row = db.execute("SELECT * FROM schedules WHERE id=? AND org_id=?",
                     (schedule_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Schedule not found")
    sched = dict(row)
    spec = _validate_schedule_body(body, partial=True)
    if "target_path" in spec:
        _resolve_scan_target(spec["target_path"])
    merged = {**sched, **spec}
    if merged["frequency"] == "weekly" and merged.get("weekday") is None:
        db.close()
        raise HTTPException(400, "weekday: required for weekly schedules")
    sets, params = [], []
    for key in ("name", "target_path", "frequency", "run_time", "weekday",
                "timezone", "alert_severity", "webhook_url", "enabled"):
        if key in spec:
            sets.append(f"{key}=?")
            params.append(spec[key])
    if any(k in spec for k in ("frequency", "run_time", "weekday",
                               "timezone")):
        nxt = compute_next_run(merged["frequency"], merged["run_time"],
                               merged.get("weekday"), merged["timezone"])
        sets.append("next_run_at=?")
        params.append(nxt)
    if sets:
        params.extend([schedule_id, request.state.org_id])
        db.execute(f"UPDATE schedules SET {', '.join(sets)}"
                   " WHERE id=? AND org_id=?", params)
        db.commit()
    db.close()
    _audit(request, "schedule.updated", "schedule", schedule_id,
           {"fields": sorted(spec.keys())})
    return get_schedule(request, schedule_id)


@app.delete("/api/schedules/{schedule_id}")
@limiter.limit("30/minute")
def delete_schedule(request: Request, schedule_id: str):
    """Delete a schedule and its notification history (member+, org scope)."""
    require_role(request, "member")
    require_org_scope(request)
    db = get_db()
    row = db.execute("SELECT id FROM schedules WHERE id=? AND org_id=?",
                     (schedule_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Schedule not found")
    db.execute("DELETE FROM notifications WHERE schedule_id=?", (schedule_id,))
    db.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
    db.commit()
    db.close()
    _audit(request, "schedule.deleted", "schedule", schedule_id, {})
    return {"schedule_id": schedule_id, "deleted": True}


@app.post("/api/schedules/{schedule_id}/run")
@limiter.limit("10/minute")
def run_schedule_endpoint(request: Request, schedule_id: str):
    """Trigger one immediate run of an enabled schedule (member+).

    The regular cadence is untouched: ``next_run_at`` keeps its value.
    """
    from scheduler import run_schedule_now  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    db = get_db()
    row = db.execute("SELECT id FROM schedules WHERE id=? AND org_id=?",
                     (schedule_id, request.state.org_id)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Schedule not found")
    try:
        scan_id = run_schedule_now(schedule_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except KeyError:
        raise HTTPException(404, "Schedule not found")
    _audit(request, "schedule.run", "schedule", schedule_id,
           {"scan_id": scan_id})
    return {"schedule_id": schedule_id, "scan_id": scan_id, "status": "queued"}



# ---------------------------------------------------------------------------
# VCS integration: scan on push (GitHub / GitLab)
# ---------------------------------------------------------------------------

def _serialize_vcs_repo(row: dict) -> dict:
    """Repo row for API responses — never exposes secret material."""
    return {
        "id": row["id"],
        "provider": row["provider"],
        "repo_url": row["repo_url"],
        "full_name": row["full_name"],
        "branch": row["branch"],
        "project_id": row["project_id"],
        "webhook_url": row["webhook_url"],
        "alert_severity": row["alert_severity"],
        "enabled": bool(row["enabled"]),
        "last_scan_id": row["last_scan_id"],
        "prev_scan_id": row["prev_scan_id"],
        "last_scan_at": row["last_scan_at"],
        "last_error": row["last_error"],
        "created_at": row["created_at"],
    }


def _validate_vcs_body(body: dict) -> dict:
    """Validate repo registration/update fields. Returns a clean spec dict."""
    from ssrf_guard import validate_webhook_url  # noqa: E402
    from vcs import VCS_PROVIDERS, validate_branch, validate_repo_url  # noqa: E402
    provider = (body.get("provider") or "").strip().lower()
    if provider not in VCS_PROVIDERS:
        raise HTTPException(
            400, f"Unknown provider {provider!r} (expected github|gitlab)")
    try:
        repo_url = validate_repo_url(body.get("repo_url") or "")
    except ValueError as e:
        raise HTTPException(400, str(e))
    branch = (body.get("branch") or "main").strip()
    try:
        validate_branch(branch)
    except ValueError as e:
        raise HTTPException(400, str(e))
    severity = (body.get("alert_severity") or "warning").strip()
    if severity not in ("note", "warning", "error"):
        raise HTTPException(400, "alert_severity must be note|warning|error")
    webhook_url = (body.get("webhook_url") or "").strip()
    if webhook_url:
        try:
            webhook_url = validate_webhook_url(webhook_url)
        except ValueError as e:
            raise HTTPException(400, f"webhook_url: {e}")
    # "" = webhook alerts disabled for this repo (email-only).
    return {"provider": provider, "repo_url": repo_url, "branch": branch,
            "alert_severity": severity, "webhook_url": webhook_url}


def _resolve_vcs_project(request: Request, body: dict) -> str | None:
    """Project scoping for VCS repos (mirrors scan/key creation)."""
    key_pid = getattr(request.state, "project_id", None)
    project_id = body.get("project_id")
    if key_pid:
        if project_id and project_id != key_pid:
            raise HTTPException(
                403, "This key is scoped to its own project")
        return key_pid
    if project_id:
        db = get_db()
        row = db.execute("SELECT id FROM projects WHERE id=? AND org_id=?",
                         (project_id, request.state.org_id)).fetchone()
        db.close()
        if not row:
            raise HTTPException(400, "Unknown project_id for this org")
    return project_id


def _vcs_receiver_url(provider: str) -> str:
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    return f"{base}/api/webhooks/{provider}" if base else f"/api/webhooks/{provider}"


@app.post("/api/vcs/repos")
@limiter.limit("30/minute")
async def create_vcs_repo(request: Request):
    """Register a repo for scan-on-push (member+, org scope).

    Returns the repo plus the one-time ``webhook_secret`` and the
    ``receiver_url`` to paste into the provider's webhook settings.
    """
    from vcs import encrypt_secret, generate_webhook_secret, hash_secret  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    spec = _validate_vcs_body(body)
    project_id = _resolve_vcs_project(request, body)
    full_name = (body.get("full_name") or "").strip()[:200]
    if not full_name:
        # Derive from the URL path when the caller doesn't supply it
        # (keeps nested GitLab groups: a/b/c).
        full_name = "/".join(spec["repo_url"].split("/")[3:])
    rid = uuid.uuid4().hex[:12]
    secret = generate_webhook_secret()
    enc = encrypt_secret(secret) if spec["provider"] == "github" else None
    db = get_db()
    try:
        db.execute(
            "INSERT INTO vcs_repos (id, org_id, project_id, provider,"
            " repo_url, full_name, branch, webhook_secret_hash,"
            " webhook_secret_enc, webhook_url, alert_severity, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, request.state.org_id, project_id, spec["provider"],
             spec["repo_url"], full_name, spec["branch"],
             hash_secret(secret), enc, spec["webhook_url"],
             spec["alert_severity"], now()))
        db.commit()
        row = db.execute("SELECT * FROM vcs_repos WHERE id=?",
                         (rid,)).fetchone()
    except sqlite3.IntegrityError:
        db.close()
        raise HTTPException(409, "This repo is already registered for this org")
    db.close()
    _audit(request, "vcs.repo.created", "vcs_repo", rid,
           {"provider": spec["provider"], "repo_url": spec["repo_url"],
            "branch": spec["branch"], "project_id": project_id})
    out = _serialize_vcs_repo(dict(row))
    out["webhook_secret"] = secret
    out["receiver_url"] = _vcs_receiver_url(spec["provider"])
    out["warning"] = ("Store this secret now — it will never be shown again."
                      " Paste it as the webhook secret in your provider.")
    return out


@app.get("/api/vcs/repos")
@limiter.limit("60/minute")
def list_vcs_repos(request: Request):
    """List the org's registered repos (viewer+, org scope)."""
    require_org_scope(request)
    key_pid = getattr(request.state, "project_id", None)
    db = get_db()
    if key_pid:
        rows = db.execute(
            "SELECT * FROM vcs_repos WHERE org_id=? AND project_id=?"
            " ORDER BY created_at DESC",
            (request.state.org_id, key_pid)).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM vcs_repos WHERE org_id=? ORDER BY created_at DESC",
            (request.state.org_id,)).fetchall()
    db.close()
    return [_serialize_vcs_repo(dict(r)) for r in rows]


@app.get("/api/vcs/repos/{repo_id}")
@limiter.limit("60/minute")
def get_vcs_repo(request: Request, repo_id: str):
    """Repo detail incl. last scan summary (viewer+, org scope)."""
    require_org_scope(request)
    db = get_db()
    row = db.execute("SELECT * FROM vcs_repos WHERE id=? AND org_id=?",
                     (repo_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Repo not found")
    repo = dict(row)
    scan = None
    if repo["last_scan_id"]:
        s = db.execute(
            "SELECT id, status, total_findings, finished_at, commit_sha,"
            " target_name, error FROM scans WHERE id=?",
            (repo["last_scan_id"],)).fetchone()
        if s:
            scan = dict(s)
    db.close()
    out = _serialize_vcs_repo(repo)
    out["last_scan"] = scan
    return out


@app.patch("/api/vcs/repos/{repo_id}")
@limiter.limit("30/minute")
async def update_vcs_repo(request: Request, repo_id: str):
    """Update branch / webhook_url / alert_severity / enabled (member+)."""
    from ssrf_guard import validate_webhook_url  # noqa: E402
    from vcs import validate_branch  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    db = get_db()
    row = db.execute("SELECT * FROM vcs_repos WHERE id=? AND org_id=?",
                     (repo_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Repo not found")
    repo = dict(row)
    updates, params = [], []
    if "branch" in body:
        try:
            branch = validate_branch((body["branch"] or "").strip())
        except ValueError as e:
            db.close()
            raise HTTPException(400, str(e))
        updates.append("branch=?")
        params.append(branch)
    if "webhook_url" in body:
        url = (body["webhook_url"] or "").strip()
        if url:
            try:
                url = validate_webhook_url(url)
            except ValueError as e:
                db.close()
                raise HTTPException(400, f"webhook_url: {e}")
        # "" disables webhook alerts (email-only repo).
        updates.append("webhook_url=?")
        params.append(url)
    if "alert_severity" in body:
        sev = (body["alert_severity"] or "").strip()
        if sev not in ("note", "warning", "error"):
            db.close()
            raise HTTPException(400, "alert_severity must be note|warning|error")
        updates.append("alert_severity=?")
        params.append(sev)
    if "enabled" in body:
        updates.append("enabled=?")
        params.append(1 if body["enabled"] else 0)
    if not updates:
        db.close()
        raise HTTPException(400, "Nothing to update")
    params.append(repo_id)
    db.execute(f"UPDATE vcs_repos SET {', '.join(updates)} WHERE id=?", params)
    db.commit()
    row = db.execute("SELECT * FROM vcs_repos WHERE id=?", (repo_id,)).fetchone()
    db.close()
    _audit(request, "vcs.repo.updated", "vcs_repo", repo_id,
           {"updated": [u.split("=")[0] for u in updates]})
    return _serialize_vcs_repo(dict(row))


@app.delete("/api/vcs/repos/{repo_id}")
@limiter.limit("30/minute")
def delete_vcs_repo(request: Request, repo_id: str):
    """Delete a repo and its notification history (member+, org scope).

    Scans stay (org audit data); only the repo link is removed.
    """
    require_role(request, "member")
    require_org_scope(request)
    db = get_db()
    row = db.execute("SELECT id FROM vcs_repos WHERE id=? AND org_id=?",
                     (repo_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Repo not found")
    db.execute("DELETE FROM notifications WHERE vcs_repo_id=?", (repo_id,))
    db.execute("DELETE FROM vcs_repos WHERE id=?", (repo_id,))
    db.commit()
    db.close()
    _audit(request, "vcs.repo.deleted", "vcs_repo", repo_id, {})
    return {"repo_id": repo_id, "deleted": True}


@app.post("/api/vcs/repos/{repo_id}/rotate-secret")
@limiter.limit("30/minute")
def rotate_vcs_secret(request: Request, repo_id: str):
    """Issue a new webhook secret (member+). Shown once; update the provider."""
    from vcs import encrypt_secret, generate_webhook_secret, hash_secret  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    db = get_db()
    row = db.execute("SELECT * FROM vcs_repos WHERE id=? AND org_id=?",
                     (repo_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Repo not found")
    repo = dict(row)
    secret = generate_webhook_secret()
    enc = encrypt_secret(secret) if repo["provider"] == "github" else None
    db.execute("UPDATE vcs_repos SET webhook_secret_hash=?,"
               " webhook_secret_enc=? WHERE id=?",
               (hash_secret(secret), enc, repo_id))
    db.commit()
    db.close()
    _audit(request, "vcs.repo.secret_rotated", "vcs_repo", repo_id, {})
    return {"repo_id": repo_id,
            "webhook_secret": secret,
            "receiver_url": _vcs_receiver_url(repo["provider"]),
            "warning": "Store this secret now — it will never be shown again."}


def _handle_vcs_webhook(provider: str, raw: bytes, headers, payload: dict,
                        background_tasks: BackgroundTasks):
    """Shared receiver logic for GitHub and GitLab (public, rate-limited).

    Returns (status_code, body). Never raises for business outcomes.
    """
    from tasks import enqueue_vcs_ingest  # noqa: E402
    from vcs import (decrypt_secret, find_repos, parse_github_push,
                     parse_gitlab_push, scan_exists_for_commit,
                     verify_github_signature, verify_gitlab_token)  # noqa: E402

    def _verified_repo(candidates):
        """First repo whose secret verifies this request (multi-org safe)."""
        for cand in candidates:
            if provider == "github":
                enc = cand.get("webhook_secret_enc")
                if enc and verify_github_signature(
                        raw, headers.get("X-Hub-Signature-256"),
                        decrypt_secret(enc)):
                    return cand
            elif verify_gitlab_token(headers.get("X-Gitlab-Token"),
                                     cand["webhook_secret_hash"]):
                return cand
        return None

    if provider == "github":
        parsed = parse_github_push(payload, headers.get("X-GitHub-Event", ""))
    else:
        parsed = parse_gitlab_push(payload, headers.get("X-Gitlab-Event"))
    if parsed is None:
        return 200, {"ok": True, "ignored": "not a push event"}
    if parsed["type"] == "ignore":
        return 200, {"ok": True, "ignored": parsed["reason"]}

    # Locate candidate repos first (the signature needs a secret to verify).
    candidates = find_repos(provider, parsed.get("clone_url") or "")
    if not candidates:
        return 200, {"ok": True, "ignored": "unknown repository"}
    repo = _verified_repo(candidates)
    if repo is None:
        log.warning("vcs webhook: bad signature/token for %s",
                    parsed.get("clone_url"))
        return 400, {"ok": False, "error": "invalid signature"}
    if parsed["type"] == "ping":
        # GitHub ping: acknowledge only when it verifiably belongs to us.
        return 200, {"ok": True, "pong": True}
    if not repo["enabled"]:
        return 200, {"ok": True, "ignored": "repository disabled"}
    if parsed["branch"] != repo["branch"]:
        return 200, {"ok": True,
                     "ignored": f"branch '{parsed['branch']}' not watched"}
    if scan_exists_for_commit(repo["id"], parsed["sha"]):
        return 200, {"ok": True, "deduped": True}
    mode = enqueue_vcs_ingest(repo["id"], parsed["sha"], background_tasks)
    log.info("vcs webhook: push %s@%s queued via %s",
             repo["full_name"], parsed["sha"][:8], mode)
    return 202, {"ok": True, "queued": True, "commit": parsed["sha"][:12]}


@app.post("/api/webhooks/github")
@limiter.limit("60/minute")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Public GitHub push receiver (rate-limited, HMAC-verified)."""
    raw = await request.body()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 - malformed JSON
        return JSONResponse({"ok": False, "error": "invalid JSON"},
                            status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "invalid JSON"},
                            status_code=400)
    code, body = _handle_vcs_webhook("github", raw, request.headers, payload,
                                     background_tasks)
    return JSONResponse(body, status_code=code)


@app.post("/api/webhooks/gitlab")
@limiter.limit("60/minute")
async def gitlab_webhook(request: Request, background_tasks: BackgroundTasks):
    """Public GitLab push receiver (rate-limited, token-verified)."""
    raw = await request.body()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 - malformed JSON
        return JSONResponse({"ok": False, "error": "invalid JSON"},
                            status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "invalid JSON"},
                            status_code=400)
    code, body = _handle_vcs_webhook("gitlab", raw, request.headers, payload,
                                     background_tasks)
    return JSONResponse(body, status_code=code)



@app.get("/api/notifications")
@limiter.limit("60/minute")
def list_notifications(request: Request, schedule_id: str | None = None,
                       vcs_repo_id: str | None = None,
                       report_schedule_id: str | None = None,
                       limit: int = 50):
    """Alert delivery log (viewer+, org scope). Newest first."""
    require_org_scope(request)
    limit = max(1, min(limit, 200))
    db = get_db()
    if schedule_id:
        rows = db.execute(
            "SELECT * FROM notifications WHERE org_id=? AND schedule_id=?"
            " ORDER BY id DESC LIMIT ?",
            (request.state.org_id, schedule_id, limit)).fetchall()
    elif vcs_repo_id:
        rows = db.execute(
            "SELECT * FROM notifications WHERE org_id=? AND vcs_repo_id=?"
            " ORDER BY id DESC LIMIT ?",
            (request.state.org_id, vcs_repo_id, limit)).fetchall()
    elif report_schedule_id:
        rows = db.execute(
            "SELECT * FROM notifications WHERE org_id=?"
            " AND report_schedule_id=? ORDER BY id DESC LIMIT ?",
            (request.state.org_id, report_schedule_id, limit)).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM notifications WHERE org_id=?"
            " ORDER BY id DESC LIMIT ?",
            (request.state.org_id, limit)).fetchall()
    db.close()
    return [dict(r) for r in rows]


# Email alert recipients (per-org). The list itself is the switch: email
# alerts fire only when the org has at least one enabled address AND the
# operator configured SMTP (BRAIMSEC_SMTP_*). Delivery happens on the same
# trigger as webhook alerts (new findings >= threshold, failed scans).
# ---------------------------------------------------------------------------

@app.get("/api/alert-emails")
@limiter.limit("60/minute")
def list_alert_emails(request: Request):
    """List the org's email alert recipients (viewer+, org scope).

    Also reports whether the server has SMTP configured — without it,
    alerts are recorded as ``skipped`` and never sent.
    """
    from email_alerts import get_org_emails, smtp_configured  # noqa: E402
    require_org_scope(request)
    return {"smtp_configured": smtp_configured(),
            "emails": get_org_emails(request.state.org_id)}


@app.post("/api/alert-emails")
@limiter.limit("30/minute")
async def add_alert_email(request: Request):
    """Add one recipient address (member+, org scope)."""
    from email_alerts import validate_email  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    try:
        email = validate_email(body.get("email") or "")
    except ValueError as e:
        raise HTTPException(400, str(e))
    db = get_db()
    dup = db.execute("SELECT id FROM alert_emails WHERE org_id=? AND email=?",
                     (request.state.org_id, email)).fetchone()
    if dup:
        db.close()
        raise HTTPException(409, "Address already registered")
    cur = db.execute(
        "INSERT INTO alert_emails (org_id, email, enabled, created_at)"
        " VALUES (?,?,1,?)",
        (request.state.org_id, email, now()))
    row = db.execute("SELECT id, email, enabled, created_at FROM alert_emails"
                     " WHERE rowid=?", (cur.lastrowid,)).fetchone()
    db.commit()
    db.close()
    _audit(request, "alert_email.added", "alert_email", row["id"],
           {"email": email})
    return dict(row)


@app.patch("/api/alert-emails/{email_id}")
@limiter.limit("30/minute")
async def toggle_alert_email(request: Request, email_id: int):
    """Enable/disable one recipient (member+, org scope)."""
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    if "enabled" not in body:
        raise HTTPException(400, "enabled: required (true|false)")
    db = get_db()
    row = db.execute("SELECT id FROM alert_emails WHERE id=? AND org_id=?",
                     (email_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Address not found")
    enabled = 1 if body["enabled"] else 0
    db.execute("UPDATE alert_emails SET enabled=? WHERE id=?",
               (enabled, email_id))
    db.commit()
    db.close()
    _audit(request, "alert_email.toggled", "alert_email", email_id,
           {"enabled": bool(enabled)})
    return {"id": email_id, "enabled": bool(enabled)}


@app.delete("/api/alert-emails/{email_id}")
@limiter.limit("30/minute")
def delete_alert_email(request: Request, email_id: int):
    """Remove one recipient address (member+, org scope)."""
    require_role(request, "member")
    require_org_scope(request)
    db = get_db()
    row = db.execute(
        "SELECT email FROM alert_emails WHERE id=? AND org_id=?",
        (email_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Address not found")
    db.execute("DELETE FROM alert_emails WHERE id=?", (email_id,))
    db.commit()
    db.close()
    _audit(request, "alert_email.removed", "alert_email", email_id,
           {"email": row["email"]})
    return {"id": email_id, "deleted": True}


# ---------------------------------------------------------------------------
# Telegram alert chats (per-org). The list itself is the switch: telegram
# alerts fire only when the org registered at least one chat id AND the
# operator configured a bot (BRAIMSEC_TELEGRAM_BOT_TOKEN). Delivery happens
# on the same trigger as webhook/email alerts (new findings >= threshold,
# failed scans). Setup steps are documented in api/telegram_alerts.py.
# ---------------------------------------------------------------------------

@app.get("/api/telegram-chats")
@limiter.limit("60/minute")
def list_telegram_chats(request: Request):
    """List the org's telegram alert chats (viewer+, org scope).

    Also reports whether the server has a bot token configured — without
    it, alerts are recorded as ``skipped`` and never sent.
    """
    from telegram_alerts import get_org_chats, telegram_configured  # noqa: E402
    require_org_scope(request)
    return {"telegram_configured": telegram_configured(),
            "chats": get_org_chats(request.state.org_id)}


@app.post("/api/telegram-chats")
@limiter.limit("30/minute")
async def add_telegram_chat(request: Request):
    """Register one chat id (member+, org scope).

    Body: {"chat_id": "<telegram chat id>", "label": "optional"}.
    """
    from telegram_alerts import validate_chat_id  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    try:
        chat_id = validate_chat_id(body.get("chat_id"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    label = str(body.get("label") or "")[:80]
    label = " ".join(label.split())
    db = get_db()
    dup = db.execute("SELECT id FROM telegram_chats WHERE org_id=? AND chat_id=?",
                     (request.state.org_id, chat_id)).fetchone()
    if dup:
        db.close()
        raise HTTPException(409, "Chat already registered")
    cur = db.execute(
        "INSERT INTO telegram_chats (org_id, chat_id, label, created_at)"
        " VALUES (?,?,?,?)",
        (request.state.org_id, chat_id, label, now()))
    row = db.execute("SELECT id, chat_id, label, created_at FROM telegram_chats"
                     " WHERE rowid=?", (cur.lastrowid,)).fetchone()
    db.commit()
    db.close()
    _audit(request, "telegram_chat.added", "telegram_chat", row["id"],
           {"chat_id": chat_id, "label": label})
    return dict(row)


@app.delete("/api/telegram-chats/{chat_row_id}")
@limiter.limit("30/minute")
def delete_telegram_chat(request: Request, chat_row_id: int):
    """Remove one registered chat (member+, org scope)."""
    require_role(request, "member")
    require_org_scope(request)
    db = get_db()
    row = db.execute(
        "SELECT chat_id FROM telegram_chats WHERE id=? AND org_id=?",
        (chat_row_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Chat not found")
    db.execute("DELETE FROM telegram_chats WHERE id=?", (chat_row_id,))
    db.commit()
    db.close()
    _audit(request, "telegram_chat.removed", "telegram_chat", chat_row_id,
           {"chat_id": row["chat_id"]})
    return {"id": chat_row_id, "deleted": True}


@app.get("/api/slack-webhooks")
@limiter.limit("60/minute")
def list_slack_webhooks(request: Request):
    """List the org's Slack alert webhooks (viewer+, org scope).

    Webhook URLs are never returned — only a masked tail. The secret lives
    encrypted in the DB.
    """
    from slack_alerts import get_org_webhooks  # noqa: E402
    require_org_scope(request)
    return {"webhooks": get_org_webhooks(request.state.org_id)}


@app.post("/api/slack-webhooks")
@limiter.limit("30/minute")
async def add_slack_webhook(request: Request):
    """Register one Slack incoming-webhook URL (member+, org scope).

    Body: {"webhook_url": "https://hooks.slack.com/services/...",
           "label": "optional, e.g. #security"}.
    The URL is Fernet-encrypted at rest and never returned by the API.
    """
    import hashlib  # noqa: E402
    from slack_alerts import (get_org_webhooks, validate_webhook_url,  # noqa: E402
                              _encrypt)
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    try:
        url = validate_webhook_url(body.get("webhook_url"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    label = str(body.get("label") or "")[:80]
    label = " ".join(label.split())
    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
    db = get_db()
    dup = db.execute(
        "SELECT id FROM slack_webhooks WHERE org_id=? AND url_hash=?",
        (request.state.org_id, url_hash)).fetchone()
    if dup:
        db.close()
        raise HTTPException(409, "Webhook already registered")
    cur = db.execute(
        "INSERT INTO slack_webhooks (org_id, webhook_url_enc, url_hash,"
        " label, created_at) VALUES (?,?,?,?,?)",
        (request.state.org_id, _encrypt(url), url_hash, label, now()))
    row_id = cur.lastrowid
    db.commit()
    db.close()
    _audit(request, "slack_webhook.added", "slack_webhook", row_id,
           {"label": label})
    webhooks = get_org_webhooks(request.state.org_id)
    return next(w for w in webhooks if w["id"] == row_id)


@app.delete("/api/slack-webhooks/{webhook_row_id}")
@limiter.limit("30/minute")
def delete_slack_webhook(request: Request, webhook_row_id: int):
    """Remove one registered Slack webhook (member+, org scope)."""
    require_role(request, "member")
    require_org_scope(request)
    db = get_db()
    row = db.execute(
        "SELECT label FROM slack_webhooks WHERE id=? AND org_id=?",
        (webhook_row_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Webhook not found")
    db.execute("DELETE FROM slack_webhooks WHERE id=?", (webhook_row_id,))
    db.commit()
    db.close()
    _audit(request, "slack_webhook.removed", "slack_webhook", webhook_row_id,
           {"label": row["label"]})
    return {"id": webhook_row_id, "deleted": True}


def _fix_payload(row):
    """Serialize the cached AI fix-suggestion columns of a finding row."""
    try:
        checks = json.loads(row.get("fix_checks") or "{}")
    except Exception:  # noqa: BLE001 - corrupted cache entry: treat as empty
        checks = {}
    return {
        "explanation": row.get("fix_explanation"),
        "diff": row.get("fix_diff"),
        "confidence": row.get("fix_confidence"),
        "caveats": row.get("fix_caveats"),
        "checks": checks,  # {applies, syntax_ok}: mechanical sanity only
        "generated_at": row.get("fix_generated_at"),
    }


@app.post("/api/findings/{finding_id}/fix-suggestion")
@limiter.limit("30/minute")  # LLM calls are expensive — stricter budget
def fix_suggestion(request: Request, finding_id: int):
    """AI-powered fix suggestion for one finding.

    On demand and cached: the first call spends **two** units of the monthly
    ``ai_review`` quota (proposal §4.3: patch generation is billed at ×2
    weight) and stores the suggestion on the finding; later calls return the
    cached suggestion for free.
    """
    require_role(request, "member")  # generation costs 2 AI units
    org_id = request.state.org_id
    db = get_db()
    pred, params = _scan_scope(request, "s")
    row = db.execute(
        f"""SELECT f.* FROM findings f JOIN scans s ON s.id = f.scan_id
           WHERE f.id = ? AND {pred}""",
        (finding_id, *params)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Finding not found")
    finding = dict(row)
    if finding.get("fix_generated_at"):
        db.close()
        return {"finding_id": finding_id, "cached": True,
                "suggestion": _fix_payload(finding)}
    # One fix = one LLM call = two ai_review units (×2 weight, proposal §4.3).
    allowed, used, quota = quota_check(org_id, "ai_review", 2)
    if not allowed:
        db.close()
        raise HTTPException(
            402,
            f"Monthly AI-review quota exceeded ({used}/{quota} used; "
            "fix generation costs 2 units). Upgrade your plan to continue.",
        )
    client = make_llm_client()
    if not client.configured:
        db.close()
        raise HTTPException(
            503,
            "مزود الذكاء الاصطناعي غير مُعد على هذا السيرفر — "
            "فعّل BRAIMSEC_GROQ_API_KEY (مفتاح مجاني من console.groq.com) "
            "وقت النشر لاستخدام اقتراحات الإصلاح.",
        )
    func_src, imports_src = extract_fix_context(
        finding.get("file") or "", finding.get("line") or 0)
    t0 = time.monotonic()
    try:
        gen = generate_fix(client, finding, func_src, imports_src)
    except Exception as e:  # noqa: BLE001 - LLM failure: clean error
        db.close()
        raise HTTPException(502, f"Fix generation failed: {e}")
    wall_ms = int((time.monotonic() - t0) * 1000)
    checks = validate_fix(finding.get("file") or "",
                          gen["fix_original"], gen["fix_patched"])
    # Backend hygiene on the stored prose (anchoring above used the raw
    # model output). The dashboard HTML-escapes on render; this is the
    # defense-in-depth half.
    gen["fix_explanation"] = sanitize_text(gen.get("fix_explanation", ""),
                                           2000)
    gen["fix_caveats"] = sanitize_text(gen.get("fix_caveats", ""), 2000)
    generated_at = now()
    db.execute(
        """UPDATE findings SET fix_diff=?, fix_explanation=?, fix_confidence=?,
           fix_caveats=?, fix_checks=?, fix_generated_at=? WHERE id=?""",
        (checks["diff"], gen["fix_explanation"], gen["fix_confidence"],
         gen["fix_caveats"], json.dumps(checks), generated_at, finding_id))
    db.commit()
    db.close()
    # ×2 billing weight for patch generation: two ledger rows.
    record_usage(org_id, "ai_review", finding["scan_id"], wall_time_ms=wall_ms)
    record_usage(org_id, "ai_review", finding["scan_id"])
    db2 = get_db()
    row2 = db2.execute(
        "SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    payload = _fix_payload(dict(row2))
    db2.close()
    _audit(request, "fix_suggestion.requested", "finding", finding_id,
           {"scan_id": finding["scan_id"]})
    return {"finding_id": finding_id, "cached": False, "suggestion": payload}


@app.post("/api/findings/{finding_id}/patch-verify")
@limiter.limit("30/minute")  # deterministic re-scan (~2 semgrep runs)
def patch_verify_endpoint(request: Request, finding_id: int):
    """Closed-loop verification of a stored fix suggestion (Proposal Part 1).

    Runs the stored patch through eligibility -> fuzzy apply -> semgrep
    re-scan and stores the verdict on the finding
    (``fix_checks["verification"]``). Deterministic: no LLM, no quota
    consumed. A ``verified`` patch is still framed as a suggestion
    requiring human review — never a guaranteed fix.
    """
    require_role(request, "member")
    org_id = request.state.org_id
    db = get_db()
    pred, params = _scan_scope(request, "s")
    row = db.execute(
        f"""SELECT f.*, s.target_dir FROM findings f
           JOIN scans s ON s.id = f.scan_id
           WHERE f.id = ? AND {pred}""",
        (finding_id, *params)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Finding not found")
    finding = dict(row)
    target_dir = finding.pop("target_dir", None)
    diff = finding.get("fix_diff")
    if not diff:
        db.close()
        raise HTTPException(
            400, "No fix suggestion stored for this finding — call "
                 "POST /api/findings/{id}/fix-suggestion first")
    if not target_dir or not os.path.isdir(target_dir):
        db.close()
        raise HTTPException(
            409, "Scan sources are no longer available "
                 "(deleted after scan — zero-retention); verification "
                 "needs the original file")
    verdict = verify_patch(
        {"id": finding_id, "tool": finding.get("tool"),
         "rule_id": finding.get("rule_id"), "file": finding.get("file"),
         "line": finding.get("line")},
        target_dir, diff)
    try:
        checks = json.loads(finding.get("fix_checks") or "{}")
    except Exception:  # noqa: BLE001 - corrupted cache entry: treat as empty
        checks = {}
    checks["verification"] = verdict
    db.execute("UPDATE findings SET fix_checks=? WHERE id=?",
               (json.dumps(checks), finding_id))
    db.commit()
    db.close()
    _audit(request, "patch_verify.requested", "finding", finding_id,
           {"verdict": verdict.get("verified") if isinstance(verdict, dict) else None})
    return {"finding_id": finding_id, "verification": verdict}


@app.get("/api/findings/{finding_id}/taint-flow")
@limiter.limit("30/minute")  # on-demand semgrep/AST work per call
def taint_flow(request: Request, finding_id: int):
    """Linear taint-flow trace for one finding (Proposal Part 3, v1).

    Deterministic — no LLM, no quota consumed. Returns the proposal §2
    schema: ordered steps (source -> propagation -> sink) each labeled with
    ``origin`` (``semgrep-trace`` | ``ast-slice``; ``ai-inferred`` is
    reserved for the AI layer and never emitted here), plus the tri-state
    ``sanitization`` verdict (unsanitized / sanitized / uncertain).
    """
    org_id = request.state.org_id
    db = get_db()
    pred, params = _scan_scope(request, "s")
    row = db.execute(
        f"""SELECT f.*, s.target_dir FROM findings f
           JOIN scans s ON s.id = f.scan_id
           WHERE f.id = ? AND {pred}""",
        (finding_id, *params)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Finding not found")
    finding = dict(row)
    target_dir = finding.pop("target_dir", None)
    if not target_dir or not os.path.isdir(target_dir):
        # zero-retention: zip-scan sources are deleted after the scan
        return {"available": False, "finding_id": finding_id,
                "reason": ("Scan sources are no longer available "
                           "(deleted after scan — zero-retention).")}
    return extract_taint_path(finding, target_dir)


# ---------------------------------------------------------------------------
# Team finding triage: status workflow, assignment, change history.
# ---------------------------------------------------------------------------

TRIAGE_STATUSES = ("open", "in_progress", "false_positive", "fixed",
                   "accepted_risk")


def _triage_finding(db, request: Request, finding_id: int):
    """Fetch one finding visible to the caller (org/project scope).

    Returns the finding dict (with org_id) or None.
    """
    pred, params = _scan_scope(request, "s")
    row = db.execute(
        f"""SELECT f.*, s.org_id FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE f.id=? AND {pred}""",
        (finding_id, *params)).fetchone()
    return dict(row) if row else None


def _validate_assignee(db, org_id: str, assigned_to):
    """assigned_to must be a live API key of the caller's org (or empty)."""
    if assigned_to in (None, ""):
        return None
    row = db.execute(
        "SELECT id FROM api_keys WHERE id=? AND org_id=? AND revoked=0",
        (assigned_to, org_id)).fetchone()
    if not row:
        raise HTTPException(
            400, "assigned_to: unknown or revoked key in this org")
    return assigned_to


def _sync_suppression(db, org_id: str, finding: dict, old_status: str,
                      new_status: str, actor: str):
    """Keep finding_suppressions in step with the triage status.

    Marking false_positive suppresses the finding's fingerprint
    (tool|rule_id|file|message — same scheme as the scheduler) so it
    never re-alerts on later scheduled runs; leaving false_positive
    lifts the suppression again.
    """
    from scheduler import finding_fingerprint  # noqa: E402
    fp = finding_fingerprint(finding.get("tool") or "",
                             finding.get("rule_id") or "",
                             finding.get("file") or "",
                             finding.get("message") or "")
    now = datetime.now(timezone.utc).isoformat()
    if new_status == "false_positive" and old_status != "false_positive":
        db.execute(
            "INSERT OR IGNORE INTO finding_suppressions"
            " (org_id, fingerprint, reason, created_by, created_at)"
            " VALUES (?,?,?,?,?)",
            (org_id, fp, (finding.get("message") or "")[:200], actor, now))
    elif old_status == "false_positive" and new_status != "false_positive":
        db.execute(
            "DELETE FROM finding_suppressions WHERE org_id=? AND fingerprint=?",
            (org_id, fp))


def _apply_triage(db, request: Request, finding_id: int, finding: dict,
                  status, assigned_to, note, actor: str, org_id: str,
                  validate_assignee: bool):
    """Upsert triage row + history + suppression sync. Returns the new state."""
    cur = db.execute("SELECT * FROM finding_triage WHERE finding_id=?",
                     (finding_id,)).fetchone()
    cur = dict(cur) if cur else None
    old_status = (cur or {}).get("status", "open")
    new_status = status if status is not None else old_status
    if validate_assignee:
        new_assignee = _validate_assignee(db, org_id, assigned_to)
    else:
        new_assignee = (cur or {}).get("assigned_to")
    new_note = note if note is not None else (cur or {}).get("note", "")
    now = datetime.now(timezone.utc).isoformat()
    if cur:
        db.execute(
            "UPDATE finding_triage SET status=?, assigned_to=?, note=?,"
            " updated_by=?, updated_at=? WHERE finding_id=?",
            (new_status, new_assignee, new_note, actor, now, finding_id))
    else:
        db.execute(
            "INSERT INTO finding_triage (finding_id, status, assigned_to,"
            " note, updated_by, updated_at) VALUES (?,?,?,?,?,?)",
            (finding_id, new_status, new_assignee, new_note, actor, now))
    db.execute(
        "INSERT INTO triage_history (finding_id, org_id, changed_by,"
        " changed_at, from_status, to_status, note)"
        " VALUES (?,?,?,?,?,?,?)",
        (finding_id, org_id, actor, now, old_status, new_status,
         new_note or ""))
    _sync_suppression(db, org_id, finding, old_status, new_status, actor)
    return {"finding_id": finding_id, "status": new_status,
            "assigned_to": new_assignee, "note": new_note,
            "updated_by": actor, "updated_at": now}


@app.get("/api/team")
@limiter.limit("60/minute")
def list_team(request: Request):
    """Org members available for finding assignment (member+).

    Returns key id, name, prefix and role — never hashes. A project-scoped
    key sees only its own project's keys.
    """
    require_role(request, "member")
    key_pid = getattr(request.state, "project_id", None)
    db = get_db()
    try:
        if key_pid:
            rows = db.execute(
                "SELECT id, name, key_prefix, role FROM api_keys"
                " WHERE org_id=? AND project_id=? AND revoked=0 ORDER BY name",
                (request.state.org_id, key_pid)).fetchall()
        else:
            rows = db.execute(
                "SELECT id, name, key_prefix, role FROM api_keys"
                " WHERE org_id=? AND revoked=0 ORDER BY name",
                (request.state.org_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


@app.get("/api/findings/{finding_id}/triage")
@limiter.limit("60/minute")
def get_triage(request: Request, finding_id: int):
    """Current triage state + change history of one finding (viewer+)."""
    db = get_db()
    finding = _triage_finding(db, request, finding_id)
    if not finding:
        db.close()
        raise HTTPException(404, "Finding not found")
    cur = db.execute("SELECT * FROM finding_triage WHERE finding_id=?",
                     (finding_id,)).fetchone()
    hist = db.execute(
        "SELECT changed_by, changed_at, from_status, to_status, note"
        " FROM triage_history WHERE finding_id=?"
        " ORDER BY changed_at DESC, id DESC",
        (finding_id,)).fetchall()
    db.close()
    return {
        "finding_id": finding_id,
        "triage": dict(cur) if cur else {"status": "open",
                                        "assigned_to": None, "note": ""},
        "history": [dict(h) for h in hist],
    }


@app.patch("/api/findings/{finding_id}/triage")
@limiter.limit("60/minute")
async def triage_finding(request: Request, finding_id: int):
    """Team triage of one finding (member+).

    Body: {"status": "open|in_progress|false_positive|fixed|accepted_risk",
           "assigned_to": "<api key id>" | null, "note": "..."}.
    Every change is recorded in triage_history; marking false_positive
    suppresses the fingerprint from future scheduled-scan alerts, and
    leaving false_positive lifts the suppression.
    """
    require_role(request, "member")
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    body = body or {}
    status = body.get("status")
    if status is not None and status not in TRIAGE_STATUSES:
        raise HTTPException(400, f"status: one of {TRIAGE_STATUSES}")
    if status is None and "assigned_to" not in body and "note" not in body:
        raise HTTPException(
            400, "Nothing to update: provide status, assigned_to or note")
    db = get_db()
    finding = _triage_finding(db, request, finding_id)
    if not finding:
        db.close()
        raise HTTPException(404, "Finding not found")
    org_id = request.state.org_id
    actor = getattr(request.state, "actor", "")
    out = _apply_triage(db, request, finding_id, finding, status,
                        body.get("assigned_to"),
                        body.get("note") if "note" in body else None,
                        actor, org_id,
                        validate_assignee="assigned_to" in body)
    db.commit()
    db.close()
    _audit(request, "finding.triaged", "finding", finding_id,
           {"from": out["status"], "assigned_to": out["assigned_to"]})
    return out


@app.post("/api/findings/triage-bulk")
@limiter.limit("30/minute")
async def triage_bulk(request: Request):
    """Triage many findings at once (member+).

    Body: {"finding_ids": [1, 2, 3], "status": "...",
           "assigned_to": "<key id>" | null, "note": "..."}.
    Findings not visible to the caller are skipped and reported.
    """
    require_role(request, "member")
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    body = body or {}
    ids = body.get("finding_ids") or []
    if not isinstance(ids, list) or not ids:
        raise HTTPException(400, "finding_ids: non-empty list required")
    if len(ids) > 200:
        raise HTTPException(400, "finding_ids: max 200 per call")
    status = body.get("status")
    if status is not None and status not in TRIAGE_STATUSES:
        raise HTTPException(400, f"status: one of {TRIAGE_STATUSES}")
    db = get_db()
    org_id = request.state.org_id
    actor = getattr(request.state, "actor", "")
    assignee = (_validate_assignee(db, org_id, body.get("assigned_to"))
                if "assigned_to" in body else None)
    note = body.get("note") if "note" in body else None
    change_assignee = "assigned_to" in body
    updated, skipped = [], []
    for raw in ids:
        try:
            fid = int(raw)
        except (TypeError, ValueError):
            skipped.append(raw)
            continue
        finding = _triage_finding(db, request, fid)
        if not finding:
            skipped.append(fid)
            continue
        _apply_triage(db, request, fid, finding, status, assignee, note,
                      actor, org_id, validate_assignee=change_assignee)
        updated.append(fid)
    db.commit()
    db.close()
    _audit(request, "finding.triaged_bulk", "finding", "",
           {"updated": len(updated), "skipped": len(skipped)})
    return {"updated": updated, "skipped": skipped}


@app.get("/api/scans/{scan_id}/sarif")
@limiter.limit("30/minute")
def scan_sarif(request: Request, scan_id: str):
    """SARIF 2.1.0 export of a scan's findings.

    Served as ``application/sarif+json`` with a Content-Disposition so it
    downloads as ``braimsec-<scan_id>.sarif``. Drop the file into GitHub
    code scanning via ``github/codeql-action/upload-sarif`` (see
    reports/SARIF.md) or any other SARIF 2.1.0 consumer.

    RBAC + per-org isolation are enforced by scan_results (404 for a
    missing scan or one belonging to another org). The document is a pure,
    deterministic function of the stored findings — no rescan, no LLM.
    """
    findings = scan_results(request, scan_id)
    doc = build_sarif(
        [{
            "tool": f["tool"], "rule_id": f["rule_id"],
            "severity": f["severity"], "message": f["message"],
            "file": f["file"], "line": f["line"] or 1, "col": f["col"] or 1,
        } for f in findings],
        scan_id=scan_id)
    try:
        validate_sarif(doc)
    except SarifError as e:
        raise HTTPException(500, f"sarif build refused: {e}")
    body = json.dumps(doc, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return Response(
        content=body, media_type="application/sarif+json",
        headers={"Content-Disposition":
                 f'attachment; filename="braimsec-{scan_id}.sarif"'})


@app.get("/api/scans/{scan_id}/badge.svg")
@limiter.limit("60/minute")
def scan_badge(request: Request, scan_id: str):
    """Public shields.io-style status badge (SVG).

    Embed in a README: ``<img src="https://<host>/api/scans/<id>/badge.svg">``.
    No authentication — the badge exposes only *aggregate* severity counts
    (never file names, messages, targets or org data); scan ids are
    unguessable (12 hex chars). Unknown scan -> 404, not a badge.
    Deterministic: same scan state always yields the same SVG bytes.
    """
    db = get_db()
    row = db.execute("SELECT id, status FROM scans WHERE id=?",
                     (scan_id,)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Scan not found")
    counts = {}
    if row["status"] == "done":
        for r in db.execute(
                "SELECT severity, COUNT(*) c FROM findings WHERE scan_id=? "
                "GROUP BY severity", (scan_id,)):
            counts[r["severity"]] = r["c"]
    db.close()
    svg = build_badge_svg(row["status"], counts)
    return Response(
        content=svg.encode("utf-8"), media_type="image/svg+xml",
        headers={"Cache-Control": "no-store",
                 "X-Content-Type-Options": "nosniff"})


@app.get("/api/scans/{scan_id}/report.pdf")
@limiter.limit("30/minute")
def scan_report_pdf(request: Request, scan_id: str):
    """CISO-grade PDF report (proposal Part 5).

    Pure function of stored scan data: no rescan, no LLM calls, no quota
    consumed. Deterministic per scan; ETag enables client caching.
    """
    import hashlib as _hashlib
    from datetime import datetime, timezone

    db = get_db()
    pred, params = _scan_scope(request, "")
    scan = db.execute(f"SELECT * FROM scans WHERE id=? AND {pred}",
                      (scan_id, *params)).fetchone()
    if not scan:
        db.close()
        raise HTTPException(404, "Scan not found")
    scan = dict(scan)
    if scan["status"] != "done":
        db.close()
        raise HTTPException(409, "Scan not completed yet")
    findings = [dict(r) for r in db.execute(
        "SELECT id, tool, rule_id, severity, message, file, line, col,"
        " ai_verdict, ai_confidence, ai_explanation,"
        " fix_diff, fix_explanation, fix_confidence, fix_caveats"
        " FROM findings WHERE scan_id=?", (scan_id,)).fetchall()]
    prev_row = db.execute(
        "SELECT id, finished_at, total_findings FROM scans"
        " WHERE org_id=? AND target_name=? AND status='done' AND id!=?"
        " ORDER BY finished_at DESC LIMIT 1",
        (request.state.org_id, scan["target_name"], scan_id)).fetchone()
    prev = None
    if prev_row:
        prev = dict(prev_row)
        pc = db.execute(
            "SELECT severity, COUNT(*) c FROM findings WHERE scan_id=?"
            " GROUP BY severity", (prev["id"],)).fetchall()
        prev = {"scan_id": prev["id"], "finished_at": prev["finished_at"],
                "counts": {r["severity"]: r["c"] for r in pc},
                "grade": None}
        # grade of the previous report, recomputed deterministically
        # (v1.1 semantics: engine-reported errors only, no AI gate)
        perr = db.execute(
            "SELECT COUNT(*) c FROM findings WHERE scan_id=? AND severity='error'",
            (prev["scan_id"],)).fetchone()["c"]
        prev["grade"] = ("A" if perr == 0 else "B" if perr <= 2
                         else "C" if perr <= 5 else "D" if perr <= 10
                         else "F")
    db.close()

    generated_at = datetime.now(timezone.utc).isoformat()
    try:
        report = build_report(scan, findings, prev=prev,
                              target_dir=scan.get("target_dir"),
                              generated_at=generated_at)
        pdf = render_pdf(report)
    except ReportError as e:
        raise HTTPException(500, f"report refused: {e}")
    # ETag over the report content (+ generator version), not the PDF bytes:
    # the PDF embeds a fresh generation timestamp, but the report itself is
    # deterministic per (scan, generator version) — that is the cache key
    # from proposal §4.4.
    import json as _json
    from builder import REPORT_VERSION as _RV
    stable = dict(report)
    stable["meta"] = {k: v for k, v in report["meta"].items()
                      if k != "generated_at"}
    etag = _hashlib.sha256(
        _json.dumps(stable, sort_keys=True, default=str).encode()
        + b"|" + _RV.encode()).hexdigest()
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304)
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"ETag": etag,
                 "Content-Disposition":
                 f'attachment; filename="braimsec-{scan_id}-report.pdf"'})


@app.post("/api/reports/executive")
@limiter.limit("30/minute")
async def executive_report_pdf(request: Request):
    """Manager-facing executive PDF (Arabic, deterministic).

    Plain-language posture, top-10 findings with practical
    recommendations, SOC 2 / ISO 27001 coverage, recent scans. Pure
    function of stored scan data: no rescan, no LLM calls, no quota
    consumed. Optional JSON body: {"project_id": ..., "days": 90}.
    Viewers may read.
    """
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - empty/malformed body -> defaults
        body = {}
    if not isinstance(body, dict):
        body = {}
    project_id = body.get("project_id")
    try:
        days = int(body.get("days", 90))
    except (TypeError, ValueError):
        raise HTTPException(400, "days: integer >= 0 (0 = all time)")
    if days < 0:
        raise HTTPException(400, "days: >= 0 (0 = all time)")

    key_pid = getattr(request.state, "project_id", None)
    if key_pid and project_id and project_id != key_pid:
        raise HTTPException(
            403, "Project-scoped keys cannot query other projects")
    eff_project = key_pid or project_id
    # Shared with the scheduled-report driver (api/scheduled_reports.py):
    # one scope-collection path for on-demand and scheduled reports.
    from scheduled_reports import collect_report_inputs  # noqa: E402
    db = get_db()
    try:
        inputs = collect_report_inputs(db, request.state.org_id,
                                       eff_project, days)
    except KeyError:
        db.close()
        raise HTTPException(404, "Project not found")
    except ReportError:
        db.close()
        raise HTTPException(404, "No completed scans in scope")
    db.close()

    generated_at = datetime.now(timezone.utc).isoformat()
    try:
        report = build_executive_report(
            inputs["org_name"], inputs["project_name"], inputs["scans"],
            inputs["latest_findings"],
            prev_counts=inputs["prev_counts"],
            compliance=inputs["compliance"],
            generated_at=generated_at)
        pdf = render_executive_pdf(report)
    except ReportError as e:
        raise HTTPException(500, f"report refused: {e}")
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition":
                 'attachment; filename="braimsec-executive-report.pdf"'})


# ---------------------------------------------------------------------------
# Scheduled executive reports (weekly/monthly emailed PDFs)
# ---------------------------------------------------------------------------

def _validate_report_schedule_body(body: dict,
                                   partial: bool = False) -> dict:
    """Validate report-schedule fields; returns cleaned values. Raises 400."""
    from scheduled_reports import (VALID_REPORT_FREQUENCIES,  # noqa: E402
                                   compute_next_report_run)
    body = body or {}
    out: dict = {}

    def need(key, cond, msg):
        if key in body:
            if not cond(body[key]):
                raise HTTPException(400, f"{key}: {msg}")
            return body[key]
        if not partial:
            raise HTTPException(400, f"{key}: required")
        return None

    name = need("name",
                lambda v: isinstance(v, str) and 1 <= len(v.strip()) <= 80,
                "1-80 characters")
    if name is not None:
        out["name"] = name.strip()
    freq = need("frequency", lambda v: v in VALID_REPORT_FREQUENCIES,
                f"one of {VALID_REPORT_FREQUENCIES}")
    if freq is not None:
        out["frequency"] = freq
    rt = need("run_time", lambda v: isinstance(v, str),
              "HH:MM (00:00-23:59)")
    if rt is not None:
        out["run_time"] = rt.strip()
    if "weekday" in body:
        wd = body["weekday"]
        if wd is not None and not (isinstance(wd, int) and 0 <= wd <= 6):
            raise HTTPException(400, "weekday: 0=Monday..6=Sunday or null")
        out["weekday"] = wd
    elif not partial:
        out["weekday"] = None
    if "day_of_month" in body:
        dom = body["day_of_month"]
        if dom is not None and not (isinstance(dom, int)
                                    and 1 <= dom <= 28):
            raise HTTPException(400, "day_of_month: 1..28 or null")
        out["day_of_month"] = dom
    elif not partial:
        out["day_of_month"] = None
    tz = need("timezone", lambda v: isinstance(v, str) and v.strip(),
              "IANA timezone name")
    if tz is not None:
        out["timezone"] = tz.strip()
    if "project_id" in body:
        pid = body["project_id"]
        if pid is not None and not (isinstance(pid, str) and pid.strip()):
            raise HTTPException(400, "project_id: string id or null")
        out["project_id"] = (pid.strip() if isinstance(pid, str)
                             and pid.strip() else None)
    if "days" in body:
        try:
            days_v = int(body["days"])
        except (TypeError, ValueError):
            raise HTTPException(400, "days: integer >= 0 (0 = all time)")
        if days_v < 0:
            raise HTTPException(400, "days: >= 0 (0 = all time)")
        out["days"] = days_v
    elif not partial:
        out["days"] = 90
    if "enabled" in body:
        out["enabled"] = 1 if body["enabled"] else 0
    # Spec coherence (create only; PATCH probes the merged row instead).
    if not partial:
        if out.get("frequency") == "weekly" and out.get("weekday") is None:
            raise HTTPException(
                400, "weekday: required for weekly report schedules")
        if (out.get("frequency") == "monthly"
                and out.get("day_of_month") is None):
            raise HTTPException(
                400, "day_of_month: required for monthly report schedules")
        try:
            compute_next_report_run(out["frequency"], out["run_time"],
                                    out.get("weekday"),
                                    out.get("day_of_month"),
                                    out["timezone"])
        except ValueError as e:
            raise HTTPException(400, str(e))
    return out


def _report_schedule_row(row) -> dict:
    return dict(row)


def _check_report_project(db, org_id: str, project_id: str | None,
                          key_pid: str | None) -> str | None:
    """Resolve + validate the effective project for a report schedule.

    Project-scoped keys never reach this (``require_org_scope`` rejects
    them at the endpoint). An explicit project must belong to the org
    (404 otherwise); null means the whole org.
    """
    if key_pid and project_id and project_id != key_pid:
        raise HTTPException(
            403, "Project-scoped keys cannot use other projects")
    eff = key_pid or project_id
    if eff:
        prow = db.execute("SELECT id FROM projects WHERE id=? AND org_id=?",
                          (eff, org_id)).fetchone()
        if not prow:
            raise HTTPException(404, "Project not found")
    return eff


@app.post("/api/report-schedules")
@limiter.limit("30/minute")
async def create_report_schedule(request: Request):
    """Create a scheduled executive report (member+, org scope).

    ``frequency`` is weekly|monthly; weekly needs ``weekday`` (0=Monday),
    monthly needs ``day_of_month`` (1..28). ``project_id`` scopes the
    report to one project (null = whole org). The PDF is emailed to the
    org's ``/api/alert-emails`` recipients when the schedule fires.
    """
    from scheduled_reports import (compute_next_report_run,  # noqa: E402
                                   new_report_schedule_id)
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    spec = _validate_report_schedule_body(body)
    db = get_db()
    eff_project = _check_report_project(db, request.state.org_id,
                                        spec.get("project_id"), None)
    sid = new_report_schedule_id()
    nxt = compute_next_report_run(spec["frequency"], spec["run_time"],
                                  spec.get("weekday"),
                                  spec.get("day_of_month"),
                                  spec["timezone"])
    db.execute(
        "INSERT INTO report_schedules (id, org_id, name, frequency,"
        " run_time, weekday, day_of_month, timezone, project_id, days,"
        " enabled, next_run_at, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, request.state.org_id, spec["name"], spec["frequency"],
         spec["run_time"], spec.get("weekday"), spec.get("day_of_month"),
         spec["timezone"], eff_project, spec.get("days", 90),
         spec.get("enabled", 1), nxt, now()))
    db.commit()
    db.close()
    _audit(request, "report_schedule.created", "report_schedule", sid,
           {"name": spec["name"], "frequency": spec["frequency"]})
    return {"report_schedule_id": sid, "next_run_at": nxt}


@app.get("/api/report-schedules")
@limiter.limit("60/minute")
def list_report_schedules(request: Request):
    """List the org's report schedules (viewer+, org scope)."""
    require_org_scope(request)
    db = get_db()
    rows = db.execute(
        "SELECT * FROM report_schedules WHERE org_id=?"
        " ORDER BY created_at DESC",
        (request.state.org_id,)).fetchall()
    db.close()
    return [_report_schedule_row(r) for r in rows]


@app.get("/api/report-schedules/{schedule_id}")
@limiter.limit("60/minute")
def get_report_schedule(request: Request, schedule_id: str):
    """Fetch one report schedule (viewer+, org scope)."""
    require_org_scope(request)
    db = get_db()
    row = db.execute("SELECT * FROM report_schedules WHERE id=? AND org_id=?",
                     (schedule_id, request.state.org_id)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Report schedule not found")
    return _report_schedule_row(row)


@app.patch("/api/report-schedules/{schedule_id}")
@limiter.limit("30/minute")
async def update_report_schedule(request: Request, schedule_id: str):
    """Update a report schedule (member+, org scope). Changing the cadence
    or timezone recomputes the next run from now."""
    from scheduled_reports import compute_next_report_run  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - malformed JSON
        body = {}
    db = get_db()
    row = db.execute("SELECT * FROM report_schedules WHERE id=? AND org_id=?",
                     (schedule_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Report schedule not found")
    sched = dict(row)
    spec = _validate_report_schedule_body(body, partial=True)
    if "project_id" in spec:
        spec["project_id"] = _check_report_project(
            db, request.state.org_id, spec["project_id"], None)
    merged = {**sched, **spec}
    if merged["frequency"] == "weekly" and merged.get("weekday") is None:
        db.close()
        raise HTTPException(
            400, "weekday: required for weekly report schedules")
    if (merged["frequency"] == "monthly"
            and merged.get("day_of_month") is None):
        db.close()
        raise HTTPException(
            400, "day_of_month: required for monthly report schedules")
    sets, params = [], []
    for key in ("name", "frequency", "run_time", "weekday", "day_of_month",
                "timezone", "project_id", "days", "enabled"):
        if key in spec:
            sets.append(f"{key}=?")
            params.append(spec[key])
    if any(k in spec for k in ("frequency", "run_time", "weekday",
                               "day_of_month", "timezone")):
        try:
            nxt = compute_next_report_run(
                merged["frequency"], merged["run_time"],
                merged.get("weekday"), merged.get("day_of_month"),
                merged["timezone"])
        except ValueError as e:
            db.close()
            raise HTTPException(400, str(e))
        sets.append("next_run_at=?")
        params.append(nxt)
    if sets:
        params.extend([schedule_id, request.state.org_id])
        db.execute(f"UPDATE report_schedules SET {', '.join(sets)}"
                   " WHERE id=? AND org_id=?", params)
        db.commit()
    db.close()
    _audit(request, "report_schedule.updated", "report_schedule", schedule_id,
           {"fields": sorted(spec.keys())})
    return get_report_schedule(request, schedule_id)


@app.delete("/api/report-schedules/{schedule_id}")
@limiter.limit("30/minute")
def delete_report_schedule(request: Request, schedule_id: str):
    """Delete a report schedule and its delivery history (member+)."""
    require_role(request, "member")
    require_org_scope(request)
    db = get_db()
    row = db.execute("SELECT project_id FROM report_schedules"
                     " WHERE id=? AND org_id=?",
                     (schedule_id, request.state.org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Report schedule not found")
    db.execute("DELETE FROM notifications WHERE report_schedule_id=?",
               (schedule_id,))
    db.execute("DELETE FROM report_schedules WHERE id=?", (schedule_id,))
    db.commit()
    db.close()
    _audit(request, "report_schedule.deleted", "report_schedule",
           schedule_id, {})
    return {"report_schedule_id": schedule_id, "deleted": True}


@app.post("/api/report-schedules/{schedule_id}/run")
@limiter.limit("10/minute")
def run_report_schedule_endpoint(request: Request, schedule_id: str):
    """Trigger one immediate delivery of an enabled report schedule
    (member+). The regular cadence is untouched: ``next_run_at`` keeps
    its value."""
    from scheduled_reports import run_report_schedule_now  # noqa: E402
    require_role(request, "member")
    require_org_scope(request)
    db = get_db()
    row = db.execute("SELECT project_id, enabled FROM report_schedules"
                     " WHERE id=? AND org_id=?",
                     (schedule_id, request.state.org_id)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Report schedule not found")
    try:
        out = run_report_schedule_now(schedule_id)
    except KeyError:
        raise HTTPException(404, "Report schedule not found")
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit(request, "report_schedule.run", "report_schedule", schedule_id,
           {"delivered": out.get("delivered")})
    return {"report_schedule_id": schedule_id, **out}


# ---------------------------------------------------------------------------
# Subscriptions (Phase 1): plans, current subscription, usage.
# ---------------------------------------------------------------------------

@app.get("/api/plans")
def api_plans():
    """Public plan catalog. Prices are placeholders until customer interviews."""
    return list_plans()


@app.get("/api/health")
@limiter.limit("60/minute")
def api_health(request: Request):
    """Public liveness/readiness probe for load balancers and monitors.

    No auth by design (probes can't carry API keys); reveals only component
    statuses, never secrets. 200 = all components healthy, 503 otherwise.
    """
    checks = {}
    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        db.close()
        checks["database"] = "ok"
    except Exception as e:  # noqa: BLE001 - health must report, not raise
        checks["database"] = f"error: {type(e).__name__}"
    if queue_enabled():
        try:
            conn = celery_app.broker_connection()
            conn.ensure_connection(max_retries=1)
            conn.release()
            checks["broker"] = "ok"
        except Exception as e:  # noqa: BLE001 - health must report, not raise
            checks["broker"] = f"error: {type(e).__name__}"
    else:
        checks["broker"] = "inline-mode"
    healthy = all(v == "ok" or v == "inline-mode" for v in checks.values())
    return JSONResponse(
        {"status": "ok" if healthy else "degraded", "checks": checks},
        status_code=200 if healthy else 503,
    )


# ---------------------------------------------------------------------------
# NOWPayments crypto checkout (USDT). DRAFT — see nowpayments_pay module.
# Deploy-time env: NOWPAYMENTS_API_KEY, NOWPAYMENTS_IPN_SECRET, PUBLIC_BASE_URL
# ---------------------------------------------------------------------------
@app.post("/api/checkout/crypto")
@limiter.limit("10/minute")
async def crypto_checkout(request: Request):
    """Create a hosted NOWPayments invoice for a public tier.

    Public (new customers have no API key yet); rate-limited to 10/min/IP.
    Body: {tier: starter|pro|advanced, cycle: monthly|annual, email: str}
    Returns: {invoice_url, invoice_id, order_id, api_key}

    Key delivery: a fresh API key is provisioned for NEW orgs and returned
    here, shown once — the buyer saves it before paying (it works on the
    free tier until the IPN upgrades the plan). Renewals reuse the existing
    org (same email) and get api_key=null: they already have a key.
    """
    api_key = os.environ.get("NOWPAYMENTS_API_KEY", "")
    if not api_key:
        raise HTTPException(503, "Crypto checkout is not configured yet")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")
    tier = str(body.get("tier", "")).lower()
    cycle = str(body.get("cycle", "")).lower()
    email = str(body.get("email", "")).strip()
    entry = nowpay.catalog_entry(tier, cycle)
    if not entry:
        raise HTTPException(400, "Unknown tier/cycle")
    if "@" not in email or len(email) > 254:
        raise HTTPException(400, "A valid email is required")
    usd_price, _plan = entry

    org_id = nowpay.find_org_by_email(email)
    raw_key = None
    if org_id is None:
        org_id = create_org(email)
        raw_key = provision_key(org_id, name="checkout")
    ensure_subscription(org_id)
    order_id = nowpay.make_order_id(tier, cycle, org_id)
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    ipn_url = f"{base}/api/webhooks/nowpayments" if base else ""
    success_url = f"{base}/checkout/success?order_id={order_id}" if base else ""
    cancel_url = f"{base}/pricing" if base else ""
    try:
        invoice = nowpay.create_invoice(
            api_key, usd_price, order_id,
            f"BraimSec {tier.title()} ({cycle})",
            ipn_url, success_url, cancel_url)
    except Exception as e:
        raise HTTPException(502, f"Payment provider error: {e}")
    invoice_id = str(invoice.get("id"))
    nowpay.record_invoice(invoice_id, order_id, org_id, tier, cycle,
                          usd_price, customer_email=email)
    return {"invoice_url": invoice.get("invoice_url"),
            "invoice_id": invoice_id, "order_id": order_id,
            "amount_usd": usd_price, "pay_currency": nowpay.PAY_CURRENCY,
            "api_key": raw_key,
            "key_note": ("Save this API key now — it is shown only once."
                         if raw_key else
                         "Use the API key from your previous checkout.")}


@app.get("/api/checkout/status")
@limiter.limit("30/minute")
async def checkout_status(request: Request, order_id: str = ""):
    """Public order status for the success page. Keyed by the unguessable
    order_id (8 random hex chars); reveals only that order's own state."""
    st = nowpay.get_order_status(order_id) if order_id else None
    if not st:
        raise HTTPException(404, "Unknown order")
    return {"order_id": st["order_id"], "pay_status": st["pay_status"],
            "tier": st["tier"], "cycle": st["cycle"],
            "amount_usd": st["amount_usd"],
            "plan": st["plan_id"], "subscription": st["sub_status"],
            "period_end": st["current_period_end"]}


@app.get("/checkout/success", response_class=HTMLResponse)
async def checkout_success(request: Request):
    """Post-payment landing page. NOWPayments redirects here with
    ?order_id=... — the page polls /api/checkout/status and shows the
    activation state. The API key itself was shown at checkout time."""
    return """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BraimSec — Payment status</title>
<style>body{font-family:system-ui,sans-serif;background:#0b1020;color:#e8ecf4;
display:flex;justify-content:center;padding:48px 16px;margin:0}
.card{max-width:560px;background:#131a30;border:1px solid #24304f;border-radius:12px;
padding:32px}h1{font-size:22px;margin:0 0 12px}.ok{color:#4ade80}.wait{color:#fbbf24}
code{background:#0b1020;padding:2px 8px;border-radius:6px;font-size:13px}
p{line-height:1.6;color:#b9c2d8}.small{font-size:13px;color:#7d88a3}</style>
</head><body><div class="card">
<h1>🛡️ BraimSec payment status</h1>
<p id="msg" class="wait">Checking your payment…</p>
<p class="small">Your API key was shown on the checkout page before payment.
Lost it? Email <code>support@braimsec.world</code> from your purchase email
and we'll rotate a new one for you.</p>
<script>
const oid = new URLSearchParams(location.search).get('order_id');
const msg = document.getElementById('msg');
if (!oid) { msg.textContent = 'Missing order id.'; }
else {
  async function poll() {
    try {
      const r = await fetch('/api/checkout/status?order_id=' + encodeURIComponent(oid));
      if (!r.ok) throw 0;
      const s = await r.json();
      if (s.pay_status === 'fulfilled' && s.subscription === 'active') {
        msg.className = 'ok';
        msg.innerHTML = 'Payment confirmed — <b>' + s.tier + ' (' + s.cycle +
          ')</b> is active until ' + (s.period_end || '').slice(0, 10) +
          '.<br>Use your API key with header <code>X-API-Key</code>.';
        return;
      }
      msg.textContent = 'Payment status: ' + s.pay_status +
        ' — this page updates automatically once the network confirms.';
    } catch (e) { msg.textContent = 'Could not reach the server — retrying…'; }
    setTimeout(poll, 8000);
  }
  poll();
}
</script></div></body></html>"""


@app.post("/api/webhooks/nowpayments")
async def nowpayments_ipn(request: Request):
    """NOWPayments Instant Payment Notification receiver.

    Public by necessity (called by NOWPayments). Security is the HMAC-SHA512
    signature in x-nowpayments-sig, verified against NOWPAYMENTS_IPN_SECRET.
    Always returns 200 on a valid signature (even for ignored events) so
    NOWPayments stops retrying; 400 only on bad signature.
    """
    secret = os.environ.get("NOWPAYMENTS_IPN_SECRET", "")
    raw = await request.body()
    sig = request.headers.get("x-nowpayments-sig")
    if not nowpay.verify_ipn_signature(raw, sig, secret):
        return JSONResponse({"ok": False, "error": "bad signature"},
                            status_code=400)
    try:
        payload = json.loads(raw.decode())
    except Exception:
        return JSONResponse({"ok": False, "error": "bad json"},
                            status_code=400)
    verdict, info = nowpay.fulfill_ipn(payload)
    return {"ok": True, "verdict": verdict,
            "detail": info if isinstance(info, str) else "fulfilled"}


@app.get("/api/subscription")
def api_subscription(request: Request):
    """The caller's org subscription: plan, status, period, quotas in force."""
    require_org_scope(request)
    sub = get_subscription(request.state.org_id)
    plan = effective_plan(request.state.org_id)
    return {
        "plan_id": sub["plan_id"],
        "plan_name": sub["plan_name"],
        "status": sub["status"],
        "current_period_start": sub["current_period_start"],
        "current_period_end": sub["current_period_end"],
        "trial_ends_at": sub["trial_ends_at"],
        "quotas": {
            "scans": plan["scan_quota"],
            "ai_reviews": plan["ai_review_quota"],
        },
        "limits": {
            "max_projects": plan["max_projects"],
            "max_seats": plan["max_seats"],
        },
        "features": plan["features"],
    }


@app.get("/api/usage")
def api_usage(request: Request):
    """Current month's consumption vs quota. Quotas never roll over."""
    require_org_scope(request)
    org_id = request.state.org_id
    out = {}
    for kind, label in (("scan", "scans"), ("ai_review", "ai_reviews")):
        allowed, used, quota = quota_check(org_id, kind, 1)
        out[label] = {"used": used, "quota": quota,
                      "remaining": (quota - used) if quota >= 0 else -1,
                      "unlimited": quota < 0}
    return out


# ---------------------------------------------------------------------------
# API documentation: OpenAPI 3.1 document + human-readable reference page.
# The spec is generated from the live routes (api/openapi.py) and fails
# closed when a route lacks a docs entry — it cannot go stale.
# ---------------------------------------------------------------------------

@app.get("/api/openapi.json")
@limiter.limit("60/minute")
def api_openapi_json(request: Request):
    """Public OpenAPI 3.1 document (see api/openapi.py)."""
    from openapi import OpenAPIError, spec_to_json  # noqa: E402
    try:
        body = spec_to_json(app)
    except OpenAPIError as e:
        return JSONResponse({"detail": f"docs out of sync: {e}"},
                            status_code=500)
    return Response(content=body, media_type="application/json")


@app.get("/docs", response_class=HTMLResponse)
@limiter.limit("600/minute")
def api_docs_page(request: Request):
    """Human-readable API reference (self-contained, no CDN)."""
    from openapi import docs_page_html  # noqa: E402
    return docs_page_html()


# Dashboard (served after API routes so /api/* matches first)
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dashboard")
if os.path.isdir(DASHBOARD_DIR):
    app.mount("/", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn

    # Local-only by default. Set BRAIMSEC_HOST=0.0.0.0 explicitly to expose —
    # and only behind proper auth/TLS.
    host = os.environ.get("BRAIMSEC_HOST", "127.0.0.1")
    port = int(os.environ.get("BRAIMSEC_PORT", "8000"))
    if host == "0.0.0.0":
        print("[braimsec] WARNING: listening on 0.0.0.0 — expose only behind auth/TLS.")
    uvicorn.run(app, host=host, port=port)
