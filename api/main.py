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
import json
import secrets
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from database import get_db, init_db
from billing import (  # noqa: E402
    OWNER_ORG_ID, cancel_subscription, consume_scan, create_org, effective_plan,
    ensure_owner_org, ensure_subscription, get_subscription, list_plans,
    provision_key, quota_check, quota_status, record_usage, run_expiry,
    seed_plans, start_trial, usage_count, verify_key,
)
import nowpayments_pay as nowpay  # noqa: E402

# Reuse the scan engine prototype
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "reports"))
from scan_engine import (  # noqa: E402
    to_sarif,
)
from builder import ReportError, build_report  # noqa: E402
from pdf import render_pdf  # noqa: E402
from sink_audit import (  # noqa: E402
    audit_candidates,
    discover_sinks,
    enabled as sink_audit_enabled,
)
from ai_layer import LLMClient  # noqa: E402
from taintflow import extract_taint_path  # noqa: E402
from fix_suggestions import (  # noqa: E402
    extract_fix_context,
    generate_fix,
    validate_fix,
)

# Durable queue (Celery + Redis); falls back to inline BackgroundTasks
# when BRAIMSEC_BROKER_URL is unset.
from tasks import enqueue_ai_review, enqueue_scan  # noqa: E402


def now():
    return datetime.now(timezone.utc).isoformat()


app = FastAPI(title="BraimSec API", version="0.1.0")


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
    Sets request.state.org_id / request.state.plan for downstream handlers.

    /api/plans is public (pricing catalog for the marketing page).
    /api/checkout/crypto is public (new-customer crypto checkout; rate-limited).
    /api/webhooks/nowpayments is public (NOWPayments IPN; secured by HMAC).
    """
    public_paths = ("/api/plans", "/api/checkout/crypto",
                    "/api/checkout/status", "/api/webhooks/nowpayments")
    if request.url.path.startswith("/api/") and request.url.path not in public_paths:
        presented = request.headers.get("x-api-key", "")
        org = None
        if presented:
            if secrets.compare_digest(presented, API_KEY):
                org = {"org_id": OWNER_ORG_ID, "plan": "team"}
            else:
                org = verify_key(presented)
        if not org:
            return JSONResponse(
                {"detail": "Invalid or missing X-API-Key header"}, status_code=401
            )
        request.state.org_id = org["org_id"]
        request.state.plan = org["plan"]
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


@app.on_event("startup")
def startup():
    init_db()
    seed_plans()
    ensure_owner_org()
    ensure_subscription(OWNER_ORG_ID)


def _new_scan(org_id: str, target_name: str, target_dir: str,
              cleanup_dir, background_tasks: BackgroundTasks,
              webhook_url: str | None = None,
              webhook_secret: str | None = None,
              baseline_scan_id: str | None = None):
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
    scan_id = uuid.uuid4().hex[:12]
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " webhook_url, webhook_secret, target_dir) VALUES (?,?,?,?,?,?,?,?)",
        (scan_id, org_id, target_name, "queued", now(),
         webhook_url, webhook_secret, target_dir))
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


def _check_baseline(org_id: str, baseline_scan_id: str) -> None:
    """Validate a baseline_scan_id for incremental scans (fail fast, no quota)."""
    from database import get_db
    db = get_db()
    row = db.execute("SELECT org_id, status FROM scans WHERE id=?",
                     (baseline_scan_id,)).fetchone()
    db.close()
    if row is None:
        raise HTTPException(404, "baseline scan not found")
    if row["org_id"] != org_id:
        raise HTTPException(403, "baseline scan belongs to another organization")
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
    """
    org_id = request.state.org_id
    allowed, used, quota = quota_status(org_id)
    if not allowed:
        raise HTTPException(
            402,
            f"Monthly scan quota exceeded ({used}/{quota} used). "
            "Upgrade your plan to continue scanning.",
        )
    webhook_secret = None
    if webhook_url:
        from urllib.parse import urlparse
        if urlparse(webhook_url).scheme not in ("http", "https"):
            raise HTTPException(400, "webhook_url must be http(s)")
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
        filename = file.filename or "upload.zip"
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
        return _new_scan(org_id, filename, target_dir, workdir, background_tasks,
                         webhook_url, webhook_secret)

    if target_path:
        target_dir = _resolve_scan_target(target_path)
        if baseline_scan_id:
            _check_baseline(org_id, baseline_scan_id)
        return _new_scan(org_id, os.path.basename(target_dir.rstrip("/")) or target_dir,
                         target_dir, None, background_tasks,
                         webhook_url, webhook_secret, baseline_scan_id)

    raise HTTPException(400, "Provide target_path or upload a zip file")


@app.get("/api/scans")
def list_scans(request: Request):
    # Org-scoped: a customer only ever sees their own scans.
    db = get_db()
    rows = db.execute(
        "SELECT * FROM scans WHERE org_id=? ORDER BY created_at DESC",
        (request.state.org_id,)).fetchall()
    db.close()
    return [dict(r) for r in rows]


@app.get("/api/scans/{scan_id}")
def scan_status(request: Request, scan_id: str):
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id=? AND org_id=?",
                     (scan_id, request.state.org_id)).fetchone()
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
def scan_results(request: Request, scan_id: str, severity: str | None = None):
    db = get_db()
    exists = db.execute("SELECT 1 FROM scans WHERE id=? AND org_id=?",
                        (scan_id, request.state.org_id)).fetchone()
    if not exists:
        db.close()
        raise HTTPException(404, "Scan not found")
    q = ("SELECT tool, rule_id, severity, message, file, line, col, "
         "ai_verdict, ai_confidence, ai_explanation, ai_fix, "
         "(fix_generated_at IS NOT NULL) AS has_fix "
         "FROM findings WHERE scan_id=?")
    params = [scan_id]
    if severity:
        q += " AND severity=?"
        params.append(severity)
    rows = db.execute(q, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


@app.post("/api/scans/{scan_id}/ai-review")
@limiter.limit("30/minute")  # LLM calls are expensive — stricter budget
def start_ai_review(request: Request, scan_id: str, background_tasks: BackgroundTasks):
    org_id = request.state.org_id
    db = get_db()
    scan = db.execute("SELECT target_dir FROM scans WHERE id=? AND org_id=?",
                      (scan_id, org_id)).fetchone()
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
    return {"scan_id": scan_id, "ai_review": "queued",
            "sink_audit": {"status": sink_status, "budget": sink_budget}}


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

    On demand and cached: the first call spends one unit of the monthly
    ``ai_review`` quota and stores the suggestion on the finding; later
    calls return the cached suggestion for free.
    """
    org_id = request.state.org_id
    db = get_db()
    row = db.execute(
        """SELECT f.* FROM findings f JOIN scans s ON s.id = f.scan_id
           WHERE f.id = ? AND s.org_id = ?""",
        (finding_id, org_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "Finding not found")
    finding = dict(row)
    if finding.get("fix_generated_at"):
        db.close()
        return {"finding_id": finding_id, "cached": True,
                "suggestion": _fix_payload(finding)}
    # One fix = one LLM call = one unit from the same ai_review pool.
    allowed, used, quota = quota_check(org_id, "ai_review", 1)
    if not allowed:
        db.close()
        raise HTTPException(
            402,
            f"Monthly AI-review quota exceeded ({used}/{quota} used). "
            "Upgrade your plan to continue.",
        )
    client = LLMClient()
    if not client.configured:
        db.close()
        raise HTTPException(503, "AI provider not configured")
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
    generated_at = now()
    db.execute(
        """UPDATE findings SET fix_diff=?, fix_explanation=?, fix_confidence=?,
           fix_caveats=?, fix_checks=?, fix_generated_at=? WHERE id=?""",
        (checks["diff"], gen["fix_explanation"], gen["fix_confidence"],
         gen["fix_caveats"], json.dumps(checks), generated_at, finding_id))
    db.commit()
    db.close()
    record_usage(org_id, "ai_review", finding["scan_id"], wall_time_ms=wall_ms)
    db2 = get_db()
    row2 = db2.execute(
        "SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    payload = _fix_payload(dict(row2))
    db2.close()
    return {"finding_id": finding_id, "cached": False, "suggestion": payload}


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
    row = db.execute(
        """SELECT f.*, s.target_dir FROM findings f
           JOIN scans s ON s.id = f.scan_id
           WHERE f.id = ? AND s.org_id = ?""",
        (finding_id, org_id)).fetchone()
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


@app.get("/api/scans/{scan_id}/sarif")
def scan_sarif(request: Request, scan_id: str):
    findings = scan_results(request, scan_id)
    return to_sarif([{
        "tool": f["tool"], "rule_id": f["rule_id"], "severity": f["severity"],
        "message": f["message"], "file": f["file"],
        "line": f["line"] or 1, "col": f["col"] or 1,
    } for f in findings])


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
    scan = db.execute("SELECT * FROM scans WHERE id=? AND org_id=?",
                      (scan_id, request.state.org_id)).fetchone()
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
        perr = db.execute(
            "SELECT COUNT(*) c FROM findings WHERE scan_id=? AND severity='error'"
            " AND (ai_verdict='vulnerable' OR tool='gitleaks')",
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


# ---------------------------------------------------------------------------
# Subscriptions (Phase 1): plans, current subscription, usage.
# ---------------------------------------------------------------------------

@app.get("/api/plans")
def api_plans():
    """Public plan catalog. Prices are placeholders until customer interviews."""
    return list_plans()


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
    org_id = request.state.org_id
    out = {}
    for kind, label in (("scan", "scans"), ("ai_review", "ai_reviews")):
        allowed, used, quota = quota_check(org_id, kind, 1)
        out[label] = {"used": used, "quota": quota,
                      "remaining": (quota - used) if quota >= 0 else -1,
                      "unlimited": quota < 0}
    return out


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
