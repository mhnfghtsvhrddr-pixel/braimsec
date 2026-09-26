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
import secrets
import shutil
import sys
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from database import get_db, init_db

# Reuse the scan engine prototype
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))
from scan_engine import (  # noqa: E402
    ENGINE_NAME,
    ENGINE_VERSION,
    run_gitleaks,
    run_semgrep,
    to_sarif,
)

# AI layer
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))
from ai_layer import LLMClient, analyze_finding, read_snippet  # noqa: E402


def now():
    return datetime.now(timezone.utc).isoformat()


app = FastAPI(title="BraimSec API", version="0.1.0")


# ---------------------------------------------------------------------------
# Security hardening (prototype-grade — not a substitute for production auth)
# ---------------------------------------------------------------------------
MAX_ZIP_BYTES = 50 * 1024 * 1024  # 50 MB upload cap (ZIP bombs)
API_KEY_ENV = "BRAIMSEC_API_KEY"

API_KEY = os.environ.get(API_KEY_ENV)
if not API_KEY:
    # Secure by default: an unset key means a random ephemeral one.
    # Printed to the operator's console only — never written to files.
    API_KEY = secrets.token_urlsafe(32)
    print(f"[braimsec] {API_KEY_ENV} not set — generated ephemeral API key (console only).")


@app.middleware("http")
async def api_key_gate(request: Request, call_next):
    """Require X-API-Key on every /api/* route. Dashboard static files stay open."""
    if request.url.path.startswith("/api/"):
        presented = request.headers.get("x-api-key", "")
        if not presented or not secrets.compare_digest(presented, API_KEY):
            return JSONResponse(
                {"detail": "Invalid or missing X-API-Key header"}, status_code=401
            )
    return await call_next(request)


def _safe_extract(z: zipfile.ZipFile, dest: str):
    """Extract a zip archive, refusing Zip Slip path traversal."""
    dest = os.path.abspath(dest)
    for member in z.infolist():
        target = os.path.abspath(os.path.join(dest, member.filename))
        if not target.startswith(dest + os.sep):
            raise HTTPException(400, f"Unsafe path in zip archive: {member.filename}")
    z.extractall(dest)


@app.on_event("startup")
def startup():
    init_db()


def do_scan(scan_id: str, target_dir: str, cleanup_dir: str | None = None):
    """Background job: run both engines, store normalized findings."""
    db = get_db()
    try:
        db.execute("UPDATE scans SET status='running', started_at=? WHERE id=?",
                   (now(), scan_id))
        db.commit()
        findings = run_semgrep(target_dir) + run_gitleaks(target_dir)
        for f in findings:
            db.execute(
                """INSERT INTO findings
                   (scan_id, tool, rule_id, severity, message, file, line, col)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (scan_id, f["tool"], f["rule_id"], f["severity"],
                 f["message"], f["file"], f["line"], f["col"]),
            )
        db.execute(
            "UPDATE scans SET status='done', finished_at=?, total_findings=? WHERE id=?",
            (now(), len(findings), scan_id),
        )
        db.commit()
    except Exception as e:  # noqa: BLE001 - prototype: record failure
        db.execute("UPDATE scans SET status='failed', finished_at=?, error=? WHERE id=?",
                   (now(), str(e), scan_id))
        db.commit()
    finally:
        db.close()
        if cleanup_dir and os.path.isdir(cleanup_dir):
            shutil.rmtree(cleanup_dir, ignore_errors=True)


def _new_scan(target_name: str, target_dir: str, cleanup_dir, background_tasks: BackgroundTasks):
    scan_id = uuid.uuid4().hex[:12]
    db = get_db()
    db.execute("INSERT INTO scans (id, target_name, status, created_at) VALUES (?,?,?,?)",
               (scan_id, target_name, "queued", now()))
    db.commit()
    db.close()
    background_tasks.add_task(do_scan, scan_id, target_dir, cleanup_dir)
    return {"scan_id": scan_id, "status": "queued"}


@app.post("/api/scans")
async def create_scan(
    background_tasks: BackgroundTasks,
    target_path: str | None = Form(None),
    file: UploadFile | None = File(None),
):
    """Start a scan from a server-local path or an uploaded zip."""
    if file is not None:
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
        return _new_scan(filename, target_dir, workdir, background_tasks)

    if target_path:
        if not os.path.isdir(target_path):
            raise HTTPException(400, f"Not a directory: {target_path}")
        return _new_scan(os.path.basename(target_path.rstrip("/")) or target_path,
                         target_path, None, background_tasks)

    raise HTTPException(400, "Provide target_path or upload a zip file")


@app.get("/api/scans")
def list_scans():
    db = get_db()
    rows = db.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]


@app.get("/api/scans/{scan_id}")
def scan_status(scan_id: str):
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
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
def scan_results(scan_id: str, severity: str | None = None):
    db = get_db()
    exists = db.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not exists:
        db.close()
        raise HTTPException(404, "Scan not found")
    q = ("SELECT tool, rule_id, severity, message, file, line, col, "
         "ai_verdict, ai_confidence, ai_explanation, ai_fix "
         "FROM findings WHERE scan_id=?")
    params = [scan_id]
    if severity:
        q += " AND severity=?"
        params.append(severity)
    rows = db.execute(q, params).fetchall()
    db.close()
    return [dict(r) for r in rows]


def do_ai_review(scan_id: str):
    """Background job: LLM second-opinion review of every finding."""
    client = LLMClient()
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        for r in rows:
            f = dict(r)
            snippet = read_snippet(f.get("file") or "", f.get("line") or 0)
            res = analyze_finding(client, f, snippet)
            db.execute(
                """UPDATE findings SET ai_verdict=?, ai_confidence=?,
                   ai_explanation=?, ai_fix=? WHERE id=?""",
                (res["ai_verdict"], res["ai_confidence"],
                 res["ai_explanation"], res["ai_fix"], f["id"]),
            )
            db.commit()
    finally:
        db.close()


@app.post("/api/scans/{scan_id}/ai-review")
def start_ai_review(scan_id: str, background_tasks: BackgroundTasks):
    db = get_db()
    exists = db.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone()
    db.close()
    if not exists:
        raise HTTPException(404, "Scan not found")
    background_tasks.add_task(do_ai_review, scan_id)
    return {"scan_id": scan_id, "ai_review": "queued"}


@app.get("/api/scans/{scan_id}/sarif")
def scan_sarif(scan_id: str):
    findings = scan_results(scan_id)
    return to_sarif([{
        "tool": f["tool"], "rule_id": f["rule_id"], "severity": f["severity"],
        "message": f["message"], "file": f["file"],
        "line": f["line"] or 1, "col": f["col"] or 1,
    } for f in findings])


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
