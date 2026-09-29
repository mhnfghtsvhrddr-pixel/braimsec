"""Durable background workers for BraimSec (Celery + Redis).

Replaces in-process FastAPI BackgroundTasks with a real queue:

- a worker crash or deploy no longer loses a running scan
- transient engine failures are retried with backoff
- horizontal scaling: run more ``celery -A tasks worker`` processes

Queue selection (read at call time, so tests can flip it)::

    BRAIMSEC_BROKER_URL set   -> enqueue via Celery (production)
    BRAIMSEC_BROKER_URL unset -> inline fallback (dev / temp backend)

The HTTP contract is unchanged: ``POST /api/scans`` still returns
``{"scan_id": ..., "status": "queued"}`` immediately; the client polls
``GET /api/scans/{scan_id}`` or receives a signed webhook.

Worker startup (from the ``api/`` directory)::

    celery -A tasks worker --loglevel=info --concurrency=2

The worker MUST share the filesystem with the API (scan targets are local
directories / extracted zips) and MUST see the same ``BRAIMSEC_DB``.
"""

import hashlib
import hmac
import json
import logging
import os
import shutil
import sys
import time
import urllib.request

from celery import Celery

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))

from database import get_db  # noqa: E402
from billing import record_usage  # noqa: E402
from scan_engine import run_gitleaks, run_semgrep, run_sca  # noqa: E402
from ai_layer import LLMClient, analyze_finding, read_snippet  # noqa: E402

log = logging.getLogger("braimsec.tasks")

BROKER_URL = os.environ.get("BRAIMSEC_BROKER_URL", "redis://127.0.0.1:6379/0")

celery_app = Celery("braimsec", broker=BROKER_URL)

# Dev-only: kombu filesystem transport (no Redis needed for local smoke tests).
# e.g. BRAIMSEC_BROKER_URL=filesystem:// with the three folders below.
_transport_options = {}
for _key in ("data_folder_in", "data_folder_out", "data_folder_processed"):
    _v = os.environ.get("BRAIMSEC_BROKER_" + _key.upper())
    if _v:
        _transport_options[_key] = _v

celery_app.conf.update(
    task_acks_late=True,            # don't lose a scan if a worker dies mid-run
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,   # long tasks: fair dispatch across workers
    task_ignore_result=True,        # scan state lives in SQLite, not the backend
    task_default_queue="scans",
    broker_transport_options=_transport_options,
)

WEBHOOK_TIMEOUT_S = 10
WEBHOOK_ATTEMPTS = 3


def queue_enabled() -> bool:
    """True when the deployment opted into the durable queue."""
    return bool(os.environ.get("BRAIMSEC_BROKER_URL"))


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _deliver_webhook(scan_id: str) -> None:
    """Best-effort signed webhook on terminal scan state. Never fails the scan."""
    db = get_db()
    row = db.execute(
        "SELECT id, org_id, status, total_findings, finished_at, error,"
        " webhook_url, webhook_secret FROM scans WHERE id=?",
        (scan_id,)).fetchone()
    db.close()
    if not row or not row["webhook_url"]:
        return
    event = "scan.completed" if row["status"] == "done" else "scan.failed"
    payload = {
        "event": event,
        "scan_id": row["id"],
        "org_id": row["org_id"],
        "status": row["status"],
        "total_findings": row["total_findings"] or 0,
        "finished_at": row["finished_at"],
        "error": row["error"],
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(row["webhook_secret"].encode(), body,
                   hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        row["webhook_url"], data=body,
        headers={"Content-Type": "application/json",
                 "X-BraimSec-Event": event,
                 "X-BraimSec-Signature": f"sha256={sig}"},
        method="POST")
    for attempt in range(1, WEBHOOK_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT_S) as resp:
                if 200 <= resp.status < 300:
                    return
                log.warning("webhook %s -> %s (attempt %d)",
                            row["webhook_url"], resp.status, attempt)
        except Exception as e:  # noqa: BLE001 - best effort by design
            log.warning("webhook %s failed (attempt %d): %s",
                        row["webhook_url"], attempt, e)
        time.sleep(2 ** attempt)
    log.error("webhook %s undelivered after %d attempts (scan %s)",
              row["webhook_url"], WEBHOOK_ATTEMPTS, scan_id)


@celery_app.task(name="braimsec.run_scan", bind=True, max_retries=2)
def run_scan(self, scan_id: str, target_dir: str, cleanup_dir: str | None = None):
    """Run both engines, store normalized findings. Idempotent on retry."""
    return _run_scan_impl(self, scan_id, target_dir, cleanup_dir)


def _run_scan_impl(task_self, scan_id: str, target_dir: str,
                   cleanup_dir: str | None = None):
    """Task body as a plain function (testable without Celery machinery)."""
    db = get_db()
    will_retry = False
    try:
        # Idempotency: a redelivered task must not duplicate findings.
        db.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        db.execute("UPDATE scans SET status='running', started_at=? WHERE id=?",
                   (_now_iso(), scan_id))
        db.commit()
        findings = run_semgrep(target_dir) + run_gitleaks(target_dir) + run_sca(target_dir)
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
            (_now_iso(), len(findings), scan_id),
        )
        db.commit()
    except Exception as e:  # noqa: BLE001 - prototype: record failure
        if task_self.request.retries >= (task_self.max_retries or 0):
            db.execute(
                "UPDATE scans SET status='failed', finished_at=?, error=?"
                " WHERE id=?", (_now_iso(), str(e), scan_id))
            db.commit()
        else:
            # Transient engine failure (e.g. binary hiccup): retry with backoff,
            # keeping the target dir alive for the next attempt.
            will_retry = True
            raise task_self.retry(exc=e, countdown=2 ** task_self.request.retries * 10)
    finally:
        db.close()
        if not will_retry and cleanup_dir and os.path.isdir(cleanup_dir):
            shutil.rmtree(cleanup_dir, ignore_errors=True)
    if not will_retry:
        _deliver_webhook(scan_id)


@celery_app.task(name="braimsec.run_ai_review", bind=True, max_retries=2)
def run_ai_review(self, scan_id: str):
    """LLM second-opinion review of every finding.

    Each reviewed finding consumes one unit of the org's monthly AI-review
    quota (the real variable cost) and is recorded in the usage ledger.
    """
    return _run_ai_review_impl(self, scan_id)


def _run_ai_review_impl(task_self, scan_id: str):
    """Task body as a plain function (testable without Celery machinery)."""
    client = LLMClient()
    db = get_db()
    will_retry = False
    try:
        scan = db.execute("SELECT org_id FROM scans WHERE id=?", (scan_id,)).fetchone()
        org_id = scan["org_id"] if scan else None
        rows = db.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        # Only pending findings: retries resume where the last attempt stopped
        # and never double-bill the AI-review quota.
        pending = [r for r in rows if r["ai_verdict"] is None]
        failed = 0
        for r in pending:
            f = dict(r)
            snippet = read_snippet(f.get("file") or "", f.get("line") or 0)
            t0 = time.monotonic()
            try:
                res = analyze_finding(client, f, snippet)
            except Exception as e:  # noqa: BLE001 - one bad finding != dead job
                log.warning("ai review failed for finding %s: %s", f["id"], e)
                failed += 1
                continue
            wall_ms = int((time.monotonic() - t0) * 1000)
            db.execute(
                """UPDATE findings SET ai_verdict=?, ai_confidence=?,
                   ai_explanation=?, ai_fix=? WHERE id=?""",
                (res["ai_verdict"], res["ai_confidence"],
                 res["ai_explanation"], res["ai_fix"], f["id"]),
            )
            db.commit()
            if org_id:
                record_usage(org_id, "ai_review", scan_id, wall_time_ms=wall_ms)
        if pending and failed == len(pending):
            # Total outage (e.g. LLM down): retry the whole batch with backoff.
            raise RuntimeError("all findings failed AI review")
    except Exception as e:  # noqa: BLE001
        if isinstance(e, RuntimeError) and task_self.request.retries < (task_self.max_retries or 0):
            will_retry = True
            raise task_self.retry(exc=e, countdown=2 ** task_self.request.retries * 30)
        log.error("ai review job %s failed: %s", scan_id, e)
    finally:
        db.close()
    return {"scan_id": scan_id, "will_retry": will_retry}


def enqueue_scan(scan_id: str, target_dir: str, cleanup_dir: str | None,
                 background_tasks=None) -> str:
    """Route a scan to the durable queue, or inline when unconfigured.

    Returns "celery" or "inline" so callers (and tests) can observe routing.
    """
    if queue_enabled():
        run_scan.delay(scan_id, target_dir, cleanup_dir)
        return "celery"
    if background_tasks is not None:
        background_tasks.add_task(run_scan, scan_id, target_dir, cleanup_dir)
    else:
        run_scan(scan_id, target_dir, cleanup_dir)
    return "inline"


def enqueue_ai_review(scan_id: str, background_tasks=None) -> str:
    """Route an AI review to the durable queue, or inline when unconfigured."""
    if queue_enabled():
        run_ai_review.delay(scan_id)
        return "celery"
    if background_tasks is not None:
        background_tasks.add_task(run_ai_review, scan_id)
    else:
        run_ai_review(scan_id)
    return "inline"
