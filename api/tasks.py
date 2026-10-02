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

from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded

from ssrf_guard import safe_webhook_post

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))

from database import get_db  # noqa: E402
from audit import log_event  # noqa: E402
from billing import quota_check, record_usage  # noqa: E402


def _audit_scan_terminal(db, scan_id: str, action: str, detail: dict):
    """Audit-log a scan reaching a terminal state (worker context).

    Actor is 'system': the worker, not a key holder, closed the scan.
    Best-effort — a logging failure must not mask the scan outcome.
    """
    try:
        row = db.execute("SELECT org_id FROM scans WHERE id=?",
                         (scan_id,)).fetchone()
        if row:
            log_event(row["org_id"], "system", action, "scan", scan_id, detail)
    except Exception:  # noqa: BLE001 - audit must not break scan completion
        pass
from scan_engine import run_gitleaks, run_semgrep, run_sca  # noqa: E402
from docker_runner import run_scan_isolated, sandbox_mode  # noqa: E402
from ai_layer import analyze_finding, read_snippet  # noqa: E402
from groq_provider import make_llm_client  # noqa: E402
from sink_audit import (  # noqa: E402
    analyze_sink,
    audit_candidates,
    discover_sinks,
    enabled as sink_audit_enabled,
    should_store,
)

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
    timezone="UTC",                 # schedule cadences are stored UTC-aware
    beat_schedule={
        # Every minute: claim due schedules and enqueue their scans.
        # Idempotent via the DB claim in scheduler.run_scheduler_once.
        "braimsec.check-schedules": {
            "task": "braimsec.check_schedules",
            "schedule": 60.0,
        },
    },
)

WEBHOOK_TIMEOUT_S = 10
WEBHOOK_ATTEMPTS = 3

# Soft time limits (seconds, env-tunable) for the Celery tasks.
# Deliberately NO hard `time_limit`: a hard kill looks like a lost worker,
# and with task_reject_on_worker_lost=True the message would be requeued
# forever (poison-message loop). The soft limit raises
# SoftTimeLimitExceeded *inside* the task, which we catch and record as a
# failed scan — no retry, no requeue. Individual engine subprocesses are
# additionally bounded by their own 600s timeout in scan_engine.
SCAN_SOFT_LIMIT_S = int(os.environ.get("BRAIMSEC_SCAN_SOFT_LIMIT", "1500"))
AI_REVIEW_SOFT_LIMIT_S = int(os.environ.get("BRAIMSEC_AI_REVIEW_SOFT_LIMIT",
                                            "1200"))


def queue_enabled() -> bool:
    """True when the deployment opted into the durable queue."""
    return bool(os.environ.get("BRAIMSEC_BROKER_URL"))


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _engine_versions() -> dict:
    """Best-effort engine versions for the report honesty appendix
    (proposal Part 5 §4.1). Never raises; unknown versions are honest."""
    import subprocess
    out = {}
    for key, env, default, flag in (
            ("semgrep", "SEMGREP_BIN", "semgrep", "--version"),
            ("gitleaks", "GITLEAKS_BIN", "gitleaks", "version")):
        try:
            p = subprocess.run([os.environ.get(env, default), flag],
                               capture_output=True, text=True, timeout=30)
            text = (p.stdout or p.stderr or "").strip().splitlines()
            out[key] = text[0][:80] if text else "unknown"
        except Exception:  # noqa: BLE001
            out[key] = "unknown"
    try:
        rules = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "scanner", "rules", "braimsec-taint.yaml")
        with open(rules, "rb") as f:
            out["braimsec_taint_rules"] = \
                "braimsec-taint.yaml@" + hashlib.sha256(f.read()).hexdigest()[:8]
    except Exception:  # noqa: BLE001
        out["braimsec_taint_rules"] = "unknown"
    return out


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
    headers = {"Content-Type": "application/json",
               "X-BraimSec-Event": event,
               "X-BraimSec-Signature": f"sha256={sig}"}
    for attempt in range(1, WEBHOOK_ATTEMPTS + 1):
        try:
            # SSRF-guarded: pinned IP, no redirects, blocked ranges refused.
            status = safe_webhook_post(row["webhook_url"], body, headers,
                                       WEBHOOK_TIMEOUT_S)
            if 200 <= status < 300:
                return
            log.warning("webhook %s -> %s (attempt %d)",
                        row["webhook_url"], status, attempt)
        except Exception as e:  # noqa: BLE001 - best effort by design
            log.warning("webhook %s failed (attempt %d): %s",
                        row["webhook_url"], attempt, e)
        time.sleep(2 ** attempt)
    log.error("webhook %s undelivered after %d attempts (scan %s)",
              row["webhook_url"], WEBHOOK_ATTEMPTS, scan_id)


@celery_app.task(name="braimsec.run_scan", bind=True, max_retries=2,
                 soft_time_limit=SCAN_SOFT_LIMIT_S)
def run_scan(self, scan_id: str, target_dir: str, cleanup_dir: str | None = None,
             baseline_scan_id: str | None = None):
    """Run both engines, store normalized findings. Idempotent on retry."""
    return _run_scan_impl(self, scan_id, target_dir, cleanup_dir,
                          baseline_scan_id)


def _relpath(target_dir, p):
    """Normalize an engine-reported path to a relpath under target_dir."""
    if not p:
        return p
    ap = p if os.path.isabs(p) else os.path.join(target_dir, p)
    return os.path.relpath(ap, target_dir)


def _run_incremental(db, scan_id, org_id, target_dir, baseline_scan_id):
    """Diff-based rescan against a baseline scan's fingerprint.

    Returns (findings, incremental_of). Raises RuntimeError (→ failed scan,
    no retry) on baseline problems: the baseline must exist, be complete,
    and belong to the same org.
    """
    from incremental import (fingerprint_tree, plan_incremental,
                             merge_findings, SCANABLE_EXTS)
    brow = db.execute(
        "SELECT fingerprint_json, org_id, status FROM scans WHERE id=?",
        (baseline_scan_id,)).fetchone()
    if brow is None:
        raise RuntimeError(f"baseline scan not found: {baseline_scan_id}")
    if brow["org_id"] != org_id:
        raise RuntimeError("baseline scan belongs to another organization")
    if brow["status"] != "done":
        raise RuntimeError(
            f"baseline scan is not complete (status={brow['status']})")
    try:
        old_fp = json.loads(brow["fingerprint_json"] or "{}")
    except (json.JSONDecodeError, TypeError):
        old_fp = {}
    old_rows = db.execute(
        "SELECT tool, rule_id, severity, message, file, line, col,"
        " ai_verdict, ai_confidence, ai_explanation, ai_fix"
        " FROM findings WHERE scan_id=?", (baseline_scan_id,)).fetchall()
    # Carried findings keep their AI review: the code did not change, so the
    # verdict stands — and the AI-review quota is not re-spent on it.
    old_findings = [{**dict(r),
                     "file": _relpath(target_dir, r["file"])} for r in old_rows]

    new_fp = fingerprint_tree(target_dir)
    plan = plan_incremental(old_fp, new_fp, target_dir)
    if plan["no_change"]:
        # Fast path: nothing changed — carry every finding, run no engines.
        return old_findings, baseline_scan_id

    scope_abs = [os.path.join(target_dir, rel)
                 for rel in plan["scope_files"]
                 if os.path.isfile(os.path.join(target_dir, rel))]
    # Semgrep only scans code; gitleaks re-checks every changed file
    # (a changed manifest could theoretically gain a secret).
    code_scope = [p for p in scope_abs if p.endswith(SCANABLE_EXTS)]
    if sandbox_mode() == "docker":
        # One sandboxed run over the union scope; SCA stays on the host
        # (it needs the OSV network). run_scan_isolated returns
        # host-absolute paths, same as the local engines.
        fresh = run_scan_isolated(target_dir, scope_abs)
    else:
        fresh = run_semgrep(target_dir, code_scope) \
            + run_gitleaks(target_dir, scope_abs)
    if plan["sca_needed"]:
        fresh += run_sca(target_dir)
    # else: manifests unchanged → SCA skipped. A periodic full SCA is still
    # required to catch newly published CVEs on old packages.
    for f in fresh:
        f["file"] = _relpath(target_dir, f["file"])
    merged = merge_findings(old_findings, fresh, set(plan["scope_files"]))
    # NB: invalidation covers the whole scope (not just changed files):
    # import-hop neighbors are rescanned, so their old findings must not
    # be carried alongside the fresh ones (that would duplicate them).
    return merged, baseline_scan_id


def _run_scan_impl(task_self, scan_id: str, target_dir: str,
                   cleanup_dir: str | None = None,
                   baseline_scan_id: str | None = None):
    """Task body as a plain function (testable without Celery machinery).

    baseline_scan_id: run incrementally against that scan's fingerprint
    baseline (diff-based rescan). Requires a persistent target_path —
    zip uploads are always full scans.
    """
    from incremental import fingerprint_tree
    db = get_db()
    will_retry = False
    try:
        # Idempotency: a redelivered task must not duplicate findings.
        db.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        db.execute("UPDATE scans SET status='running', started_at=? WHERE id=?",
                   (_now_iso(), scan_id))
        db.commit()
        scan_row = db.execute("SELECT org_id FROM scans WHERE id=?",
                              (scan_id,)).fetchone()
        org_id = scan_row["org_id"] if scan_row else None
        incremental_of = None
        if baseline_scan_id:
            findings, incremental_of = _run_incremental(
                db, scan_id, org_id, target_dir, baseline_scan_id)
        else:
            if sandbox_mode() == "docker":
                # semgrep+gitleaks run isolated in the sandbox container;
                # SCA stays on the host (manifest parsing + OSV lookups
                # need the network and never execute target code).
                # A ContainerError fails the scan loudly: docker mode must
                # never silently degrade to an un-isolated scan.
                findings = (run_scan_isolated(target_dir)
                            + run_sca(target_dir))
            else:
                findings = (run_semgrep(target_dir)
                            + run_gitleaks(target_dir)
                            + run_sca(target_dir))
        for f in findings:
            db.execute(
                """INSERT INTO findings
                   (scan_id, tool, rule_id, severity, message, file, line, col,
                    ai_verdict, ai_confidence, ai_explanation, ai_fix)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, f["tool"], f["rule_id"], f["severity"],
                 f["message"], f["file"], f["line"], f["col"],
                 f.get("ai_verdict"), f.get("ai_confidence"),
                 f.get("ai_explanation"), f.get("ai_fix")),
            )
        db.execute(
            "UPDATE scans SET status='done', finished_at=?, total_findings=?,"
            " fingerprint_json=?, incremental_of=?, engines_json=? WHERE id=?",
            (_now_iso(), len(findings),
             json.dumps(fingerprint_tree(target_dir)), incremental_of,
             json.dumps(_engine_versions()), scan_id),
        )
        db.commit()
        _audit_scan_terminal(db, scan_id, "scan.completed",
                             {"total_findings": len(findings)})
    except Exception as e:  # noqa: BLE001 - prototype: record failure
        # A timed-out scan is not transient: retrying would burn two more
        # full time-limit windows. Fail it outright.
        timed_out = isinstance(e, SoftTimeLimitExceeded)
        if timed_out or task_self.request.retries >= (task_self.max_retries or 0):
            error = (f"scan exceeded the {SCAN_SOFT_LIMIT_S}s time limit"
                     if timed_out else str(e))
            db.execute(
                "UPDATE scans SET status='failed', finished_at=?, error=?"
                " WHERE id=?", (_now_iso(), error, scan_id))
            db.commit()
            _audit_scan_terminal(db, scan_id, "scan.failed",
                                 {"error": error[:200]})
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
        # Scheduled scans: diff vs the previous scheduled run and fire the
        # new-findings alert webhook. Best-effort: alerting must never break
        # scan completion.
        try:
            from scheduler import evaluate_schedule_alerts  # noqa: E402
            evaluate_schedule_alerts(scan_id)
        except Exception:  # noqa: BLE001
            log.exception("schedule alert evaluation failed for scan %s",
                          scan_id)
        # VCS (push-triggered) scans: same treatment vs the previous push scan.
        try:
            from vcs import evaluate_vcs_alerts  # noqa: E402
            evaluate_vcs_alerts(scan_id)
        except Exception:  # noqa: BLE001
            log.exception("vcs alert evaluation failed for scan %s",
                          scan_id)


@celery_app.task(name="braimsec.run_ai_review", bind=True, max_retries=2,
                 soft_time_limit=AI_REVIEW_SOFT_LIMIT_S)
def run_ai_review(self, scan_id: str):
    """LLM second-opinion review of every finding.

    Each reviewed finding consumes one unit of the org's monthly AI-review
    quota (the real variable cost) and is recorded in the usage ledger.
    """
    return _run_ai_review_impl(self, scan_id)


def _run_ai_review_impl(task_self, scan_id: str):
    """Task body as a plain function (testable without Celery machinery)."""
    client = make_llm_client()
    db = get_db()
    will_retry = False
    sink_summary = {"status": "skipped", "sites": 0, "candidates": 0,
                    "audited": 0, "confirmed": 0, "skipped_quota": 0}
    try:
        scan = db.execute("SELECT org_id, target_dir FROM scans WHERE id=?",
                          (scan_id,)).fetchone()
        org_id = scan["org_id"] if scan else None
        target_dir = scan["target_dir"] if scan else None
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
        # --- High-risk sink auditing: proactive second pass over dangerous
        # sinks (SSRF, command injection, ...) that no scanner rule fired on.
        # Each AI call spends one ai_review quota unit — the same pool as
        # finding reviews. Findings created here are pre-reviewed, so the
        # pending-findings loop above (ai_verdict IS NULL) never re-bills them.
        if sink_audit_enabled() and client.configured:
            if not (target_dir and os.path.isdir(target_dir)):
                # Sources gone (e.g. cleaned-up zip upload): nothing to hunt.
                sink_summary["status"] = "skipped_no_sources"
            else:
                try:
                    sites = discover_sinks(target_dir)
                except Exception as e:  # noqa: BLE001 - fail-soft
                    log.warning("sink discovery failed for scan %s: %s",
                                scan_id, e)
                    sites = []
                candidates = audit_candidates(sites)
                sink_summary.update(status="audited", sites=len(sites),
                                    candidates=len(candidates))
                new_findings = 0
                for idx, site in enumerate(candidates):
                    if org_id:
                        allowed, _, _ = quota_check(org_id, "ai_review", 1)
                        if not allowed:
                            # Quota exhausted mid-pass: count the rest as skipped.
                            sink_summary["skipped_quota"] = len(candidates) - idx
                            break
                    snippet = read_snippet(site["file"], site["line"], radius=30)
                    t0 = time.monotonic()
                    try:
                        res = analyze_sink(client, site, snippet)
                    except Exception as e:  # noqa: BLE001 - one bad site != dead job
                        log.warning("sink audit failed at %s:%s: %s",
                                    site["file"], site["line"], e)
                        continue
                    wall_ms = int((time.monotonic() - t0) * 1000)
                    sink_summary["audited"] += 1
                    if org_id:
                        record_usage(org_id, "ai_review", scan_id,
                                     wall_time_ms=wall_ms)
                    if not should_store(res):
                        continue
                    # Idempotency: a retried job must not duplicate sink findings.
                    dup = db.execute(
                        "SELECT 1 FROM findings WHERE scan_id=? AND tool='sink-audit'"
                        " AND rule_id=? AND file=? AND line=?",
                        (scan_id, site["category"] + "-sink",
                         site["file"], site["line"])).fetchone()
                    if dup:
                        continue
                    db.execute(
                        """INSERT INTO findings
                           (scan_id, tool, rule_id, severity, message, file, line, col,
                            ai_verdict, ai_confidence, ai_explanation, ai_fix)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (scan_id, "sink-audit", site["category"] + "-sink",
                         site["severity"], res["ai_explanation"], site["file"],
                         site["line"], site["col"], res["ai_verdict"],
                         res["ai_confidence"], res["ai_explanation"],
                         res["ai_fix"]),
                    )
                    db.commit()
                    new_findings += 1
                if new_findings:
                    db.execute("UPDATE scans SET total_findings = total_findings + ?"
                               " WHERE id=?", (new_findings, scan_id))
                    db.commit()
                sink_summary["confirmed"] = new_findings
        elif not sink_audit_enabled():
            sink_summary["status"] = "disabled"
        else:
            sink_summary["status"] = "skipped_no_llm"
    except Exception as e:  # noqa: BLE001
        if isinstance(e, RuntimeError) and task_self.request.retries < (task_self.max_retries or 0):
            will_retry = True
            raise task_self.retry(exc=e, countdown=2 ** task_self.request.retries * 30)
        log.error("ai review job %s failed: %s", scan_id, e)
    finally:
        db.close()
    return {"scan_id": scan_id, "will_retry": will_retry,
            "sink_audit": sink_summary}


def enqueue_scan(scan_id: str, target_dir: str, cleanup_dir: str | None,
                 background_tasks=None, baseline_scan_id: str | None = None) -> str:
    """Route a scan to the durable queue, or inline when unconfigured.

    Returns "celery" or "inline" so callers (and tests) can observe routing.
    """
    if queue_enabled():
        run_scan.delay(scan_id, target_dir, cleanup_dir, baseline_scan_id)
        return "celery"
    if background_tasks is not None:
        background_tasks.add_task(run_scan, scan_id, target_dir, cleanup_dir,
                                  baseline_scan_id)
    else:
        run_scan(scan_id, target_dir, cleanup_dir, baseline_scan_id)
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


@celery_app.task(name="braimsec.check_schedules")
def check_schedules():
    """Celery beat (every 60s): run due scheduled scans and reports.

    Idempotent: ``scheduler.run_scheduler_once`` and
    ``scheduled_reports.run_report_scheduler_once`` claim each due
    schedule with a conditional UPDATE, so overlapping beat instances
    never double-run. In dev without a broker, call it directly instead.
    """
    from scheduler import run_scheduler_once  # noqa: E402
    from scheduled_reports import run_report_scheduler_once  # noqa: E402
    from cert_monitor import run_cert_checks_once  # noqa: E402
    from uptime_monitor import run_uptime_checks_once  # noqa: E402
    from uptime_digest import run_digests_once  # noqa: E402
    return {"scans": run_scheduler_once(),
            "reports": run_report_scheduler_once(),
            "certs": run_cert_checks_once(),
            "uptime": run_uptime_checks_once(),
            "digests": run_digests_once()}


def enqueue_vcs_ingest(repo_id: str, sha: str,
                       background_tasks=None) -> str:
    """Route a VCS push ingest to the durable queue, or inline when unconfigured.

    Returns "celery" or "inline" so callers (and tests) can observe routing.
    """
    if queue_enabled():
        vcs_ingest.delay(repo_id, sha)
        return "celery"
    if background_tasks is not None:
        background_tasks.add_task(_vcs_ingest_inline, repo_id, sha)
    else:
        _vcs_ingest_inline(repo_id, sha)
    return "inline"


def _vcs_ingest_inline(repo_id: str, sha: str):
    from vcs import _ingest_vcs_push  # noqa: E402
    return _ingest_vcs_push(repo_id, sha)


@celery_app.task(name="braimsec.vcs_ingest", bind=True, max_retries=0,
                 soft_time_limit=600)
def vcs_ingest(self, repo_id: str, sha: str):
    """Celery task: clone a pushed commit and create a scan for it."""
    from vcs import _ingest_vcs_push  # noqa: E402
    return _ingest_vcs_push(repo_id, sha)
