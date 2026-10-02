"""Enterprise audit trail for BraimSec.

Append-only by convention: this module exposes a single writer
(:func:`log_event`) and read helpers. The one sanctioned exception is
:func:`archive_events`, which moves rows older than the retention
cutoff into tamper-evident gzipped archives and deletes them from the
hot table — the run itself is logged as ``audit_log.archived``, so the
trail never loses track of its own pruning.

What gets logged (v1 — the CISO surface):
- scan.created / scan.completed / scan.failed
- ai_review.requested / fix_suggestion.requested / patch_verify.requested
- finding.triaged / finding.triaged_bulk
- api_key.created / api_key.revoked
- audit_log.archived

``actor`` is an API key prefix (``bs_xxxxxxxx``), ``'owner'`` for the
master key, or ``'system'`` for background/checkout flows. The full key
secret never enters the log.
"""
import gzip
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from database import get_db

# Actions the audit trail records. Centralized so the read API and tests
# can validate action names instead of scattering string literals.
ACTIONS = frozenset({
    "scan.created",
    "scan.completed",
    "scan.failed",
    "ai_review.requested",
    "fix_suggestion.requested",
    "patch_verify.requested",
    "finding.triaged",
    "finding.triaged_bulk",
    "api_key.created",
    "api_key.revoked",
    "project.created",
    "project.deleted",
    "audit_log.archived",
    "schedule.created",
    "schedule.updated",
    "schedule.deleted",
    "schedule.run",
    "report_schedule.created",
    "report_schedule.updated",
    "report_schedule.deleted",
    "report_schedule.run",
    "vcs.repo.created",
    "vcs.repo.updated",
    "vcs.repo.deleted",
    "vcs.repo.secret_rotated",
    "vcs.scan.created",
    "alert_email.added",
    "alert_email.toggled",
    "alert_email.removed",
    "telegram_chat.added",
    "telegram_chat.removed",
    "slack_webhook.added",
    "slack_webhook.removed",
    "teams_webhook.added",
    "teams_webhook.removed",
    "webhook_signing.rotated",
    "notification.resent",
    "cert_domain.added",
    "cert_domain.updated",
    "cert_domain.removed",
    "cert_domain.alerted",
    "uptime_target.added",
    "uptime_target.updated",
    "uptime_target.removed",
    "uptime_target.down",
    "uptime_target.recovered",
    "status_page.created",
    "status_page.updated",
    "status_page.deleted",
    "incident.created",
    "incident.updated",
    "incident.resolved",
    "incident.removed",
    "incident_update.added",
    "maintenance.created",
    "maintenance.updated",
    "maintenance.deleted",
    "maintenance.cancelled",
    "maintenance.alert_suppressed",
})

# Archival never touches recent history: the window must be at least
# this many days old, so a misclick cannot nuke yesterday's trail.
ARCHIVE_MIN_DAYS = 1


def _archive_root():
    # Read lazily (not at import) so tests can point it at a temp dir.
    return os.environ.get(
        "BRAIMSEC_ARCHIVE_ROOT",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "archives"),
    )


def _default_retention_days():
    try:
        return max(ARCHIVE_MIN_DAYS,
                   int(os.environ.get("BRAIMSEC_AUDIT_RETENTION_DAYS", "90")))
    except (TypeError, ValueError):
        return 90


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_event(org_id: str, actor: str, action: str,
              resource_type: str = "", resource_id: str = "",
              detail: dict | None = None, ip: str = "",
              db=None) -> int:
    """Append one audit record. Returns the row id.

    Unknown actions raise ValueError — the action vocabulary is closed
    so dashboards and SIEM exports can rely on it.

    ``db``: optional caller-managed sqlite3 connection. When given, the
    INSERT joins the caller's transaction (no commit/close here) — use
    this when the audit record must commit atomically with other writes
    (a second connection would hit "database is locked"). When omitted,
    the event is committed on its own connection as before.
    """
    if action not in ACTIONS:
        raise ValueError(f"unknown audit action: {action!r}")
    own = db is None
    if own:
        db = get_db()
    try:
        cur = db.execute(
            """INSERT INTO audit_log
               (org_id, actor, action, resource_type, resource_id,
                detail, ip, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (org_id, actor or "", action, resource_type, resource_id,
             json.dumps(detail or {}, ensure_ascii=False), ip or "", _now()),
        )
        if own:
            db.commit()
        return cur.lastrowid
    finally:
        if own:
            db.close()


def read_events(org_id: str, limit: int = 50, offset: int = 0,
                action: str | None = None) -> list[dict]:
    """Newest-first audit records for one org (org isolation enforced)."""
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    db = get_db()
    try:
        if action:
            rows = db.execute(
                """SELECT * FROM audit_log
                   WHERE org_id=? AND action=?
                   ORDER BY id DESC LIMIT ? OFFSET ?""",
                (org_id, action, limit, offset)).fetchall()
        else:
            rows = db.execute(
                """SELECT * FROM audit_log WHERE org_id=?
                   ORDER BY id DESC LIMIT ? OFFSET ?""",
                (org_id, limit, offset)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except (json.JSONDecodeError, TypeError):
                d["detail"] = {}
            out.append(d)
        return out
    finally:
        db.close()


def archive_events(org_id: str, actor: str, older_than_days: int | None = None,
                   archive_root: str | None = None) -> dict:
    """Move audit rows older than the cutoff into a tamper-evident archive.

    Crash-safety ordering (documented, not just hoped for):
    1. SELECT the rows (read-only).
    2. Write them to ``{root}/{org_id}/{archive_id}.jsonl.gz``, fsync,
       sha256, atomic rename. Nothing in the DB changes yet.
    3. ONE transaction: INSERT the manifest, DELETE the rows, log
       ``audit_log.archived`` — single commit. The DELETE's rowcount is
       checked against the SELECT: a concurrent archive run that stole
       the rows makes this one abort instead of writing a lying manifest.
    4. If step 3 fails: rollback, best-effort delete the file, raise.
       A manifest without a file, or a file without a manifest, cannot
       survive this function.

    Returns {"archived": n, "archive_id": ..., "sha256": ..., ...}.
    With no rows older than the cutoff it returns {"archived": 0,
    "archive_id": None} and writes nothing.

    Raises ValueError for a window smaller than ARCHIVE_MIN_DAYS.
    """
    if older_than_days is None:
        older_than_days = _default_retention_days()
    if older_than_days < ARCHIVE_MIN_DAYS:
        raise ValueError(
            f"older_than_days must be >= {ARCHIVE_MIN_DAYS}")
    root = archive_root or _archive_root()
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=older_than_days)).isoformat(timespec="seconds")

    db = get_db()
    try:
        rows = db.execute(
            """SELECT * FROM audit_log
               WHERE org_id=? AND created_at < ?
               ORDER BY id""",
            (org_id, cutoff)).fetchall()
    finally:
        db.close()
    if not rows:
        return {"archived": 0, "archive_id": None}

    archive_id = "arc_" + uuid.uuid4().hex[:12]
    org_dir = os.path.join(root, org_id)
    os.makedirs(org_dir, exist_ok=True)
    final = os.path.join(org_dir, archive_id + ".jsonl.gz")
    tmp = final + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8") as gz:
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except (json.JSONDecodeError, TypeError):
                d["detail"] = {}
            gz.write(json.dumps(d, ensure_ascii=False) + "\n")
    with open(tmp, "rb") as fh:
        os.fsync(fh.fileno())
        digest = hashlib.sha256(fh.read()).hexdigest()
    os.replace(tmp, final)

    first_id, last_id = rows[0]["id"], rows[-1]["id"]
    filename = os.path.join(org_id, archive_id + ".jsonl.gz")
    db = get_db()
    try:
        db.execute(
            """INSERT INTO audit_archives
               (id, org_id, created_at, actor, cutoff, row_count,
                sha256, filename, first_id, last_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (archive_id, org_id, _now(), actor or "", cutoff, len(rows),
             digest, filename, first_id, last_id),
        )
        cur = db.execute(
            "DELETE FROM audit_log WHERE org_id=? AND created_at < ?",
            (org_id, cutoff))
        if cur.rowcount != len(rows):
            # A concurrent archive run deleted some of these rows first;
            # abort rather than record a manifest that lies about content.
            raise RuntimeError("concurrent archive run modified the row set")
        log_event(org_id, actor, "audit_log.archived", "audit_archive",
                  archive_id,
                  {"rows": len(rows), "cutoff": cutoff, "sha256": digest,
                   "first_id": first_id, "last_id": last_id}, "", db=db)
        db.commit()
    except Exception:
        db.rollback()
        try:
            os.remove(final)
        except OSError:
            pass
        raise
    finally:
        db.close()
    return {"archived": len(rows), "archive_id": archive_id,
            "sha256": digest, "filename": filename,
            "first_id": first_id, "last_id": last_id}


def list_archives(org_id: str) -> list[dict]:
    """Newest-first archive manifests for one org."""
    db = get_db()
    try:
        return [dict(r) for r in db.execute(
            "SELECT * FROM audit_archives WHERE org_id=? ORDER BY id DESC",
            (org_id,)).fetchall()]
    finally:
        db.close()


def verify_archive(org_id: str, archive_id: str,
                   archive_root: str | None = None) -> dict:
    """Re-hash an archive file and compare with its manifest.

    Returns {"archive_id": ..., "match": bool, ...}. A missing file is
    reported as match=False with a reason, not an exception — the point
    of verification is to surface exactly that.
    """
    db = get_db()
    try:
        row = db.execute(
            "SELECT * FROM audit_archives WHERE id=? AND org_id=?",
            (archive_id, org_id)).fetchone()
    finally:
        db.close()
    if not row:
        raise KeyError(f"no such archive: {archive_id}")
    manifest = dict(row)
    root = archive_root or _archive_root()
    # Filenames are server-generated, but normalize anyway: an archive
    # must never resolve outside the archive root.
    path = os.path.realpath(os.path.join(root, manifest["filename"]))
    if not path.startswith(os.path.realpath(root) + os.sep):
        return {"archive_id": archive_id, "match": False,
                "reason": "path escapes archive root",
                "expected_sha256": manifest["sha256"]}
    try:
        with open(path, "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
    except FileNotFoundError:
        return {"archive_id": archive_id, "match": False,
                "reason": "archive file missing",
                "expected_sha256": manifest["sha256"]}
    return {"archive_id": archive_id, "match": actual == manifest["sha256"],
            "expected_sha256": manifest["sha256"],
            "actual_sha256": actual,
            "row_count": manifest["row_count"]}
