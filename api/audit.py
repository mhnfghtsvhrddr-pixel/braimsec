"""Enterprise audit trail for BraimSec.

Append-only by convention: this module exposes a single writer
(:func:`log_event`) and read helpers. No UPDATE/DELETE against
``audit_log`` exists anywhere in the codebase.

What gets logged (v1 — the CISO surface):
- scan.created / scan.completed / scan.failed
- ai_review.requested / fix_suggestion.requested / patch_verify.requested
- api_key.created / api_key.revoked

``actor`` is an API key prefix (``bs_xxxxxxxx``), ``'owner'`` for the
master key, or ``'system'`` for background/checkout flows. The full key
secret never enters the log.
"""
import json
import sqlite3
from datetime import datetime, timezone

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
    "api_key.created",
    "api_key.revoked",
})


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_event(org_id: str, actor: str, action: str,
              resource_type: str = "", resource_id: str = "",
              detail: dict | None = None, ip: str = "") -> int:
    """Append one audit record. Returns the row id.

    Unknown actions raise ValueError — the action vocabulary is closed
    so dashboards and SIEM exports can rely on it.
    """
    if action not in ACTIONS:
        raise ValueError(f"unknown audit action: {action!r}")
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
        db.commit()
        return cur.lastrowid
    finally:
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
