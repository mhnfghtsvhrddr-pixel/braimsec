"""Scheduled maintenance windows.

An org can schedule a maintenance window (optionally scoped to specific
uptime targets, otherwise covering all of them). While a window is active:

- ``uptime.down`` alerts for covered targets are *suppressed* — recorded in
  the notifications log with ``status='suppressed'`` and
  ``channel='maintenance'`` so the alerts log stays honest, but nothing is
  sent and no incident auto-opens.
- Probes keep running and the daily aggregates keep recording (the
  90-day bars reflect reality).
- The public status page shows active and upcoming windows prominently.

Window status is derived lazily from the clock (scheduled/active/
completed/cancelled) — no background transition needed.
"""

import json
import logging
import time
from datetime import datetime, timedelta, timezone

log = logging.getLogger("braimsec.maintenance")

MAX_DURATION_DAYS = 30
MAX_AHEAD_DAYS = 365
UPCOMING_PUBLIC_DAYS = 7


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def _parse_iso(value: str, field: str) -> datetime:
    try:
        dt = datetime.fromisoformat(str(value).strip())
    except (ValueError, AttributeError):
        raise ValueError(f"{field} must be ISO 8601 datetime")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def validate_window(starts_at: str, ends_at: str):
    start = _parse_iso(starts_at, "starts_at")
    end = _parse_iso(ends_at, "ends_at")
    if end <= start:
        raise ValueError("ends_at must be after starts_at")
    if (end - start) > timedelta(days=MAX_DURATION_DAYS):
        raise ValueError(f"window too long (max {MAX_DURATION_DAYS} days)")
    now = datetime.now(timezone.utc)
    if start > now + timedelta(days=MAX_AHEAD_DAYS):
        raise ValueError("starts_at too far in the future")
    return start, end


def _validate_target_ids(db, org_id: str, target_ids) -> list[int]:
    if target_ids is None:
        return []
    if not isinstance(target_ids, list):
        raise ValueError("target_ids must be a list")
    ids = []
    for tid in target_ids:
        try:
            tid = int(tid)
        except (TypeError, ValueError):
            raise ValueError(f"bad target id: {tid!r}")
        ok = db.execute("SELECT id FROM uptime_targets WHERE id=?"
                        " AND org_id=?", (tid, org_id)).fetchone()
        if ok is None:
            raise ValueError(f"target not found: {tid}")
        ids.append(tid)
    return sorted(set(ids))


def derived_status(window: dict,
                   now: datetime | None = None) -> str:
    """scheduled|active|completed|cancelled from the stored row + clock."""
    if window["status"] == "cancelled":
        return "cancelled"
    now = now or datetime.now(timezone.utc)
    start = datetime.fromisoformat(window["starts_at"])
    end = datetime.fromisoformat(window["ends_at"])
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if now >= end:
        return "completed"
    if now >= start:
        return "active"
    return "scheduled"


def _with_status(row: dict) -> dict:
    row = dict(row)
    row["status"] = derived_status(row)
    row["target_ids"] = json.loads(row["target_ids_json"] or "[]")
    del row["target_ids_json"]
    return row


def create_window(db, org_id: str, title: str, starts_at: str,
                  ends_at: str, description: str = "",
                  target_ids=None, created_by: str = "") -> dict:
    title = (title or "").strip()
    if not title:
        raise ValueError("title is required")
    if len(title) > 200:
        raise ValueError("title too long (max 200)")
    start, end = validate_window(starts_at, ends_at)
    ids = _validate_target_ids(db, org_id, target_ids)
    now = _now_iso()
    cur = db.execute(
        "INSERT INTO maintenance_windows (org_id, title, description,"
        " target_ids_json, starts_at, ends_at, status, created_by,"
        " created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (org_id, title, (description or "").strip()[:2000],
         json.dumps(ids), start.isoformat(timespec="seconds"),
         end.isoformat(timespec="seconds"), "scheduled",
         created_by or "", now))
    db.commit()
    return get_window(db, cur.lastrowid, org_id)


def get_window(db, window_id: int, org_id: str) -> dict | None:
    r = db.execute("SELECT * FROM maintenance_windows WHERE id=?"
                   " AND org_id=?", (window_id, org_id)).fetchone()
    return _with_status(r) if r else None


def list_windows(db, org_id: str, include_past: bool = False) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM maintenance_windows WHERE org_id=?"
        " ORDER BY starts_at DESC", (org_id,)).fetchall()
    out = [_with_status(r) for r in rows]
    if not include_past:
        out = [w for w in out if w["status"] in ("scheduled", "active")]
    return out


def update_window(db, window_id: int, org_id: str, **fields) -> dict:
    row = db.execute("SELECT * FROM maintenance_windows WHERE id=?"
                     " AND org_id=?", (window_id, org_id)).fetchone()
    if row is None:
        raise KeyError("window not found")
    if derived_status(dict(row)) != "scheduled":
        raise ValueError("only scheduled windows can be edited")
    sets, args = [], []
    if "title" in fields:
        title = (fields["title"] or "").strip()
        if not title:
            raise ValueError("title is required")
        if len(title) > 200:
            raise ValueError("title too long (max 200)")
        sets.append("title=?")
        args.append(title)
    if "description" in fields:
        sets.append("description=?")
        args.append((fields["description"] or "").strip()[:2000])
    new_start = fields.get("starts_at", row["starts_at"])
    new_end = fields.get("ends_at", row["ends_at"])
    if "starts_at" in fields or "ends_at" in fields:
        start, end = validate_window(new_start, new_end)
        sets.append("starts_at=?")
        args.append(start.isoformat(timespec="seconds"))
        sets.append("ends_at=?")
        args.append(end.isoformat(timespec="seconds"))
    if "target_ids" in fields:
        ids = _validate_target_ids(db, org_id, fields["target_ids"])
        sets.append("target_ids_json=?")
        args.append(json.dumps(ids))
    if not sets:
        raise ValueError("nothing to update")
    args.append(window_id)
    db.execute(f"UPDATE maintenance_windows SET {', '.join(sets)}"
               " WHERE id=?", args)
    db.commit()
    return get_window(db, window_id, org_id)


def cancel_window(db, window_id: int, org_id: str) -> dict:
    row = db.execute("SELECT * FROM maintenance_windows WHERE id=?"
                     " AND org_id=?", (window_id, org_id)).fetchone()
    if row is None:
        raise KeyError("window not found")
    if derived_status(dict(row)) not in ("scheduled", "active"):
        raise ValueError("only scheduled/active windows can be cancelled")
    db.execute("UPDATE maintenance_windows SET status='cancelled'"
               " WHERE id=?", (window_id,))
    db.commit()
    return get_window(db, window_id, org_id)


def delete_window(db, window_id: int, org_id: str):
    row = db.execute("SELECT * FROM maintenance_windows WHERE id=?"
                     " AND org_id=?", (window_id, org_id)).fetchone()
    if row is None:
        raise KeyError("window not found")
    db.execute("DELETE FROM maintenance_windows WHERE id=?", (window_id,))
    db.commit()


def active_windows(db, org_id: str,
                   now: datetime | None = None) -> list[dict]:
    """Windows active right now (for alert suppression)."""
    now = now or datetime.now(timezone.utc)
    iso = now.isoformat(timespec="seconds")
    rows = db.execute(
        "SELECT * FROM maintenance_windows WHERE org_id=?"
        " AND status != 'cancelled' AND starts_at <= ? AND ends_at > ?",
        (org_id, iso, iso)).fetchall()
    return [_with_status(r) for r in rows]


def is_target_in_maintenance(db, org_id: str, target_id: int,
                             now: datetime | None = None) -> dict | None:
    """Return the covering active window, or None. Empty target list =
    the window covers all targets."""
    for w in active_windows(db, org_id, now):
        if not w["target_ids"] or target_id in w["target_ids"]:
            return w
    return None


def public_windows(db, org_id: str,
                   now: datetime | None = None) -> list[dict]:
    """Active + upcoming (7d) windows for the public status page."""
    now = now or datetime.now(timezone.utc)
    horizon = (now + timedelta(days=UPCOMING_PUBLIC_DAYS)).isoformat(
        timespec="seconds")
    iso = now.isoformat(timespec="seconds")
    rows = db.execute(
        "SELECT * FROM maintenance_windows WHERE org_id=?"
        " AND status != 'cancelled'"
        " AND ((starts_at <= ? AND ends_at > ?) OR"
        "      (starts_at > ? AND starts_at <= ?))"
        " ORDER BY starts_at",
        (org_id, iso, iso, iso, horizon)).fetchall()
    out = []
    for r in rows:
        w = _with_status(r)
        out.append({k: w[k] for k in
                    ("id", "title", "description", "starts_at", "ends_at",
                     "status")})
    return out
