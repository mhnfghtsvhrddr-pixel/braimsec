"""Public status pages + incident log, built on top of uptime monitoring.

An org can publish a public status page (``/status/<slug>``) showing the
live state of its uptime targets, 90-day uptime bars, active incidents and
recent history — the same kind of page SaaS companies publish for their
own customers.

Incidents are *automatic*: when ``uptime.down`` fires, an incident opens
for that target (idempotent — one open incident per target); when
``uptime.recovered`` fires, open incidents for the target auto-resolve
with a closing update. Orgs can also manage incidents manually through
the API and the dashboard.

Public endpoints are read-only and expose no auth material: only enabled
pages, only targets of that org, only public incidents and their updates.

Daily aggregates (``uptime_daily``) keep the 90-day bars cheap: one row
per target per UTC day. Rows older than :data:`DAILY_RETENTION_DAYS` are
pruned by the beat sweep.
"""

import logging
import re
import time
from datetime import datetime, timedelta, timezone

log = logging.getLogger("braimsec.status")

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,58}[a-z0-9]$")
DAILY_RETENTION_DAYS = 120
PUBLIC_HISTORY_DAYS = 90
PUBLIC_INCIDENT_HISTORY_DAYS = 30

INCIDENT_STATUSES = ("investigating", "identified", "monitoring", "resolved")
INCIDENT_IMPACTS = ("none", "minor", "major", "critical")
OPEN_STATUSES = ("investigating", "identified", "monitoring")

STATUS_AR = {
    "investigating": "قيد التحقيق",
    "identified": "تم تحديد المشكلة",
    "monitoring": "قيد المراقبة",
    "resolved": "تم الحل",
}
IMPACT_AR = {
    "none": "بلا تأثير",
    "minor": "تأثير بسيط",
    "major": "تأثير كبير",
    "critical": "تأثير حرج",
}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def validate_slug(slug: str) -> str:
    s = (slug or "").strip().lower()
    if not SLUG_RE.match(s):
        raise ValueError("slug must be 3..60 chars: lowercase letters, "
                         "digits and hyphens")
    return s


# ---------------------------------------------------------------------------
# Status pages
# ---------------------------------------------------------------------------

def list_pages(db, org_id: str) -> list[dict]:
    return [dict(r) for r in db.execute(
        "SELECT * FROM status_pages WHERE org_id=? ORDER BY created_at",
        (org_id,)).fetchall()]


def get_page_by_slug(db, slug: str) -> dict | None:
    r = db.execute("SELECT * FROM status_pages WHERE slug=?",
                   (slug,)).fetchone()
    return dict(r) if r else None


def create_page(db, org_id: str, title: str, slug: str,
                headline: str = "", enabled: bool = True) -> dict:
    title = (title or "").strip()
    if not title:
        raise ValueError("title is required")
    if len(title) > 120:
        raise ValueError("title too long (max 120)")
    slug = validate_slug(slug)
    headline = (headline or "").strip()[:500]
    if db.execute("SELECT id FROM status_pages WHERE slug=?",
                  (slug,)).fetchone():
        raise ValueError("slug already taken")
    cur = db.execute(
        "INSERT INTO status_pages (org_id, title, slug, headline, enabled,"
        " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
        (org_id, title, slug, headline, 1 if enabled else 0,
         _now_iso(), _now_iso()))
    db.commit()
    return dict(db.execute("SELECT * FROM status_pages WHERE id=?",
                           (cur.lastrowid,)).fetchone())


def update_page(db, page_id: int, org_id: str, **fields) -> dict:
    row = db.execute("SELECT * FROM status_pages WHERE id=? AND org_id=?",
                     (page_id, org_id)).fetchone()
    if row is None:
        raise KeyError("page not found")
    sets, args = [], []
    if "title" in fields:
        title = (fields["title"] or "").strip()
        if not title:
            raise ValueError("title is required")
        if len(title) > 120:
            raise ValueError("title too long (max 120)")
        sets.append("title=?")
        args.append(title)
    if "slug" in fields:
        slug = validate_slug(fields["slug"])
        taken = db.execute("SELECT id FROM status_pages WHERE slug=?"
                           " AND id!=?", (slug, page_id)).fetchone()
        if taken:
            raise ValueError("slug already taken")
        sets.append("slug=?")
        args.append(slug)
    if "headline" in fields:
        sets.append("headline=?")
        args.append((fields["headline"] or "").strip()[:500])
    if "enabled" in fields:
        sets.append("enabled=?")
        args.append(1 if fields["enabled"] else 0)
    if not sets:
        raise ValueError("nothing to update")
    sets.append("updated_at=?")
    args.append(_now_iso())
    args.append(page_id)
    db.execute(f"UPDATE status_pages SET {', '.join(sets)} WHERE id=?",
               args)
    db.commit()
    return dict(db.execute("SELECT * FROM status_pages WHERE id=?",
                           (page_id,)).fetchone())


def delete_page(db, page_id: int, org_id: str):
    row = db.execute("SELECT * FROM status_pages WHERE id=? AND org_id=?",
                     (page_id, org_id)).fetchone()
    if row is None:
        raise KeyError("page not found")
    db.execute("DELETE FROM status_pages WHERE id=?", (page_id,))
    db.commit()


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def _validate_incident(title, status, impact, target_id, org_id, db):
    title = (title or "").strip()
    if not title:
        raise ValueError("title is required")
    if len(title) > 200:
        raise ValueError("title too long (max 200)")
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"status must be one of {INCIDENT_STATUSES}")
    if impact not in INCIDENT_IMPACTS:
        raise ValueError(f"impact must be one of {INCIDENT_IMPACTS}")
    if target_id is not None:
        t = db.execute("SELECT id FROM uptime_targets WHERE id=?"
                       " AND org_id=?", (target_id, org_id)).fetchone()
        if t is None:
            raise ValueError("target not found")
    return title


def create_incident(db, org_id: str, title: str,
                    status: str = "investigating",
                    impact: str = "minor",
                    target_id: int | None = None,
                    public_visible: bool = True,
                    created_by: str = "",
                    initial_message: str = "") -> dict:
    title = _validate_incident(title, status, impact, target_id, org_id, db)
    now = _now_iso()
    cur = db.execute(
        "INSERT INTO incidents (org_id, title, status, impact, target_id,"
        " public_visible, started_at, resolved_at, created_by, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (org_id, title, status, impact, target_id,
         1 if public_visible else 0, now,
         now if status == "resolved" else None,
         created_by or "", now))
    inc_id = cur.lastrowid
    msg = (initial_message or "").strip()
    if msg or status != "investigating":
        db.execute(
            "INSERT INTO incident_updates (incident_id, status, message,"
            " created_by, created_at) VALUES (?,?,?,?,?)",
            (inc_id, status, msg, created_by or "", now))
    db.commit()
    return get_incident(db, inc_id, org_id)


def get_incident(db, incident_id: int, org_id: str) -> dict | None:
    r = db.execute("SELECT * FROM incidents WHERE id=? AND org_id=?",
                   (incident_id, org_id)).fetchone()
    if r is None:
        return None
    inc = dict(r)
    inc["updates"] = [dict(u) for u in db.execute(
        "SELECT * FROM incident_updates WHERE incident_id=?"
        " ORDER BY created_at, id", (incident_id,)).fetchall()]
    return inc


def list_incidents(db, org_id: str, status: str | None = None,
                   target_id: int | None = None) -> list[dict]:
    q = "SELECT * FROM incidents WHERE org_id=?"
    args: list = [org_id]
    if status:
        if status not in INCIDENT_STATUSES and status != "open":
            raise ValueError("bad status filter")
        if status == "open":
            q += " AND status IN ('investigating','identified','monitoring')"
        else:
            q += " AND status=?"
            args.append(status)
    if target_id is not None:
        q += " AND target_id=?"
        args.append(target_id)
    q += " ORDER BY started_at DESC, id DESC"
    return [dict(r) for r in db.execute(q, args).fetchall()]


def update_incident(db, incident_id: int, org_id: str,
                    actor: str = "", **fields) -> dict:
    inc = db.execute("SELECT * FROM incidents WHERE id=? AND org_id=?",
                     (incident_id, org_id)).fetchone()
    if inc is None:
        raise KeyError("incident not found")
    sets, args = [], []
    if "title" in fields:
        title = (fields["title"] or "").strip()
        if not title:
            raise ValueError("title is required")
        if len(title) > 200:
            raise ValueError("title too long (max 200)")
        sets.append("title=?")
        args.append(title)
    if "impact" in fields:
        if fields["impact"] not in INCIDENT_IMPACTS:
            raise ValueError(f"impact must be one of {INCIDENT_IMPACTS}")
        sets.append("impact=?")
        args.append(fields["impact"])
    if "public_visible" in fields:
        sets.append("public_visible=?")
        args.append(1 if fields["public_visible"] else 0)
    if "status" in fields:
        st = fields["status"]
        if st not in INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {INCIDENT_STATUSES}")
        sets.append("status=?")
        args.append(st)
        sets.append("resolved_at=?")
        args.append(_now_iso() if st == "resolved" else None)
    if not sets:
        raise ValueError("nothing to update")
    args.append(incident_id)
    db.execute(f"UPDATE incidents SET {', '.join(sets)} WHERE id=?", args)
    db.commit()
    return get_incident(db, incident_id, org_id)


def add_update(db, incident_id: int, org_id: str, message: str,
               status: str | None = None, created_by: str = "") -> dict:
    inc = db.execute("SELECT * FROM incidents WHERE id=? AND org_id=?",
                     (incident_id, org_id)).fetchone()
    if inc is None:
        raise KeyError("incident not found")
    message = (message or "").strip()
    if status is not None and status not in INCIDENT_STATUSES:
        raise ValueError(f"status must be one of {INCIDENT_STATUSES}")
    if not message and status is None:
        raise ValueError("message or status is required")
    now = _now_iso()
    st = status or inc["status"]
    db.execute(
        "INSERT INTO incident_updates (incident_id, status, message,"
        " created_by, created_at) VALUES (?,?,?,?,?)",
        (incident_id, st, message[:2000], created_by or "", now))
    if status is not None and status != inc["status"]:
        db.execute("UPDATE incidents SET status=?, resolved_at=?"
                   " WHERE id=?",
                   (status, now if status == "resolved" else None,
                    incident_id))
    db.commit()
    return get_incident(db, incident_id, org_id)


def resolve_incident(db, incident_id: int, org_id: str,
                     message: str = "", created_by: str = "") -> dict:
    inc = db.execute("SELECT * FROM incidents WHERE id=? AND org_id=?",
                     (incident_id, org_id)).fetchone()
    if inc is None:
        raise KeyError("incident not found")
    if inc["status"] == "resolved":
        return get_incident(db, incident_id, org_id)
    return add_update(db, incident_id, org_id,
                      message or "تم حل المشكلة", status="resolved",
                      created_by=created_by)


def delete_incident(db, incident_id: int, org_id: str):
    inc = db.execute("SELECT * FROM incidents WHERE id=? AND org_id=?",
                     (incident_id, org_id)).fetchone()
    if inc is None:
        raise KeyError("incident not found")
    db.execute("DELETE FROM incident_updates WHERE incident_id=?",
               (incident_id,))
    db.execute("DELETE FROM incidents WHERE id=?", (incident_id,))
    db.commit()


# ---------------------------------------------------------------------------
# Automatic incidents driven by uptime alerts
# ---------------------------------------------------------------------------

def _url_of_target(target: dict) -> str:
    scheme = "https" if target.get("use_https") else "http"
    default = 443 if scheme == "https" else 80
    port = f":{target['port']}" if target.get("port") != default else ""
    return f"{scheme}://{target['hostname']}{port}{target.get('path', '/')}"


def open_incident_for_target(db, target: dict, reason: str = "") -> dict | None:
    """Open an incident for a down target. Idempotent: at most one open
    incident per target. Returns the incident or None if one is open."""
    org_id = target["org_id"]
    open_one = db.execute(
        "SELECT id FROM incidents WHERE org_id=? AND target_id=?"
        " AND status IN ('investigating','identified','monitoring')",
        (org_id, target["id"])).fetchone()
    if open_one:
        return None
    url = _url_of_target(target)
    msg = (f"رصد تلقائي: الموقع «{url}» متوقف."
           + (f" السبب: {reason}" if reason else ""))
    return create_incident(
        db, org_id, f"توقف {target['hostname']}{target.get('path', '/')}",
        status="investigating", impact="critical",
        target_id=target["id"], public_visible=True,
        created_by="system", initial_message=msg)


def resolve_incidents_for_target(db, target: dict,
                                 message: str = "") -> int:
    """Resolve every open incident for a recovered target. Returns count."""
    org_id = target["org_id"]
    rows = db.execute(
        "SELECT id FROM incidents WHERE org_id=? AND target_id=?"
        " AND status IN ('investigating','identified','monitoring')",
        (org_id, target["id"])).fetchall()
    msg = message or (f"عاد الموقع «{_url_of_target(target)}» للعمل —"
                      " أُغلق الحادث تلقائياً.")
    for r in rows:
        resolve_incident(db, r["id"], org_id, message=msg,
                         created_by="system")
    return len(rows)


# ---------------------------------------------------------------------------
# Daily aggregates -> 90-day uptime bars
# ---------------------------------------------------------------------------

def record_check(db, target_id: int, status: str,
                 latency_ms: int | None):
    """Fold one probe outcome into today's aggregate row. Never raises."""
    try:
        day = _today()
        col = {"up": "checks_up", "down": "checks_down",
               "error": "checks_error"}.get(status)
        if col is None:
            return
        row = db.execute("SELECT * FROM uptime_daily WHERE target_id=?"
                         " AND day=?", (target_id, day)).fetchone()
        if row is None:
            db.execute("INSERT INTO uptime_daily (target_id, day,"
                       " checks_up, checks_down, checks_error,"
                       " latency_sum_ms, latency_n)"
                       " VALUES (?,?,?,?,?,?,?)",
                       (target_id, day, 1 if col == "checks_up" else 0,
                        1 if col == "checks_down" else 0,
                        1 if col == "checks_error" else 0,
                        latency_ms or 0, 1 if latency_ms else 0))
        else:
            db.execute(f"UPDATE uptime_daily SET {col}={col}+1,"
                       " latency_sum_ms=latency_sum_ms+?,"
                       " latency_n=latency_n+? WHERE target_id=? AND day=?",
                       (latency_ms or 0, 1 if latency_ms else 0,
                        target_id, day))
        db.commit()
    except Exception:  # noqa: BLE001 - aggregates must never kill checks
        log.exception("failed to record daily aggregate")


def prune_daily(db, retention_days: int = DAILY_RETENTION_DAYS):
    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=retention_days)).strftime("%Y-%m-%d")
    db.execute("DELETE FROM uptime_daily WHERE day < ?", (cutoff,))
    db.commit()


def target_history(db, target_id: int,
                   days: int = PUBLIC_HISTORY_DAYS) -> list[dict]:
    """One entry per day (newest last): uptime fraction or None."""
    rows = {r["day"]: dict(r) for r in db.execute(
        "SELECT * FROM uptime_daily WHERE target_id=?"
        " ORDER BY day DESC LIMIT ?", (target_id, days)).fetchall()}
    out = []
    today = datetime.now(timezone.utc).date()
    for i in range(days - 1, -1, -1):
        day = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        r = rows.get(day)
        if r is None or (r["checks_up"] + r["checks_down"]
                         + r["checks_error"]) == 0:
            out.append({"day": day, "uptime": None})
        else:
            total = r["checks_up"] + r["checks_down"] + r["checks_error"]
            out.append({"day": day,
                        "uptime": round(r["checks_up"] / total, 4)})
    return out


# ---------------------------------------------------------------------------
# Public summary (read-only, auth-free)
# ---------------------------------------------------------------------------

def public_summary(db, slug: str) -> dict | None:
    """Build the public status payload for an enabled page, or None."""
    page = get_page_by_slug(db, slug)
    if page is None or not page["enabled"]:
        return None
    org_id = page["org_id"]
    targets = [dict(r) for r in db.execute(
        "SELECT id, hostname, port, path, use_https, last_status,"
        " last_checked_at, last_latency_ms FROM uptime_targets"
        " WHERE org_id=? AND enabled=1 ORDER BY hostname, path",
        (org_id,)).fetchall()]
    for t in targets:
        t["url"] = _url_of_target(t)
        t["history"] = target_history(db, t["id"])
        known = [h["uptime"] for h in t["history"] if h["uptime"] is not None]
        t["uptime_90d"] = (round(sum(known) / len(known), 4)
                           if known else None)
        for k in ("id",):
            t.pop(k, None)
    incidents = [dict(r) for r in db.execute(
        "SELECT id, title, status, impact, started_at, resolved_at"
        " FROM incidents WHERE org_id=? AND public_visible=1"
        " AND (status IN ('investigating','identified','monitoring')"
        " OR (status='resolved' AND started_at >= ?))"
        " ORDER BY started_at DESC",
        (org_id, (datetime.now(timezone.utc)
                  - timedelta(days=PUBLIC_INCIDENT_HISTORY_DAYS))
         .strftime("%Y-%m-%dT%H:%M:%S+00:00"))).fetchall()]
    for inc in incidents:
        inc["updates"] = [dict(u) for u in db.execute(
            "SELECT status, message, created_at FROM incident_updates"
            " WHERE incident_id=? ORDER BY created_at, id",
            (inc["id"],)).fetchall()]
    overall = "operational"
    if any(t["last_status"] == "down" for t in targets):
        overall = "outage"
    elif any(i["status"] in OPEN_STATUSES for i in incidents):
        overall = "degraded"
    import maintenance as _mnt  # noqa: E402
    return {"title": page["title"], "headline": page["headline"],
            "slug": page["slug"], "overall": overall,
            "targets": targets, "incidents": incidents,
            "maintenance": _mnt.public_windows(db, org_id),
            "generated_at": _now_iso()}
