#!/usr/bin/env python3
"""BraimSec scheduled executive reports (emailed PDFs).

A *report schedule* belongs to one org and periodically builds the
manager-facing executive report (``reports/executive.py`` — deterministic,
no LLM, no quota) from stored scan data, renders it to PDF
(``reports/executive_pdf.py``) and emails it as an attachment to the org's
registered ``alert_emails`` recipients.

Cadence is weekly or monthly (scan schedules are daily/weekly — reports
deserve the slower rhythm). The periodic driver is
:func:`run_report_scheduler_once`, called from the same Celery beat task as
scheduled scans (``braimsec.check_schedules`` in ``tasks.py``). Due
schedules are claimed with a single conditional UPDATE so overlapping
beat/worker instances can never double-send a report.

Delivery outcomes mirror ``email_alerts``: one ``notifications`` row per
recipient with ``channel='email_report'``; unconfigured SMTP is recorded
as ``skipped`` (never silent); a schedule whose scope has no completed
scans yet is recorded as ``skipped`` too — the builder refuses to produce
a report without scope, and spamming an empty failure every week would be
worse than one honest skipped row.
"""

import logging
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "reports"))

from database import get_db  # noqa: E402
from builder import (ReportError, compliance_map,  # noqa: E402
                     lookup_compliance)
from executive import build_executive_report  # noqa: E402
from executive_pdf import render_executive_pdf  # noqa: E402

log = logging.getLogger("braimsec.scheduled_reports")

VALID_REPORT_FREQUENCIES = ("weekly", "monthly")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Scheduling math (pure)
# ---------------------------------------------------------------------------

def compute_next_report_run(frequency: str, run_time: str,
                            weekday: int | None, day_of_month: int | None,
                            tz_name: str,
                            after: datetime | None = None) -> str:
    """Next run strictly after ``after`` (default: now), as ISO-8601.

    ``run_time`` is ``HH:MM`` in the schedule's IANA timezone. Weekly
    schedules need ``weekday`` (0=Monday..6=Sunday); monthly schedules need
    ``day_of_month`` (1..28 — capped so every month has the day).
    """
    if frequency not in VALID_REPORT_FREQUENCIES:
        raise ValueError(f"frequency must be one of {VALID_REPORT_FREQUENCIES}")
    if frequency == "weekly":
        # Deferred import: scheduler is the scan-schedule module; weekly
        # report math is identical to weekly scan math.
        from scheduler import compute_next_run  # noqa: E402
        return compute_next_run("weekly", run_time, weekday, tz_name,
                                after=after)
    # monthly
    try:
        hour, minute = (int(x) for x in run_time.split(":"))
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError()
    except ValueError:
        raise ValueError("run_time must be HH:MM (00:00-23:59)")
    if (day_of_month is None or not isinstance(day_of_month, int)
            or not (1 <= day_of_month <= 28)):
        raise ValueError("day_of_month: 1..28 is required for monthly")
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"unknown timezone: {tz_name}")
    after = after or datetime.now(timezone.utc)
    if after.tzinfo is None:
        after = after.replace(tzinfo=timezone.utc)
    local = after.astimezone(tz)
    candidate = local.replace(day=day_of_month, hour=hour, minute=minute,
                              second=0, microsecond=0)
    if candidate <= local:
        year, month = candidate.year, candidate.month + 1
        if month > 12:
            year, month = year + 1, 1
        candidate = candidate.replace(year=year, month=month)
    return candidate.isoformat()


# ---------------------------------------------------------------------------
# Report input collection (shared by the on-demand endpoint and the driver)
# ---------------------------------------------------------------------------

def collect_report_inputs(db, org_id: str, project_id: str | None = None,
                          days: int = 90) -> dict:
    """Gather everything ``build_executive_report`` needs.

    Returns a dict with org_name, project_name, scans, latest_findings,
    prev_counts and compliance. Raises ``ReportError`` when no completed
    scan exists in scope (a report without scope would be dishonest) and
    ``KeyError`` when the project does not belong to the org.
    """
    org_row = db.execute("SELECT name FROM organizations WHERE id=?",
                         (org_id,)).fetchone()
    org_name = org_row["name"] if org_row else org_id
    project_name = None
    if project_id:
        prow = db.execute("SELECT name FROM projects WHERE id=? AND org_id=?",
                          (project_id, org_id)).fetchone()
        if not prow:
            raise KeyError(project_id)
        project_name = prow["name"]
    q = ("SELECT s.id, s.target_name, s.finished_at, s.created_at,"
         " s.total_findings FROM scans s"
         " WHERE s.org_id=? AND s.status='done'")
    params: list = [org_id]
    if project_id:
        q += " AND s.project_id=?"
        params.append(project_id)
    q += " ORDER BY s.created_at ASC"
    rows = db.execute(q, params).fetchall()
    if days > 0:
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(days=days)).isoformat()
        rows = [r for r in rows if (r["created_at"] or "") >= cutoff]
    if not rows:
        raise ReportError("refusing: no completed scans in scope — "
                          "an executive report without scope is dishonest")
    scans = [dict(r) for r in rows]
    latest = scans[-1]
    latest_findings = [dict(r) for r in db.execute(
        "SELECT tool, rule_id, severity, message, file, line"
        " FROM findings WHERE scan_id=?", (latest["id"],)).fetchall()]
    prev_counts = None
    if len(scans) >= 2:
        pc = db.execute(
            "SELECT severity, COUNT(*) c FROM findings WHERE scan_id=?"
            " GROUP BY severity", (scans[-2]["id"],)).fetchall()
        prev_counts = {r["severity"]: r["c"] for r in pc}
    soc2_m = iso_m = 0
    for f in latest_findings:
        comp = lookup_compliance(f.get("rule_id"), f.get("tool"))
        if comp:
            if comp.get("soc2"):
                soc2_m += 1
            if comp.get("iso"):
                iso_m += 1
    map_version = compliance_map().get("version", "unknown")
    return {
        "org_name": org_name,
        "project_name": project_name,
        "scans": scans,
        "latest_findings": latest_findings,
        "prev_counts": prev_counts,
        "compliance": {"soc2_mapped": soc2_m, "iso_mapped": iso_m,
                       "total": len(latest_findings),
                       "map_version": map_version},
    }


def _highest_severity(findings: list[dict]) -> str:
    rank = {"note": 0, "warning": 1, "error": 2}
    best = "note"
    for f in findings:
        sev = f.get("severity") or "warning"
        if rank.get(sev, 1) > rank.get(best, 0):
            best = sev
    return best


def _report_email_body(sched: dict, report: dict) -> tuple[str, str, str]:
    """(subject, text, html) for a scheduled report delivery."""
    freq_ar = {"weekly": "الأسبوعي", "monthly": "الشهري"}
    scope = report["meta"]["project"] or report["meta"]["org"]
    posture = report["posture"]
    subject = (f"📊 BraimSec: التقرير التنفيذي "
               f"{freq_ar.get(sched['frequency'], '')} — {scope}").strip()
    text = (f"BraimSec — التقرير التنفيذي ({sched['name']})\n"
            f"النطاق: {scope}\n"
            f"الوضع العام: {posture['verdict']}\n"
            f"{posture['summary']}\n\n"
            f"التقرير الكامل مرفق كملف PDF.")
    html = (
        '<html dir="rtl" lang="ar"><body style="font-family:sans-serif">'
        f"<h2>📊 BraimSec: التقرير التنفيذي</h2>"
        f"<p><b>{sched['name']}</b> — النطاق: {scope}</p>"
        f"<p><b>الوضع العام:</b> {posture['verdict']}</p>"
        f"<p>{posture['summary']}</p>"
        f"<p>التقرير الكامل مرفق كملف PDF.</p>"
        "</body></html>")
    return subject, text, html


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def deliver_scheduled_report(report_schedule_id: str) -> dict:
    """Build, render and email one scheduled report. Never raises.

    Returns an outcome dict for logs/tests. A schedule with no completed
    scans in scope is recorded as skipped (the builder refuses empty
    scope); a missing project is a hard error on the schedule row.
    """
    db = get_db()
    try:
        row = db.execute("SELECT * FROM report_schedules WHERE id=?",
                         (report_schedule_id,)).fetchone()
        if not row:
            return {"delivered": False, "reason": "schedule not found"}
        sched = dict(row)
        if not sched["enabled"]:
            return {"delivered": False, "reason": "schedule disabled"}
        org_id = sched["org_id"]
        try:
            inputs = collect_report_inputs(db, org_id, sched["project_id"],
                                           sched["days"])
        except KeyError:
            db.execute("UPDATE report_schedules SET last_error=? WHERE id=?",
                       ("project not found (deleted?)", sched["id"]))
            db.commit()
            return {"delivered": False, "reason": "project not found"}
        except ReportError:
            # Honest skip: nothing to report yet. One notifications row so
            # the dashboard shows it, not a weekly failure storm.
            now_iso = _now_iso()
            # No completed scan exists, so there is no scan_id to attach;
            # scan_id is NOT NULL, use "" for this bookkeeping row.
            db.execute(
                "INSERT INTO notifications (org_id, schedule_id,"
                " report_schedule_id, vcs_repo_id, scan_id, event, severity,"
                " new_count, webhook_url, channel, recipient, status,"
                " attempts, response_code, error, payload, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (org_id, None, sched["id"], None, "",
                 "report.scheduled", "note", 0, "", "email_report", "",
                 "skipped", 0, None,
                 "no completed scans in scope yet", "{}", now_iso))
            db.execute("UPDATE report_schedules SET last_run_at=?,"
                       " last_error=? WHERE id=?",
                       (now_iso, "skipped: no completed scans in scope yet",
                        sched["id"]))
            db.commit()
            return {"delivered": False,
                    "reason": "skipped: no completed scans in scope"}
        generated_at = _now_iso()
        try:
            report = build_executive_report(
                inputs["org_name"], inputs["project_name"], inputs["scans"],
                inputs["latest_findings"],
                prev_counts=inputs["prev_counts"],
                compliance=inputs["compliance"],
                generated_at=generated_at)
            pdf = render_executive_pdf(report)
        except ReportError as e:
            db.execute("UPDATE report_schedules SET last_error=? WHERE id=?",
                       (f"report refused: {e}"[:300], sched["id"]))
            db.commit()
            return {"delivered": False, "reason": f"report refused: {e}"}
        except Exception as e:  # noqa: BLE001 - never break the driver
            log.exception("report build crashed for %s", sched["id"])
            db.execute("UPDATE report_schedules SET last_error=? WHERE id=?",
                       (f"report build crashed: {e}"[:300], sched["id"]))
            db.commit()
            return {"delivered": False,
                    "reason": f"report build crashed: {e}"[:200]}
        subject, text, html = _report_email_body(sched, report)
        severity = _highest_severity(inputs["latest_findings"])
        latest_scan_id = inputs["scans"][-1]["id"]
        try:
            from email_alerts import dispatch_report_emails  # noqa: E402
            out = dispatch_report_emails(
                db, org_id=org_id, report_schedule_id=sched["id"],
                scan_id=latest_scan_id, subject=subject, text_body=text,
                html_body=html, pdf_bytes=pdf,
                filename="braimsec-executive-report.pdf", severity=severity)
        except Exception:  # noqa: BLE001 - best-effort by design
            log.exception("report email dispatch crashed for %s", sched["id"])
            out = {"emailed": False, "reason": "dispatch crashed"}
        db.execute("UPDATE report_schedules SET last_run_at=?, last_error=?"
                   " WHERE id=?",
                   (_now_iso(),
                    None if out.get("emailed") else out.get("reason"),
                    sched["id"]))
        db.commit()
        return {"delivered": bool(out.get("emailed")),
                "reason": out.get("reason"), "email": out,
                "scan_id": latest_scan_id}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Driver: claim due report schedules and deliver them
# ---------------------------------------------------------------------------

def run_report_scheduler_once(now_iso: str | None = None) -> dict:
    """Deliver every report schedule whose time has come.

    Each due schedule is claimed with one conditional UPDATE (sets the next
    run *before* delivery starts), so two beat instances can never
    double-send a report. A schedule whose delivery fails is logged and
    skipped; its next run is already advanced so one bad row cannot wedge
    the loop.
    """
    now_iso = now_iso or _now_iso()
    db = get_db()
    ran, skipped = [], []
    try:
        due = db.execute(
            "SELECT * FROM report_schedules WHERE enabled=1"
            " AND next_run_at <= ?", (now_iso,)).fetchall()
        for row in due:
            sched = dict(row)
            try:
                nxt = compute_next_report_run(
                    sched["frequency"], sched["run_time"], sched["weekday"],
                    sched["day_of_month"], sched["timezone"],
                    after=datetime.fromisoformat(now_iso))
            except ValueError as e:
                log.error("report schedule %s has invalid spec: %s",
                          sched["id"], e)
                skipped.append({"id": sched["id"], "reason": str(e)[:120]})
                continue
            # Atomic claim: only the winner's UPDATE matches.
            cur = db.execute(
                "UPDATE report_schedules SET next_run_at=?, last_run_at=?"
                " WHERE id=? AND next_run_at <= ?",
                (nxt, now_iso, sched["id"], now_iso))
            if cur.rowcount == 0:
                continue  # claimed by another beat instance
            db.commit()
            try:
                out = deliver_scheduled_report(sched["id"])
            except Exception as e:  # noqa: BLE001 - one bad row != dead loop
                log.exception("scheduled report failed for %s", sched["id"])
                db.execute("UPDATE report_schedules SET last_error=?"
                           " WHERE id=?", (str(e)[:300], sched["id"]))
                db.commit()
                skipped.append({"id": sched["id"], "reason": str(e)[:120]})
                continue
            ran.append({"id": sched["id"],
                        "delivered": out.get("delivered"),
                        "reason": out.get("reason")})
    finally:
        db.close()
    return {"ran": ran, "skipped": skipped, "at": now_iso}


def run_report_schedule_now(report_schedule_id: str) -> dict:
    """Trigger one immediate delivery of an enabled report schedule.

    A manual run does not shift next_run_at.
    """
    db = get_db()
    try:
        row = db.execute("SELECT * FROM report_schedules WHERE id=?",
                         (report_schedule_id,)).fetchone()
        if not row:
            raise KeyError(report_schedule_id)
        if not row["enabled"]:
            raise ValueError("report schedule is disabled")
        return deliver_scheduled_report(report_schedule_id)
    finally:
        db.close()


def new_report_schedule_id() -> str:
    return uuid.uuid4().hex[:12]
