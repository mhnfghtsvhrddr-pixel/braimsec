"""Tests for team finding triage (feature 3).

- PATCH /api/findings/{id}/triage: status workflow, assignment, notes,
  RBAC (member+ writes, viewer read-only), org isolation, validation
- GET /api/findings/{id}/triage: current state + append-only history
- POST /api/findings/triage-bulk: mixed own/foreign ids -> updated/skipped
- GET /api/scans/{id}/results: triage_status / assigned_to filters
- GET /api/team: member list without hashes (member+)
- false_positive triage -> finding_suppressions row -> the scheduler's
  new-findings diff skips the fingerprint (no re-alert); leaving
  false_positive lifts the suppression
"""
import os
import sys
import tempfile
import uuid

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-triage-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-triage-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import scheduler  # noqa: E402
from billing import create_org, ensure_owner_org, provision_key  # noqa: E402
from database import get_db, init_db  # noqa: E402

init_db()
MASTER = os.environ["BRAIMSEC_API_KEY"]
UID = uuid.uuid4().hex[:8]


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


@pytest.fixture()
def ctx():
    ensure_owner_org()
    org = create_org(f"TriageCo-{UID}", plan="free")
    other = create_org(f"TriageOther-{UID}", plan="free")
    keys = {
        "org": org,
        "viewer": provision_key(org, f"t-viewer-{UID}", actor="owner",
                               role="viewer"),
        "member": provision_key(org, f"t-member-{UID}", actor="owner",
                                role="member"),
        "admin": provision_key(org, f"t-admin-{UID}", actor="owner",
                              role="admin"),
        "member_id": None,  # filled below
        "o_member": provision_key(other, f"t-omember-{UID}", actor="owner",
                                 role="member"),
        "other": other,
    }
    db = get_db()
    row = db.execute(
        "SELECT id FROM api_keys WHERE org_id=? AND name=?",
        (org, f"t-member-{UID}")).fetchone()
    keys["member_id"] = row["id"]
    db.close()
    return keys


def _h(key):
    return {"x-api-key": key}


def _scan_with_findings(org_id, findings, status="done"):
    """Insert a scan + findings directly; returns (scan_id, [finding_ids])."""
    db = get_db()
    scan_id = f"tri-{UID}-{uuid.uuid4().hex[:6]}"
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,datetime('now'))",
        (scan_id, org_id, f"target-{UID}", status))
    ids = []
    for f in findings:
        cur = db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, f.get("tool", "semgrep"), f.get("rule_id", "r1"),
             f.get("severity", "error"), f.get("message", "m"),
             f.get("file", "a.py"), f.get("line", 1), f.get("col", 0)))
        ids.append(cur.lastrowid)
    db.commit()
    db.close()
    return scan_id, ids


def _client():
    return TestClient(main.app)


# --- PATCH triage -----------------------------------------------------------

def test_member_can_triage(ctx):
    c = _client()
    _, (fid,) = _scan_with_findings(ctx["org"], [{"message": "tainted"}])
    r = c.patch(f"/api/findings/{fid}/triage", headers=_h(ctx["member"]),
                json={"status": "in_progress",
                      "assigned_to": ctx["member_id"],
                      "note": "looking into it"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "in_progress"
    assert body["assigned_to"] == ctx["member_id"]
    assert body["note"] == "looking into it"
    # history recorded
    r2 = c.get(f"/api/findings/{fid}/triage", headers=_h(ctx["member"]))
    assert r2.status_code == 200
    t = r2.json()
    assert t["triage"]["status"] == "in_progress"
    assert len(t["history"]) == 1
    assert t["history"][0]["from_status"] == "open"
    assert t["history"][0]["to_status"] == "in_progress"


def test_viewer_cannot_triage(ctx):
    c = _client()
    _, (fid,) = _scan_with_findings(ctx["org"], [{"message": "v"}])
    r = c.patch(f"/api/findings/{fid}/triage", headers=_h(ctx["viewer"]),
                json={"status": "fixed"})
    assert r.status_code == 403
    # viewer CAN read triage state
    r2 = c.get(f"/api/findings/{fid}/triage", headers=_h(ctx["viewer"]))
    assert r2.status_code == 200
    assert r2.json()["triage"]["status"] == "open"


def test_triage_other_org_is_404(ctx):
    c = _client()
    _, (fid,) = _scan_with_findings(ctx["org"], [{"message": "x"}])
    r = c.patch(f"/api/findings/{fid}/triage", headers=_h(ctx["o_member"]),
                json={"status": "fixed"})
    assert r.status_code == 404
    r2 = c.get(f"/api/findings/{fid}/triage", headers=_h(ctx["o_member"]))
    assert r2.status_code == 404


def test_triage_validation(ctx):
    c = _client()
    _, (fid,) = _scan_with_findings(ctx["org"], [{"message": "y"}])
    m = _h(ctx["member"])
    assert c.patch(f"/api/findings/{fid}/triage", headers=m,
                   json={"status": "bogus"}).status_code == 400
    assert c.patch(f"/api/findings/{fid}/triage", headers=m,
                   json={}).status_code == 400
    # unknown assignee
    assert c.patch(f"/api/findings/{fid}/triage", headers=m,
                   json={"assigned_to": "nope"}).status_code == 400
    # assignee from another org
    db = get_db()
    other_key = db.execute(
        "SELECT id FROM api_keys WHERE org_id=?", (ctx["other"],)).fetchone()["id"]
    db.close()
    assert c.patch(f"/api/findings/{fid}/triage", headers=m,
                   json={"assigned_to": other_key}).status_code == 400
    # unassign works
    r = c.patch(f"/api/findings/{fid}/triage", headers=m,
                json={"assigned_to": None, "note": "nobody"})
    assert r.status_code == 200
    assert r.json()["assigned_to"] is None


def test_triage_note_only(ctx):
    c = _client()
    _, (fid,) = _scan_with_findings(ctx["org"], [{"message": "z"}])
    r = c.patch(f"/api/findings/{fid}/triage", headers=_h(ctx["member"]),
                json={"note": "just a note"})
    assert r.status_code == 200
    assert r.json()["status"] == "open"  # unchanged
    assert r.json()["note"] == "just a note"


def test_triage_audit_logged(ctx):
    c = _client()
    _, (fid,) = _scan_with_findings(ctx["org"], [{"message": "a"}])
    c.patch(f"/api/findings/{fid}/triage", headers=_h(ctx["member"]),
            json={"status": "accepted_risk"})
    db = get_db()
    row = db.execute(
        "SELECT action FROM audit_log WHERE org_id=? AND resource_id=?"
        " ORDER BY id DESC LIMIT 1",
        (ctx["org"], str(fid))).fetchone()
    db.close()
    assert row and row["action"] == "finding.triaged"


# --- bulk triage ------------------------------------------------------------

def test_bulk_triage(ctx):
    c = _client()
    _, ids = _scan_with_findings(ctx["org"], [{"message": "b1"},
                                             {"message": "b2"}])
    _, (foreign,) = _scan_with_findings(ctx["other"], [{"message": "b3"}])
    r = c.post("/api/findings/triage-bulk", headers=_h(ctx["member"]),
               json={"finding_ids": ids + [foreign, 999999],
                     "status": "fixed", "note": "patched"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert sorted(body["updated"]) == sorted(ids)
    assert foreign in body["skipped"] and 999999 in body["skipped"]
    # state applied
    r2 = c.get(f"/api/findings/{ids[0]}/triage", headers=_h(ctx["member"]))
    assert r2.json()["triage"]["status"] == "fixed"


def test_bulk_triage_viewer_forbidden(ctx):
    c = _client()
    r = c.post("/api/findings/triage-bulk", headers=_h(ctx["viewer"]),
               json={"finding_ids": [1], "status": "fixed"})
    assert r.status_code == 403


# --- results filters --------------------------------------------------------

def test_results_triage_filters(ctx):
    c = _client()
    scan_id, (f1, f2) = _scan_with_findings(ctx["org"],
                                           [{"message": "k1"},
                                            {"message": "k2"}])
    m = _h(ctx["member"])
    c.patch(f"/api/findings/{f1}/triage", headers=m,
            json={"status": "false_positive",
                  "assigned_to": ctx["member_id"]})
    # triage columns present
    rows = c.get(f"/api/scans/{scan_id}/results", headers=m).json()
    by_id = {r["id"]: r for r in rows}
    assert by_id[f1]["triage_status"] == "false_positive"
    assert by_id[f1]["triage_assignee"] == ctx["member_id"]
    assert by_id[f2]["triage_status"] == "open"
    # filter by status
    rows = c.get(f"/api/scans/{scan_id}/results?triage_status=false_positive",
                 headers=m).json()
    assert [r["id"] for r in rows] == [f1]
    # filter by assignee
    rows = c.get(
        f"/api/scans/{scan_id}/results?assigned_to={ctx['member_id']}",
        headers=m).json()
    assert [r["id"] for r in rows] == [f1]
    # combined with severity filter
    rows = c.get(f"/api/scans/{scan_id}/results?severity=error"
                 "&triage_status=open", headers=m).json()
    assert [r["id"] for r in rows] == [f2]
    # invalid status -> 400
    assert c.get("/api/scans/{scan_id}/results?triage_status=bogus".format(
        scan_id=scan_id), headers=m).status_code == 400


# --- team endpoint ----------------------------------------------------------

def test_team_endpoint(ctx):
    c = _client()
    rows = c.get("/api/team", headers=_h(ctx["member"])).json()
    names = {r["name"] for r in rows}
    assert f"t-member-{UID}" in names
    # no hashes leaked
    assert all("key_hash" not in r and "key" not in r for r in rows)
    assert all(set(r) == {"id", "name", "key_prefix", "role"} for r in rows)
    # viewer cannot list the team
    assert c.get("/api/team", headers=_h(ctx["viewer"])).status_code == 403
    # other org sees only its own keys
    rows2 = c.get("/api/team", headers=_h(ctx["o_member"])).json()
    assert {r["name"] for r in rows2} == {f"t-omember-{UID}"}


# --- false_positive <-> scheduler suppression -------------------------------

def test_false_positive_suppresses_scheduled_alert(ctx, monkeypatch):
    """Triaging FP creates a suppression; the scheduler skips it."""
    db = get_db()
    # start clean: leftover schedules from other suites must not interfere
    db.execute("DELETE FROM schedules")
    db.commit()
    db.close()
    c = _client()
    m = _h(ctx["member"])
    prev_id, _ = _scan_with_findings(ctx["org"], [])
    new_id, (fp_fid, real_fid) = _scan_with_findings(
        ctx["org"],
        [{"tool": "semgrep", "rule_id": "r-fp", "severity": "error",
          "message": "known FP", "file": "fp.py"},
         {"tool": "semgrep", "rule_id": "r-real", "severity": "error",
          "message": "real bug", "file": "real.py"}])
    # triage one finding as false positive -> suppression row
    r = c.patch(f"/api/findings/{fp_fid}/triage", headers=m,
                json={"status": "false_positive", "note": "test"})
    assert r.status_code == 200
    db = get_db()
    sup = db.execute(
        "SELECT fingerprint FROM finding_suppressions WHERE org_id=?",
        (ctx["org"],)).fetchall()
    db.close()
    assert len(sup) == 1
    assert sup[0]["fingerprint"] == scheduler.finding_fingerprint(
        "semgrep", "r-fp", "fp.py", "known FP")
    # wire a schedule: prev -> new, then evaluate
    db = get_db()
    db.execute(
        "INSERT INTO schedules (id, org_id, name, target_path, frequency,"
        " run_time, timezone, alert_severity, webhook_url, enabled,"
        " next_run_at, last_scan_id, prev_scan_id, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))",
        (f"sched-{UID}", ctx["org"], "n", "/tmp", "daily", "02:00", "UTC",
         "warning", "https://hooks.test/x", 1, "2099-01-01T00:00:00",
         new_id, prev_id))
    db.commit()
    db.close()
    seen = {}
    monkeypatch.setattr(
        scheduler, "send_alert",
        lambda url, payload, org_id=None: (seen.setdefault("payload", payload),
                             (True, 1, 200, None))[1])
    out = scheduler.evaluate_schedule_alerts(new_id)
    assert out["alerted"] is True
    assert out["new_count"] == 1  # the FP is excluded
    msgs = [f["message"] for f in seen["payload"]["findings"]]
    assert msgs == ["real bug"]


def test_leaving_false_positive_lifts_suppression(ctx):
    c = _client()
    m = _h(ctx["member"])
    _, (fid,) = _scan_with_findings(ctx["org"], [{"message": "lift me"}])
    c.patch(f"/api/findings/{fid}/triage", headers=m,
            json={"status": "false_positive"})
    db = get_db()
    n1 = db.execute(
        "SELECT COUNT(*) c FROM finding_suppressions WHERE org_id=?",
        (ctx["org"],)).fetchone()["c"]
    db.close()
    assert n1 == 1
    c.patch(f"/api/findings/{fid}/triage", headers=m,
            json={"status": "open"})
    db = get_db()
    n2 = db.execute(
        "SELECT COUNT(*) c FROM finding_suppressions WHERE org_id=?",
        (ctx["org"],)).fetchone()["c"]
    db.close()
    assert n2 == 0
