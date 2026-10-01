"""Tests for /api/notifications filters (channel/event/status).

- filtering by channel, event, status, and combinations
- invalid filter values -> 400
- legacy id filters (schedule_id) still work and combine with new ones
- org isolation, viewer+ access
"""
import os
import sys
import tempfile

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-notif-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-notif-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from billing import (create_org, ensure_owner_org, provision_key,  # noqa: E402
                     seed_plans)
from database import get_db, init_db  # noqa: E402

init_db()
seed_plans()


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


def _insert(db, org, channel, event, status, schedule_id=None):
    cur = db.execute(
        "INSERT INTO notifications (org_id, schedule_id, scan_id, event,"
        " severity, new_count, webhook_url, channel, recipient, status,"
        " attempts, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (org, schedule_id, "scan1", event, "warning", 3, "", channel, "",
         status, 1, "2026-10-02T00:00:00+00:00"))
    db.commit()
    return cur.lastrowid


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = os.urandom(4).hex()
    org = create_org(f"NotifCo_{uid}", plan="free")
    other = create_org(f"NotifOther_{uid}", plan="free")
    viewer = provision_key(org, "nt-viewer", actor="owner", role="viewer")
    o_viewer = provision_key(other, "o-viewer", actor="owner", role="viewer")
    db = get_db()
    _insert(db, org, "webhook", "schedule.alert", "sent")
    _insert(db, org, "email", "schedule.alert", "sent")
    _insert(db, org, "telegram", "schedule.failed", "failed")
    _insert(db, org, "slack", "schedule.alert", "skipped")
    _insert(db, org, "teams", "vcs.alert", "sent")
    _insert(db, org, "webhook", "vcs.failed", "failed",
            schedule_id="sched-1")
    _insert(db, other, "webhook", "schedule.alert", "sent")
    db.close()
    return {"org": org, "viewer": viewer, "o_viewer": o_viewer}


def _h(key):
    return {"X-API-Key": key}


def _get(c, key, qs=""):
    r = c.get("/api/notifications" + qs, headers=_h(key))
    assert r.status_code == 200, r.text
    return r.json()


def test_no_filters_returns_all_org_rows(ctx):
    c = TestClient(main.app)
    assert len(_get(c, ctx["viewer"])) == 6


def test_filter_channel(ctx):
    c = TestClient(main.app)
    rows = _get(c, ctx["viewer"], "?channel=telegram")
    assert len(rows) == 1 and rows[0]["channel"] == "telegram"
    rows = _get(c, ctx["viewer"], "?channel=webhook")
    assert len(rows) == 2


def test_filter_event(ctx):
    c = TestClient(main.app)
    rows = _get(c, ctx["viewer"], "?event=schedule.failed")
    assert len(rows) == 1 and rows[0]["event"] == "schedule.failed"
    rows = _get(c, ctx["viewer"], "?event=schedule.alert")
    assert len(rows) == 3


def test_filter_status(ctx):
    c = TestClient(main.app)
    rows = _get(c, ctx["viewer"], "?status=failed")
    assert len(rows) == 2
    assert {r["status"] for r in rows} == {"failed"}
    rows = _get(c, ctx["viewer"], "?status=skipped")
    assert len(rows) == 1 and rows[0]["channel"] == "slack"


def test_filter_combination(ctx):
    c = TestClient(main.app)
    rows = _get(c, ctx["viewer"],
                "?channel=webhook&event=schedule.alert&status=sent")
    assert len(rows) == 1
    rows = _get(c, ctx["viewer"], "?channel=webhook&status=failed")
    assert len(rows) == 1 and rows[0]["event"] == "vcs.failed"
    # combination with no match -> empty, not an error
    assert _get(c, ctx["viewer"], "?channel=email&status=failed") == []


def test_filter_combines_with_schedule_id(ctx):
    c = TestClient(main.app)
    rows = _get(c, ctx["viewer"], "?schedule_id=sched-1&status=failed")
    assert len(rows) == 1
    rows = _get(c, ctx["viewer"], "?schedule_id=sched-1&status=sent")
    assert rows == []


def test_invalid_filter_values_400(ctx):
    c = TestClient(main.app)
    for qs in ("?channel=sms", "?event=scan.done", "?status=pending"):
        r = c.get("/api/notifications" + qs, headers=_h(ctx["viewer"]))
        assert r.status_code == 400, qs


def test_org_isolation(ctx):
    c = TestClient(main.app)
    rows = _get(c, ctx["o_viewer"])
    assert len(rows) == 1
    rows = _get(c, ctx["o_viewer"], "?channel=email")
    assert rows == []


def test_newest_first(ctx):
    c = TestClient(main.app)
    rows = _get(c, ctx["viewer"])
    ids = [r["id"] for r in rows]
    assert ids == sorted(ids, reverse=True)
