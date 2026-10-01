"""Tests for scan status badges (GET /api/scans/{id}/badge.svg).

- shields-style SVG: valid XML, correct colors per severity
- statuses: done (clean/critical/high/low), queued/running (gray),
  failed (gray), unknown -> 404 (not a badge)
- public: no API key required
- privacy: no file names, messages, targets or org data in the SVG
- deterministic: identical bytes across calls
"""
import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import pytest

# New test module: setdefault only (test_async_queue.py pins these first in
# the unified run — see AGENTS.md).
_tmp = tempfile.mkdtemp(prefix="braimsec-test-badge-")
os.environ.setdefault("BRAIMSEC_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("BRAIMSEC_API_KEY", "test-badge-master-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from billing import create_org, ensure_owner_org, seed_plans  # noqa: E402
from database import get_db, init_db  # noqa: E402
from scan_badge import badge_text_and_color, build_badge_svg  # noqa: E402

init_db()
seed_plans()


@pytest.fixture(autouse=True)
def _fresh_limiter():
    main.limiter._storage.reset()
    yield
    main.limiter._storage.reset()


def _uid():
    import uuid as _u
    return _u.uuid4().hex[:8]


def _ts():
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture()
def ctx():
    ensure_owner_org()
    uid = _uid()
    org = create_org(f"BadgeCo_{uid}", plan="free")
    return {"org": org, "uid": uid}


def _mk_scan(org, scan_id, status, findings):
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " total_findings) VALUES (?,?,?,?,?,?)",
        (scan_id, org, "secret-target-name", status, _ts(), len(findings)))
    for tool, rule, sev, msg, f, line in findings:
        db.execute(
            "INSERT INTO findings (scan_id, tool, rule_id, severity,"
            " message, file, line, col) VALUES (?,?,?,?,?,?,?,?)",
            (scan_id, tool, rule, sev, msg, f, line, 1))
    db.commit()
    db.close()


def _badge(scan_id):
    c = TestClient(main.app)
    return c.get(f"/api/scans/{scan_id}/badge.svg")  # no auth header


# ---------------------------------------------------------------------------
# Core rendering
# ---------------------------------------------------------------------------

def test_badge_critical_red(ctx):
    sid = f"bd1_{ctx['uid']}"
    _mk_scan(ctx["org"], sid, "done",
             [("semgrep", "r1", "error", "m1", "a.py", 1),
              ("semgrep", "r2", "warning", "m2", "b.py", 2)])
    r = _badge(sid)
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/svg+xml"
    ET.fromstring(r.content)  # valid XML
    assert b"1 critical" in r.content
    assert b"#e05d44" in r.content  # red


def test_badge_high_orange_when_no_critical(ctx):
    sid = f"bd2_{ctx['uid']}"
    _mk_scan(ctx["org"], sid, "done",
             [("semgrep", "r1", "warning", "m1", "a.py", 1)])
    r = _badge(sid)
    assert r.status_code == 200
    assert b"1 high" in r.content
    assert b"#fe7d37" in r.content


def test_badge_low_yellow(ctx):
    sid = f"bd3_{ctx['uid']}"
    _mk_scan(ctx["org"], sid, "done",
             [("gitleaks", "r1", "note", "m1", "a.py", 1)])
    r = _badge(sid)
    assert b"1 low" in r.content
    assert b"#dfb317" in r.content


def test_badge_clean_green(ctx):
    sid = f"bd4_{ctx['uid']}"
    _mk_scan(ctx["org"], sid, "done", [])
    r = _badge(sid)
    assert r.status_code == 200
    assert b"clean" in r.content
    assert b"#4c1" in r.content


def test_badge_in_progress_gray(ctx):
    for status, word in [("queued", "queued"), ("running", "scanning")]:
        sid = f"bd5_{ctx['uid']}_{status}"
        _mk_scan(ctx["org"], sid, status, [])
        r = _badge(sid)
        assert r.status_code == 200
        assert word.encode() in r.content
        assert b"#9e9e9e" in r.content


def test_badge_failed_gray(ctx):
    sid = f"bd6_{ctx['uid']}"
    _mk_scan(ctx["org"], sid, "failed", [])
    r = _badge(sid)
    assert r.status_code == 200
    assert b"failed" in r.content


def test_badge_404_unknown_scan():
    r = _badge("nope_not_real_123")
    assert r.status_code == 404
    assert b"<svg" not in r.content  # 404, not a badge


# ---------------------------------------------------------------------------
# Privacy + determinism
# ---------------------------------------------------------------------------

def test_badge_leaks_nothing_sensitive(ctx):
    sid = f"bd7_{ctx['uid']}"
    _mk_scan(ctx["org"], sid, "done",
             [("semgrep", "super-secret-rule", "error",
               "password = hunter2 exposed", "internal/secret_config.py", 7)])
    r = _badge(sid)
    body = r.content.decode()
    for secret in ["super-secret-rule", "hunter2", "secret_config.py",
                   "secret-target-name", ctx["org"]]:
        assert secret not in body, f"leaked: {secret}"


def test_badge_deterministic(ctx):
    sid = f"bd8_{ctx['uid']}"
    _mk_scan(ctx["org"], sid, "done",
             [("semgrep", "r1", "error", "m1", "a.py", 1)])
    assert _badge(sid).content == _badge(sid).content


def test_badge_headers(ctx):
    sid = f"bd9_{ctx['uid']}"
    _mk_scan(ctx["org"], sid, "done", [])
    r = _badge(sid)
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"


# ---------------------------------------------------------------------------
# Pure function unit tests
# ---------------------------------------------------------------------------

def test_badge_text_and_color_matrix():
    assert badge_text_and_color("done", {}) == ("clean", "#4c1")
    assert badge_text_and_color("done", {"error": 3}) == ("3 critical", "#e05d44")
    assert badge_text_and_color("done", {"warning": 2, "error": 1})[0] == "1 critical"
    assert badge_text_and_color("done", {"note": 5}) == ("5 low", "#dfb317")
    assert badge_text_and_color("queued", {}) == ("queued…", "#9e9e9e")
    assert badge_text_and_color("running", {}) == ("scanning…", "#9e9e9e")
    assert badge_text_and_color("failed", {}) == ("failed", "#9e9e9e")


def test_build_badge_svg_escapes_xml():
    svg = build_badge_svg("done", {"error": 1})
    ET.fromstring(svg)
    # a hostile severity label must not break the document
    svg2 = build_badge_svg("weird\"><script>", {})
    ET.fromstring(svg2)
    assert "<script>" not in svg2
