"""Dashboard smoke tests for the uptime monitoring section."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "index.html")


def _html():
    with open(HTML, encoding="utf-8") as f:
        return f.read()


def test_uptime_section_markup():
    h = _html()
    for needle in ['id="uptime-section"', 'id="up-host"', 'id="up-port"',
                   'id="up-path"', 'id="up-https"', 'id="up-kw"',
                   'id="up-wh"', 'id="uptime-wrap"',
                   "addUptimeTarget()", "مراقبة الجهوزية"]:
        assert needle in h, needle


def test_uptime_js_functions():
    h = _html()
    for fn in ["async function loadUptimeTargets()",
               "async function addUptimeTarget()",
               "async function delUptimeTarget(id)",
               "async function checkUptimeTarget(id)",
               "async function toggleUptimeTarget(id, enabled)",
               "const UP_ST ="]:
        assert fn in h, fn


def test_uptime_api_calls_wired():
    h = _html()
    for call in ['api("/uptime-targets")',
                 'api(`/uptime-targets/${id}/check`',
                 'api(`/uptime-targets/${id}`']:
        assert call in h, call


def test_uptime_event_labels_and_options():
    h = _html()
    assert '<option value="uptime.down">' in h
    assert '<option value="uptime.recovered">' in h
    assert '"uptime.down": "🔴 توقف الموقع"' in h
    assert '"uptime.recovered": "🟢 عودة الموقع"' in h
    assert ".sev-info" in h


def test_uptime_loader_runs_with_sched_view():
    h = _html()
    assert "loadUptimeTargets(); loadStatusPages(); loadIncidents(); loadMaintenance(); loadDigestConfig(); }" in h
