"""Dashboard smoke tests for the public status page + incident log section."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "index.html")


def _html():
    with open(HTML, encoding="utf-8") as f:
        return f.read()


def test_status_section_markup():
    h = _html()
    for needle in ['id="status-section"', 'id="sp-title"', 'id="sp-slug"',
                   'id="sp-headline"', 'id="status-pages-wrap"',
                   'id="inc-title"', 'id="inc-impact"', 'id="inc-msg"',
                   'id="incidents-wrap"', "addStatusPage()",
                   "addIncident()", "صفحة الحالة العامة"]:
        assert needle in h, needle


def test_status_js_functions():
    h = _html()
    for fn in ["async function loadStatusPages()",
               "async function addStatusPage()",
               "async function delStatusPage(id)",
               "async function toggleStatusPage(id, enabled)",
               "async function loadIncidents()",
               "async function addIncident()",
               "async function addIncidentUpdate(id)",
               "async function resolveIncident(id)",
               "async function delIncident(id)",
               "const INC_ST ="]:
        assert fn in h, fn


def test_status_api_calls_wired():
    h = _html()
    for call in ['api("/status-pages")',
                 'api(`/status-pages/${id}`',
                 'api("/incidents")',
                 'api(`/incidents/${id}/updates`',
                 'api(`/incidents/${id}/resolve`',
                 'api(`/incidents/${id}`',
                 '/status/${esc(p.slug)}']:
        assert call in h, call


def test_status_loader_runs_with_sched_view():
    h = _html()
    assert "loadStatusPages();" in h
    assert "loadIncidents();" in h
    assert "loadStatusPages(); loadIncidents(); loadMaintenance(); loadDigestConfig(); }" in h
