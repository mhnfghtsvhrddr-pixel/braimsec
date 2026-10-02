"""Dashboard smoke tests for the maintenance windows section."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "index.html")


def _html():
    with open(HTML, encoding="utf-8") as f:
        return f.read()


def test_maintenance_section_markup():
    h = _html()
    for needle in ['id="mnt-title"', 'id="mnt-start"', 'id="mnt-end"',
                   'id="mnt-desc"', 'id="maintenance-wrap"',
                   "addMaintenance()", "نافذة الصيانة",
                   "نوافذ الصيانة المجدولة"]:
        assert needle in h, needle


def test_maintenance_js_functions():
    h = _html()
    for fn in ["async function loadMaintenance()",
               "async function addMaintenance()",
               "async function cancelMaintenance(id)",
               "async function delMaintenance(id)",
               "const MNT_ST ="]:
        assert fn in h, fn


def test_maintenance_api_calls_wired():
    h = _html()
    for call in ['api("/maintenance")',
                 'api(`/maintenance/${id}/cancel`',
                 'api(`/maintenance/${id}`']:
        assert call in h, call


def test_maintenance_loader_runs_with_sched_view():
    h = _html()
    assert "loadMaintenance(); loadDigestConfig(); }" in h
