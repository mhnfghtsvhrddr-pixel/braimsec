"""اختبارات فلاتر سجل التنبيهات في لوحة BraimSec.

يتحقق من:
1. وجود عناصر الفلاتر الثلاثة (القناة/الحدث/الحالة) وزر التصفير.
2. بناء loadNotifications لسلسلة الاستعلام من قيم الفلاتر.
3. دعم أسماء القنوات الخمس في العرض.
4. صلاحية بنية الجافاسكربت المضمن.
"""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

DASH = Path(__file__).resolve().parent / "index.html"


def _read():
    return DASH.read_text(encoding="utf-8")


def _scripts(html):
    return re.findall(r"<script>(.*?)</script>", html, re.S)


def test_filter_controls_present():
    html = _read()
    for eid in ["notif-f-channel", "notif-f-event", "notif-f-status"]:
        assert f'id="{eid}"' in html, f"missing filter id={eid}"


def test_filter_options_cover_all_values():
    html = _read()
    chan = re.search(r'id="notif-f-channel"(.*?)</select>', html, re.S).group(1)
    for v in ["webhook", "email", "telegram", "slack", "teams"]:
        assert f'value="{v}"' in chan, f"channel option {v} missing"
    ev = re.search(r'id="notif-f-event"(.*?)</select>', html, re.S).group(1)
    for v in ["schedule.alert", "schedule.failed", "vcs.alert", "vcs.failed"]:
        assert f'value="{v}"' in ev, f"event option {v} missing"
    st = re.search(r'id="notif-f-status"(.*?)</select>', html, re.S).group(1)
    for v in ["sent", "failed", "skipped"]:
        assert f'value="{v}"' in st, f"status option {v} missing"


def test_filters_inside_sched_view():
    html = _read()
    sched = re.search(r'<section id="view-sched"[^>]*>(.*?)</section>', html,
                      re.S)
    assert sched, "view-sched section missing"
    for eid in ["notif-f-channel", "notif-f-event", "notif-f-status"]:
        assert f'id="{eid}"' in sched.group(1), f"{eid} not inside view-sched"


def test_load_notifications_builds_query():
    html = _read()
    fn = re.search(r"async function loadNotifications\(\) \{(.*?)\n\}",
                   html, re.S)
    assert fn, "loadNotifications not found"
    body = fn.group(1)
    assert 'qs.set("channel", fc)' in body
    assert 'qs.set("event", fe)' in body
    assert 'qs.set("status", fs)' in body
    assert "/notifications?" in body


def test_reset_filters_function():
    html = _read()
    assert re.search(r"function resetNotifFilters\(\)", html)
    assert "onclick=\"resetNotifFilters()\"" in html


def test_channel_labels_all_five():
    html = _read()
    fn = re.search(r"async function loadNotifications\(\) \{(.*?)\n\}",
                   html, re.S).group(1)
    for ch in ["webhook", "email", "telegram", "slack", "teams"]:
        assert f'"{ch}"' in fn, f"channel label {ch} missing in chAr"


def test_dashboard_js_syntax_valid():
    node = shutil.which("node")
    if not node:
        import pytest
        pytest.skip("node not available")
    for i, src in enumerate(_scripts(_read())):
        with tempfile.NamedTemporaryFile("w", suffix=".js",
                                         delete=False) as f:
            f.write(src)
            tmp = f.name
        r = subprocess.run([node, "--check", tmp], capture_output=True,
                           text=True)
        Path(tmp).unlink(missing_ok=True)
        assert r.returncode == 0, f"JS syntax error in script {i}: {r.stderr}"
