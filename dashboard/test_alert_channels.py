"""اختبارات قسم قنوات المراسلة الفورية في لوحة BraimSec.

يتحقق من:
1. وجود عناصر HTML لكل قناة (تيليجرام / Slack / Teams).
2. وجود دوال JS (تحميل/إضافة/حذف) لكل قناة وربطها عند فتح تبويب الجدولة.
3. عدم تسريب أسرار الـwebhooks في الواجهة (عرض مقنّع فقط).
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


def test_channel_section_ids_present():
    html = _read()
    for eid in [
        "tg-status", "tg-chat-new", "tg-label-new", "tg-wrap",
        "slack-url-new", "slack-label-new", "slack-wrap",
        "teams-url-new", "teams-label-new", "teams-wrap",
    ]:
        assert f'id="{eid}"' in html, f"missing element id={eid}"


def test_channel_section_inside_sched_view():
    html = _read()
    sched = re.search(r'<section id="view-sched"[^>]*>(.*?)</section>', html, re.S)
    assert sched, "view-sched section missing"
    for eid in ["tg-wrap", "slack-wrap", "teams-wrap"]:
        assert f'id="{eid}"' in sched.group(1), f"{eid} not inside view-sched"


def test_channel_js_functions_present():
    html = _read()
    for fn in [
        "loadAlertChannels",
        "loadTelegramChats", "addTelegramChat", "deleteTelegramChat",
        "loadSlackWebhooks", "addSlackWebhook", "deleteSlackWebhook",
        "loadTeamsWebhooks", "addTeamsWebhook", "deleteTeamsWebhook",
    ]:
        assert re.search(rf"function {fn}\s*\(", html), f"missing JS function {fn}"


def test_channels_loaded_with_sched_view():
    html = _read()
    # كل مسار يعيد تحميل تبويب الجدولة يجب أن يشمل قنوات المراسلة
    for m in re.finditer(r"loadSchedules\(\); loadAlertEmails\(\);(.*?)\n", html):
        assert "loadAlertChannels()" in m.group(1), \
            "sched refresh path missing loadAlertChannels()"


def test_channel_endpoints_used():
    html = _read()
    for ep in ['"/telegram-chats"', '"/slack-webhooks"', '"/teams-webhooks"']:
        assert ep in html, f"endpoint {ep} not wired in dashboard JS"


def test_no_webhook_secret_leak_in_ui():
    html = _read()
    # الواجهة تعرض فقط النسخة المقنعة — لا حقل يعرض الـURL الكامل
    assert "webhook_url_masked" in html
    assert "webhook_url\":" not in html.replace("webhook_url_masked", "")


def test_delete_confirmations_present():
    html = _read()
    assert html.count("confirm(") >= 3


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
