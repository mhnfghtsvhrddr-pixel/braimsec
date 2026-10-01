"""اختبارات معالج البداية في لوحة BraimSec.

يتحقق من:
1. وجود كل عناصر المعالج (HTML) ووظائفه (JS) وأصنافه (CSS).
2. عدم كسر أي عنصر حالي في اللوحة.
3. صلاحية بنية الجافاسكربت المضمن.
"""
import re
import shutil
import subprocess
from pathlib import Path

DASH = Path(__file__).resolve().parent / "index.html"


def _read():
    return DASH.read_text(encoding="utf-8")


def _scripts(html):
    return re.findall(r"<script>(.*?)</script>", html, re.S)


def test_wizard_overlay_ids_present():
    html = _read()
    for eid in [
        "ob-back", "ob-steps", "ob-bar",
        "ob-pane-1", "ob-pane-2", "ob-pane-3", "ob-pane-4", "ob-pane-5",
        "ob-key-create", "ob-key-done", "ob-key-btn", "ob-key-val", "ob-key-err",
        "ob-zip", "ob-scan-btn", "ob-scan-err", "ob-scan-prog",
        "ob-scan-bar", "ob-scan-msg", "ob-scan-result",
        "ob-email", "ob-email-msg", "ob-summary",
    ]:
        assert f'id="{eid}"' in html, f"missing element id={eid}"


def test_wizard_panes_visibility():
    html = _read()
    # الخطوة 1 ظاهرة افتراضياً، البقية مخفية
    assert re.search(r'id="ob-pane-1"[^>]*>', html).group(0).count("hidden") == 0
    for i in range(2, 6):
        m = re.search(rf'id="ob-pane-{i}"[^>]*>', html)
        assert m and "hidden" in m.group(0), f"ob-pane-{i} should start hidden"


def test_wizard_js_functions_defined():
    html = _read()
    js = "\n".join(_scripts(html))
    for fn in [
        "function obShow()", "function obGo(", "function obFinish(",
        "function obRestart()", "async function obCreateKey()",
        "function obCopyKey()", "async function obStartScan()",
        "async function obAddEmail()", "function obRenderSummary()",
    ]:
        assert fn in js, f"missing {fn}"


def test_wizard_css_classes_defined():
    html = _read()
    css = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
    for cls in [
        "wiz-modal", "wiz-head", "wiz-steps", "wiz-step", "wiz-dot",
        "wiz-progress", "wiz-pane", "wiz-points", "wiz-point", "wiz-nav",
        "lead", "keybox", "warn",
    ]:
        assert re.search(r"\." + cls + r"\s*[{,]", css), f"missing CSS .{cls}"


def test_wizard_step_indicator_wired():
    html = _read()
    # 5 مؤشرات خطوات داخل ob-steps
    steps = re.search(r'id="ob-steps">(.*?)</div>\s*<div class="wiz-progress">', html, re.S)
    assert steps and steps.group(1).count("wiz-dot") == 5
    # obGo يحدّث الشريط والمؤشرات
    js = "\n".join(_scripts(html))
    assert 'getElementById("ob-bar")' in js
    assert 'getElementById("ob-steps")' in js


def test_wizard_shows_once_and_restartable():
    html = _read()
    js = "\n".join(_scripts(html))
    assert "braimsec_onboarding_done" in js  # علامة الإكمال
    assert "obRestart" in js
    # زر إعادة المعالج في الترويسة
    assert re.search(r'onclick="obRestart\(\)"', html)


def test_wizard_js_syntax_valid():
    node = shutil.which("node")
    if not node:
        return  # يُتخطى عند غياب node
    html = _read()
    tmp = Path("/tmp/ob_wiz_check.js")
    tmp.write_text("\n".join(_scripts(html)), encoding="utf-8")
    r = subprocess.run([node, "--check", str(tmp)], capture_output=True, text=True)
    assert r.returncode == 0, f"JS syntax error: {r.stderr}"


def test_existing_dashboard_intact():
    html = _read()
    # التبويبات والعناصر الحالية لم تُكسر
    for token in [
        'id="view-scans"', 'id="view-sched"', 'id="view-detail"',
        'id="api-key"', "loadScans();", 'id="keys-wrap"', 'id="new-key-btn"',
        "function showView(", "async function api(",
    ]:
        assert token in html, f"existing dashboard element broken/missing: {token}"


def test_wizard_uses_correct_api_endpoints():
    js = "\n".join(_scripts(_read()))
    # المعالج يستخدم نفس عقود الـAPI الحالية
    assert 'api("/keys"' in js          # إنشاء المفتاح
    assert 'api("/scans"' in js          # أول فحص
    assert 'api("/alert-emails"' in js   # التنبيهات
    assert 'api(`/scans/${id}`)' in js   # متابعة حالة الفحص
