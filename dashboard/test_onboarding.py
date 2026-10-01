"""Onboarding wizard tests for dashboard/index.html.

Static checks (no browser needed):
- wizard overlay + all 5 panes exist with unique ids
- every onclick="ob*"/"wiz*" handler referenced in HTML is defined in the script
- existing dashboard views/tabs are untouched (regression)
- the main <script> block has no JS syntax errors (node --check when available)
"""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

DASH = Path(__file__).resolve().parent / "index.html"
HTML = DASH.read_text(encoding="utf-8")

WIZARD_IDS = [
    "ob-back", "ob-steps", "ob-bar",
    "ob-pane-1", "ob-pane-2", "ob-pane-3", "ob-pane-4", "ob-pane-5",
    "ob-key-create", "ob-key-done", "ob-key-btn", "ob-key-val", "ob-key-err",
    "ob-zip", "ob-scan-btn", "ob-scan-err", "ob-scan-prog", "ob-scan-bar",
    "ob-scan-msg", "ob-scan-result",
    "ob-email", "ob-email-msg", "ob-summary",
]

# Pre-existing structure that must not break (regression guard)
LEGACY_IDS = [
    "view-scans", "view-detail", "view-trends", "view-sched",
    "view-reports", "view-vcs", "view-billing", "view-keys",
    "nav-scans", "nav-trends", "nav-sched", "nav-reports", "nav-vcs",
    "nav-billing", "nav-keys",
    "modal-back", "key-back", "rawkey-back", "sched-back", "vcs-back",
    "repsched-back", "exec-back", "fix-back", "api-key",
]

WIZARD_FUNCS = [
    "obShow", "obGo", "obFinish", "obRestart",
    "obCreateKey", "obCopyKey", "obStartScan", "obAddEmail", "obRenderSummary",
]

LEGACY_FUNCS = [
    "showView", "loadScans", "openDetail", "startScan", "createKey",
    "loadKeys", "loadSchedules", "loadAlertEmails", "loadVcsRepos",
    "loadReportSchedules", "downloadPdf", "downloadSarif", "runDiff",
]


def _main_script():
    blocks = re.findall(r"<script>(.*?)</script>", HTML, re.S)
    mains = [b for b in blocks if "const API" in b]
    assert mains, "main dashboard script block not found"
    return mains[0]


def test_wizard_ids_present_and_unique():
    for wid in WIZARD_IDS:
        n = len(re.findall(rf'id="{re.escape(wid)}"', HTML))
        assert n == 1, f"wizard id {wid!r} found {n} times (expected exactly 1)"


def test_five_panes_and_step_indicator():
    panes = re.findall(r'id="ob-pane-(\d)"', HTML)
    assert sorted(panes) == ["1", "2", "3", "4", "5"], f"panes: {panes}"
    dots = re.findall(r'<span class="wiz-dot">', HTML)
    assert len(dots) == 5, f"expected 5 step dots, found {len(dots)}"


def test_wizard_handlers_defined():
    js = _main_script()
    for fn in WIZARD_FUNCS:
        assert re.search(rf"function {fn}\s*\(", js), f"wizard function {fn}() not defined"
    refs = set(re.findall(r'onclick="([a-zA-Z_$][\w$]*)\(', HTML))
    wiz_refs = {r for r in refs if r.startswith("ob") or r.startswith("wiz")}
    missing = {r for r in wiz_refs if not re.search(rf"function {r}\s*\(", js)}
    assert not missing, f"HTML references undefined wizard handlers: {missing}"


def test_legacy_views_and_handlers_intact():
    for lid in LEGACY_IDS:
        assert f'id="{lid}"' in HTML, f"legacy id {lid!r} missing — wizard broke the dashboard"
    js = _main_script()
    for fn in LEGACY_FUNCS:
        assert re.search(rf"function {fn}\s*\(", js), f"legacy function {fn}() missing"


def test_showview_not_corrupted():
    js = _main_script()
    assert 'if (name === "scans") loadScans();' in js, "showView scans branch corrupted"
    assert "loadScans();loadScans();" not in js, "duplicated loadScans() call"


def test_completion_flag_consistency():
    js = _main_script()
    assert 'const OB_DONE = "braimsec_onboarding_done"' in js
    # flag is read, written and cleared through the constant only
    assert js.count("braimsec_onboarding_done") == 1, "flag string must appear once (via OB_DONE)"
    assert "localStorage.setItem(OB_DONE" in js
    assert "localStorage.getItem(OB_DONE" in js
    assert "localStorage.removeItem(OB_DONE" in js


def test_api_calls_match_backend_contract():
    js = _main_script()
    # key creation mirrors the dashboard's existing createKey() contract
    assert 'api("/keys", {' in js and '"member"' in js
    # scan upload mirrors startScan(): FormData with "file" -> POST /api/scans
    assert 'fd.append("file", file)' in js
    assert 'api("/scans", { method: "POST", body: fd })' in js
    # status polling mirrors openDetail(): GET /api/scans/{id}
    assert re.search(r"api\(`/scans/\$\{id\}`\)", js)
    # alert email mirrors addAlertEmail(): POST /api/alert-emails with JSON
    assert 'api("/alert-emails", {' in js


def test_js_syntax_with_node():
    if not shutil.which("node"):
        import pytest
        pytest.skip("node not available")
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(_main_script())
        path = f.name
    r = subprocess.run(["node", "--check", path], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"JS syntax error: {r.stderr}"
