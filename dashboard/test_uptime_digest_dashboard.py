"""Dashboard smoke tests for the uptime digest section."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "index.html")


def _html():
    with open(HTML, encoding="utf-8") as f:
        return f.read()


def test_digest_section_markup():
    h = _html()
    for needle in ['id="dg-enabled"', 'id="dg-freq"', 'id="dg-dow"',
                   'id="dg-dom"', 'id="dg-hour"', 'id="digest-wrap"',
                   "saveDigestConfig()", "previewDigest()",
                   "sendDigestNow()", "تقرير الجهوزية الدوري"]:
        assert needle in h, needle


def test_digest_js_functions():
    h = _html()
    for fn in ["async function loadDigestConfig()",
               "async function saveDigestConfig()",
               "async function previewDigest()",
               "async function sendDigestNow()"]:
        assert fn in h, fn


def test_digest_api_calls_wired():
    h = _html()
    for call in ['api("/uptime-digest/config")',
                 'api("/uptime-digest/preview?days=7")',
                 'api("/uptime-digest/send"']:
        assert call in h, call


def test_digest_loader_runs_with_sched_view():
    h = _html()
    assert "loadDigestConfig(); }" in h
