"""Dashboard smoke tests for the TLS certificate monitoring section.

index.html must carry the section markup, the JS functions, the
cert.expiry event label/option, and the API calls the JS relies on.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "index.html")


def _html():
    with open(HTML, encoding="utf-8") as f:
        return f.read()


def test_cert_section_markup():
    h = _html()
    for needle in ['id="cert-section"', 'id="cert-host"', 'id="cert-port"',
                   'id="cert-warn"', 'id="cert-wh"', 'id="cert-wrap"',
                   "addCertDomain()", "مراقبة شهادات TLS"]:
        assert needle in h, needle


def test_cert_js_functions():
    h = _html()
    for fn in ["async function loadCertDomains()",
               "async function addCertDomain()",
               "async function delCertDomain(id)",
               "async function checkCertDomain(id)",
               "async function toggleCertDomain(id, enabled)",
               "const CERT_ST ="]:
        assert fn in h, fn


def test_cert_api_calls_wired():
    h = _html()
    for call in ['api("/cert-domains")',
                 'api(`/cert-domains/${id}/check`',
                 'api(`/cert-domains/${id}`']:
        assert call in h, call


def test_cert_event_label_and_option():
    h = _html()
    assert '<option value="cert.expiry">' in h
    assert '"cert.expiry": "🔒 انتهاء شهادة TLS"' in h


def test_cert_loader_runs_with_sched_view():
    h = _html()
    # the JS that refreshes the scheduling tab must include cert domains
    assert h.count("loadCertDomains(); }") >= 2
