"""Executive report builder + PDF unit tests (deterministic, Arabic).

- builder: sections, severity counts, trend verdicts (improving /
  worsening / stable / insufficient), plain-language top-10 with
  recommendations, compliance coverage, fail-closed on empty scope.
- PDF: byte-deterministic per report, starts with %PDF-, embeds the
  Unicode font, timestamp is the only allowed variance.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from executive import (  # noqa: E402
    EXECUTIVE_REPORT_VERSION,
    build_executive_report,
)
from executive_pdf import render_executive_pdf  # noqa: E402
from builder import ReportError  # noqa: E402

GEN = "2026-10-01T00:00:00+00:00"


def _scans():
    return [
        {"id": "s1", "target_name": "webapp",
         "finished_at": "2026-09-01T00:00:00+00:00", "total_findings": 8},
        {"id": "s2", "target_name": "webapp",
         "finished_at": "2026-10-01T00:00:00+00:00", "total_findings": 5},
    ]


def _findings():
    return [
        {"tool": "semgrep", "rule_id": "x.braimsec.inject.sqli",
         "severity": "error", "message": "tainted sql", "file": "db.py",
         "line": 12},
        {"tool": "semgrep", "rule_id": "x.braimsec.taint.xss-reflected",
         "severity": "error", "message": "xss", "file": "views.py",
         "line": 30},
        {"tool": "gitleaks", "rule_id": "generic-api-key",
         "severity": "error", "message": "key", "file": ".env", "line": 1},
        {"tool": "semgrep",
         "rule_id": "x.braimsec.dockerfile.secrets-in-env",
         "severity": "warning", "message": "secret", "file": "Dockerfile",
         "line": 5},
        {"tool": "semgrep", "rule_id": "something.unknown.rule",
         "severity": "note", "message": "m", "file": "a.py", "line": 1},
    ]


def _comp():
    return {"soc2_mapped": 3, "iso_mapped": 2, "total": 5,
            "map_version": "2.1.0"}


def _build(**kw):
    kw.setdefault("generated_at", GEN)
    return build_executive_report("Acme", "Web", _scans(), _findings(),
                                  **kw)


# --- builder --------------------------------------------------------------

def test_sections_and_version():
    r = _build(prev_counts={"error": 4, "warning": 3, "note": 1},
               compliance=_comp())
    assert r["meta"]["report_version"] == EXECUTIVE_REPORT_VERSION
    assert r["meta"]["kind"] == "executive"
    assert r["meta"]["provenance"] == "deterministic"
    assert set(r) == {"meta", "cover", "posture", "risk_table",
                      "top_findings", "compliance", "recent_scans",
                      "honesty"}


def test_counts_and_trend_improving():
    r = _build(prev_counts={"error": 4, "warning": 3, "note": 1},
               compliance=_comp())
    p = r["posture"]
    assert p["critical"] == 3 and p["high"] == 1 and p["total"] == 5
    assert p["trend"] == "improving" and p["verdict"] == "يتحسن"
    assert "3" in p["summary"] and "يتحسن" in p["summary"]


def test_trend_worsening_stable_insufficient():
    r = _build(prev_counts={"error": 1, "warning": 0, "note": 0},
               compliance=_comp())
    assert r["posture"]["trend"] == "worsening"
    assert r["posture"]["verdict"] == "يتدهور"
    r = _build(prev_counts={"error": 3, "warning": 1, "note": 1},
               compliance=_comp())
    assert r["posture"]["trend"] == "stable"
    assert r["posture"]["verdict"] == "مستقر"
    r = _build(compliance=_comp())  # first scan in scope
    assert r["posture"]["trend"] == "insufficient"
    assert "لا توجد بيانات كافية" in r["posture"]["verdict"]


def test_posture_clean_when_no_critical():
    r = build_executive_report(
        "Acme", None, _scans(), [], prev_counts={"error": 2},
        generated_at=GEN)
    assert r["posture"]["critical"] == 0 and r["posture"]["high"] == 0
    assert "الوضع العام جيد" in r["posture"]["summary"]
    assert r["top_findings"] == []


def test_top_findings_plain_language_and_cap():
    many = _findings() * 2  # 10 known findings
    many += [{"tool": "semgrep", "rule_id": "something.unknown.rule",
              "severity": s, "message": "m", "file": "x.py", "line": i}
             for i, s in enumerate(("error", "warning", "note"))]
    # 13 findings -> cap at 10; unknown rules ride along
    r = build_executive_report("Acme", None, _scans(), many,
                               prev_counts={"error": 1}, generated_at=GEN)
    top = r["top_findings"]
    assert len(top) == 10
    titles = [t["title"] for t in top]
    assert "ثغرة حقن في قاعدة البيانات" in titles
    assert "ثغرة برمجة عبر المواقع" in titles
    assert "بيانات سرية مكشوفة في الكود" in titles
    assert "مشكلة في إعداد حاوية Docker" in titles
    # unknown rule -> conservative generic fallback, never invented
    assert "نتيجة فحص تقنية" in titles
    for t in top:
        assert t["meaning"] and t["recommendation"] and t["where"]
        assert t["severity"] in ("حرجة", "متوسطة", "منخفضة")
        assert t["provenance"] == "deterministic"
    # errors first
    sevs = [t["severity"] for t in top]
    assert sevs.index("متوسطة") > sevs.index("حرجة")


def test_risk_table_labels_and_meanings():
    r = _build(prev_counts={"error": 1}, compliance=_comp())
    rt = {row["severity"]: row for row in r["risk_table"]}
    assert rt["حرجة"]["count"] == 3
    assert rt["متوسطة"]["count"] == 1
    assert rt["منخفضة"]["count"] == 1
    assert all(row["meaning"] for row in r["risk_table"])


def test_compliance_coverage_pct():
    r = _build(prev_counts={"error": 1}, compliance=_comp())
    c = r["compliance"]
    assert c["soc2_coverage_pct"] == 60
    assert c["iso_coverage_pct"] == 40
    assert c["map_version"] == "2.1.0"
    assert "متحفظ" in c["note"]


def test_compliance_zero_total_safe():
    r = build_executive_report(
        "Acme", None, _scans(), [],
        compliance={"soc2_mapped": 0, "iso_mapped": 0, "total": 0,
                    "map_version": "2.1.0"},
        generated_at=GEN)
    assert r["compliance"]["soc2_coverage_pct"] == 0
    assert r["compliance"]["iso_coverage_pct"] == 0


def test_refuses_empty_scope():
    with pytest.raises(ReportError):
        build_executive_report("Acme", None, [], [], generated_at=GEN)


def test_recent_scans_capped_and_honesty():
    r = _build(prev_counts={"error": 1}, compliance=_comp())
    assert len(r["recent_scans"]) == 2
    assert r["recent_scans"][-1]["target"] == "webapp"
    assert "حرجة = error" in r["honesty"]["severity_mapping"]
    assert "لا يستخدم الذكاء الاصطناعي" in r["honesty"]["method"]


# --- PDF ------------------------------------------------------------------

def test_pdf_deterministic_and_arabic():
    r = _build(prev_counts={"error": 4, "warning": 3, "note": 1},
               compliance=_comp())
    a, b = render_executive_pdf(r), render_executive_pdf(r)
    assert a == b, "same report must render byte-identical"
    assert a.startswith(b"%PDF-")
    assert b"DejaVuSans" in a, "Unicode font must be embedded"
    r2 = _build(prev_counts={"error": 4, "warning": 3, "note": 1},
                compliance=_comp())
    r2["meta"]["generated_at"] = "2026-10-02T00:00:00+00:00"
    assert render_executive_pdf(r2) != a


def test_pdf_empty_findings():
    r = build_executive_report("Acme", None, _scans(), [],
                               generated_at=GEN)
    pdf = render_executive_pdf(r)
    assert pdf.startswith(b"%PDF-")
