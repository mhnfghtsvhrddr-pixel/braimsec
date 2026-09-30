"""Part 5 (report & compliance engine) unit tests: compliance map,
report builder (five sections, ordering, grades, fail-closed honesty),
and deterministic PDF rendering incl. Arabic."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from builder import (  # noqa: E402
    REPORT_VERSION, ReportError, build_report, lookup_compliance,
)
from pdf import render_pdf  # noqa: E402

GEN = "2026-01-01T00:00:00+00:00"


def _scan(**kw):
    s = {"id": "scan_1", "target_name": "acme-web",
         "status": "done", "finished_at": GEN, "engines_json": None}
    s.update(kw)
    return s


def _f(fid, **kw):
    f = {"id": fid, "tool": "semgrep", "rule_id": "some.rule",
         "severity": "error", "message": "m", "file": "a.py", "line": fid,
         "ai_verdict": None, "ai_confidence": None, "ai_explanation": None,
         "fix_diff": None, "fix_explanation": None, "fix_confidence": None,
         "fix_caveats": None}
    f.update(kw)
    return f


# --- compliance map -------------------------------------------------------

def test_map_versioned_and_conservative():
    assert REPORT_VERSION == "1.1.0"
    # dotted check_id (as semgrep emits it) must match
    hit = lookup_compliance(
        "home.hatch.workspace.rules.braimsec.taint.ssrf-requests", "semgrep")
    assert hit["owasp"]["code"] == "A10:2021"
    assert hit["cwe"]["id"] == "CWE-918"
    assert hit["map_version"] == "1.0.0"
    assert hit["provenance"] == "deterministic"


def test_gitleaks_tool_level_mapping():
    hit = lookup_compliance("generic-api-key", "gitleaks")
    assert hit["cwe"]["id"] == "CWE-798"
    assert hit["owasp"]["code"] == "A07:2021"


def test_unknown_rule_unmapped():
    assert lookup_compliance("python.lang.security.foo", "semgrep") is None


# --- builder --------------------------------------------------------------

def test_five_sections_and_ordering():
    fs = [_f(1, severity="warning"),
          _f(2, severity="error", ai_verdict="vulnerable", ai_confidence=0.9),
          _f(3, severity="note")]
    r = build_report(_scan(), fs, generated_at=GEN)
    assert set(r) == {"meta", "executive", "findings", "honesty",
                      "compliance", "fix_plan"}
    assert [f["finding_id"] for f in r["findings"]] == [2, 1, 3]
    assert r["executive"]["grade"] == "B"  # 1 deterministic error
    assert r["executive"]["deterministic_errors"] == 1
    assert r["executive"]["ai_confirmed_errors"] == 1
    assert "confirmed_errors" not in r["executive"]  # v1.0 field retired
    assert r["executive"]["delta"]["baseline"].startswith("first scan")


def test_grade_f_many_deterministic_errors():
    fs = [_f(i, ai_verdict="vulnerable", ai_confidence=0.9)
          for i in range(1, 12)]
    r = build_report(_scan(), fs, generated_at=GEN)
    assert r["executive"]["grade"] == "F"
    assert r["executive"]["deterministic_errors"] == 11
    assert r["executive"]["ai_confirmed_errors"] == 11


def test_grade_counts_unreviewed_errors():
    # v1.1 behavior change: the grade no longer depends on AI review.
    # An engine-reported error counts whether or not the AI looked at it —
    # otherwise the grade would hinge on AI quota spend and AI false
    # negatives would inflate it.
    fs = [_f(i) for i in range(1, 12)]  # ai_verdict=None: never reviewed
    r = build_report(_scan(), fs, generated_at=GEN)
    assert r["executive"]["grade"] == "F"
    assert r["executive"]["deterministic_errors"] == 11
    assert r["executive"]["ai_confirmed_errors"] == 0


def test_ai_rejected_error_still_counts_in_grade():
    # The core honesty fix: an error the AI rejected ("not_vulnerable" is a
    # measured ~15% FN bucket on config/secrets) must not vanish from the
    # posture grade.
    fs = [_f(1, severity="error", ai_verdict="not_vulnerable",
             ai_confidence=0.4),
          _f(2, severity="error", ai_verdict="vulnerable",
             ai_confidence=0.9)]
    r = build_report(_scan(), fs, generated_at=GEN)
    exe = r["executive"]
    assert exe["deterministic_errors"] == 2
    assert exe["ai_confirmed_errors"] == 1  # supplementary opinion only
    assert exe["grade"] == "B"  # 2 deterministic errors
    assert "AI verdicts" in exe["grade_basis"]
    # honesty appendix reports both numbers too
    cov = r["honesty"]["coverage"]
    assert cov["deterministic_errors"] == 2
    assert cov["ai_confirmed_errors"] == 1


def test_delta_vs_previous():
    fs = [_f(1, severity="error", ai_verdict="vulnerable"),
          _f(2, severity="warning")]
    prev = {"scan_id": "scan_0", "finished_at": GEN,
            "counts": {"error": 3, "warning": 0, "note": 0}, "grade": "C"}
    r = build_report(_scan(), fs, prev=prev, generated_at=GEN)
    d = r["executive"]["delta"]
    assert d["error"] == -2 and d["warning"] == 1
    assert d["grade"] == {"prev": "C", "now": "B"}


def test_top_risks_cite_finding_ids_with_provenance():
    fs = [_f(7, ai_verdict="vulnerable", ai_confidence=0.88,
             ai_explanation="شرح عربي")]
    r = build_report(_scan(), fs, generated_at=GEN)
    top = r["executive"]["top_risks"]
    assert len(top) == 1
    assert top[0]["finding_id"] == 7
    assert top[0]["provenance"] == "ai"
    assert top[0]["confidence"] == 0.88


def test_honesty_fail_closed():
    with pytest.raises(ReportError):
        build_report({}, [], generated_at=GEN)
    with pytest.raises(ReportError):
        build_report({"id": "x"}, [], generated_at=GEN)


def test_honesty_appendix_content():
    fs = [_f(1, rule_id="x.rules.braimsec.taint.ssrf-requests")]
    r = build_report(_scan(), fs, target_dir=None, generated_at=GEN)
    h = r["honesty"]
    assert h["scope"]["target"] == "acme-web"
    assert h["not_covered"], "not_covered must never be empty"
    assert h["limitations"], "limitations must never be empty"
    joined = " ".join(h["not_covered"])
    assert "AI review: 0/1" in joined
    assert "zero-retention" in joined  # taint sources gone
    assert "not recorded" in joined    # engine versions
    assert r["findings"][0]["compliance"]["owasp"]["code"] == "A10:2021"


def test_compliance_rollup_and_unmapped():
    fs = [_f(1, rule_id="r.braimsec.taint.ssrf-requests"),
          _f(2, rule_id="nope.unknown")]
    r = build_report(_scan(), fs, generated_at=GEN)
    assert r["compliance"]["by_owasp"] == {"A10:2021": 1}
    assert r["compliance"]["unmapped"] == 1


def test_fix_plan_quick_wins():
    fs = [_f(1, fix_diff="--- a\n+++ b\n", fix_confidence=0.9,
             fix_explanation="إصلاح", fix_caveats="none"),
          _f(2)]
    r = build_report(_scan(), fs, generated_at=GEN)
    assert [q["finding_id"] for q in r["fix_plan"]["quick_wins"]] == [1]
    assert [q["finding_id"] for q in r["fix_plan"]["architectural"]] == [2]
    assert r["fix_plan"]["quick_wins"][0]["provenance"] == "ai"


# --- PDF ------------------------------------------------------------------

def test_pdf_deterministic_and_arabic():
    fs = [_f(1, rule_id="r.braimsec.taint.ssrf-requests",
             ai_verdict="vulnerable", ai_confidence=0.95,
             ai_explanation="هذا ثغرة SSRF حقيقية في requests.get")]
    r = build_report(_scan(), fs, generated_at=GEN)
    a, b = render_pdf(r), render_pdf(r)
    assert a == b, "same report must render byte-identical"
    assert a.startswith(b"%PDF-")
    assert b"DejaVuSans" in a, "Unicode font must be embedded"
    # timestamp is the only allowed variance
    r2 = build_report(_scan(), fs, generated_at="2026-02-02T00:00:00+00:00")
    assert render_pdf(r2) != a


def test_pdf_empty_scan():
    r = build_report(_scan(), [], generated_at=GEN)
    pdf = render_pdf(r)
    assert pdf.startswith(b"%PDF-")
    assert r["executive"]["grade"] == "A"
