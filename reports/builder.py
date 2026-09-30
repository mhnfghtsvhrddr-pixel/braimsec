"""BraimSec report builder — Proposal Part 5 (v1).

Assembles the five-section CISO report as pure data. Pure function of
stored data: no new scanning, no LLM calls. Deterministic: the same
inputs (+ the same ``generated_at``) always produce the same report.

Sections (§2):
  1. executive — one-page posture: grade A-F, severity counts, delta vs
     the previous scan, top-3 risks (each citing finding IDs).
  2. findings — every finding, ordered by severity then AI confidence,
     with AI verdict, compliance mapping, taint trace and fix suggestion.
  3. honesty — MANDATORY appendix: scope, engine versions, coverage,
     what was NOT covered, known limitations. The builder refuses to
     produce a report without it (fail-closed).
  4. compliance — OWASP/CWE rollup + unmapped count.
  5. fix_plan — prioritized checklist: quick wins vs architectural.

Provenance (§4.3): every AI-derived string carries
``provenance: "ai"`` + confidence; deterministic sections carry
``provenance: "deterministic"``. Nothing is silently rewritten.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import yaml
except Exception:  # noqa: BLE001
    yaml = None

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scanner"))
try:
    from taintflow import extract_taint_path, _is_taint_rule  # noqa: E402
except Exception:  # noqa: BLE001
    extract_taint_path = None

    def _is_taint_rule(rule_id):  # fallback if taintflow import fails
        return bool(rule_id) and "braimsec.taint." in rule_id

REPORT_VERSION = "1.1.0"
MAP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "compliance_map.yaml")

SEVERITY_RANK = {"note": 0, "warning": 1, "error": 2}

# Posture grade from DETERMINISTIC error count (v1.1 heuristic, documented):
# the grade counts engine-reported error-severity findings and never depends
# on AI verdicts. Rationale: the AI reviewer has a measured ~15% false-negative
# rate on config/secrets holdout, and gating the grade on AI opinions would
# (a) inflate the grade whenever the AI misses a real vulnerability, and
# (b) make the grade depend on whether the customer paid for AI review.
# AI confirmations are reported separately as supplementary opinion.
GRADE_BANDS = [(0, "A"), (2, "B"), (5, "C"), (10, "D")]

KNOWN_LIMITATIONS = [
    "Taint-flow traces are intra-file and intra-procedural (Python, v1); "
    "cross-file propagation is not traced.",
    "The report is a point-in-time snapshot of stored scan data — it does "
    "not re-scan and does not reflect code changed after the scan finished.",
    "The posture grade is deterministic: it counts engine-reported "
    "error-severity findings only. AI verdicts are opinions with confidence "
    "scores, not proofs, and are reported separately — never as grade inputs.",
    "Compliance mappings are conservative by design: unmapped findings are "
    "reported as unmapped, never force-fitted to a standard.",
]


class ReportError(Exception):
    """Raised when a report cannot be built honestly."""


# ---------------------------------------------------------------------------
# Compliance mapping
# ---------------------------------------------------------------------------

def _load_map():
    if yaml is None:
        return {"version": "unavailable", "mappings": []}
    with open(MAP_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


_MAP = None


def compliance_map():
    global _MAP
    if _MAP is None:
        _MAP = _load_map()
    return _MAP


def lookup_compliance(rule_id, tool):
    """-> {owasp, cwe, pci, soc2, map_version} or None (unmapped)."""
    cmap = compliance_map()
    for m in cmap.get("mappings", []):
        if m.get("tool") and tool == m["tool"]:
            hit = m
            break
        rid = m.get("rule") or ""
        if rid and rule_id and (rule_id == rid or rule_id.endswith(rid)):
            hit = m
            break
    else:
        return None
    return {
        "owasp": m.get("owasp"), "cwe": m.get("cwe"),
        "pci": m.get("pci"), "soc2": m.get("soc2"),
        "map_version": cmap.get("version", "unknown"),
        "provenance": "deterministic",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_error(f):
    """Engine-reported error severity — the deterministic grade input."""
    return f.get("severity") == "error"


def _ai_confirmed(f):
    """AI opinion only — supplementary signal, never a grade input."""
    return f.get("ai_verdict") == "vulnerable"


def _grade(deterministic_errors):
    for cap, g in GRADE_BANDS:
        if deterministic_errors <= cap:
            return g
    return "F"


def _ordered(findings):
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK.get(f.get("severity") or "warning", 1),
                       -(f.get("ai_confidence") or 0),
                       f.get("id") or 0))


def _taint_trace(finding, target_dir):
    if not _is_taint_rule(finding.get("rule_id")):
        return None
    if extract_taint_path is None or not target_dir:
        return None
    try:
        t = extract_taint_path(dict(finding), target_dir)
    except Exception:  # noqa: BLE001 - best-effort enrichment
        return None
    if not t.get("available"):
        return None
    t["provenance"] = "deterministic"
    return t


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_report(scan, findings, prev=None, target_dir=None,
                 generated_at=None):
    """Build the five-section report dict. Raises ReportError if the
    honesty appendix cannot be completed."""
    scan_id = (scan or {}).get("id")
    target = (scan or {}).get("target_name")
    if not scan_id or not target:
        raise ReportError("refusing: scan id/target missing — "
                          "a report without scope is dishonest")

    findings = _ordered(list(findings or []))
    counts = {"error": 0, "warning": 0, "note": 0}
    for f in findings:
        counts[f.get("severity") or "warning"] = \
            counts.get(f.get("severity") or "warning", 0) + 1
    det_errors = sum(1 for f in findings if _is_error(f))
    ai_confirmed_errors = sum(1 for f in findings
                              if _is_error(f) and _ai_confirmed(f))

    # --- 1. executive ----------------------------------------------------
    top3 = []
    for f in [x for x in findings if x.get("severity") == "error"][:3]:
        ai = f.get("ai_verdict") not in (None, "", "skipped")
        top3.append({
            "finding_id": f.get("id"), "file": f.get("file"),
            "line": f.get("line"), "message": f.get("message"),
            "provenance": "ai" if ai else "deterministic",
            "confidence": f.get("ai_confidence"),
        })
    if prev and prev.get("counts"):
        delta = {"prev_scan_id": prev.get("scan_id"),
                 "prev_finished_at": prev.get("finished_at"),
                 "error": counts["error"] - prev["counts"].get("error", 0),
                 "warning": counts["warning"] - prev["counts"].get("warning", 0),
                 "note": counts["note"] - prev["counts"].get("note", 0),
                 "grade": {"prev": prev.get("grade"),
                           "now": _grade(det_errors)},
                 "provenance": "deterministic"}
    else:
        delta = {"baseline": "first scan of this target — no previous report",
                 "provenance": "deterministic"}
    executive = {
        "grade": _grade(det_errors),
        "grade_basis": (f"{det_errors} deterministic error(s); the grade "
                        "counts engine-reported errors only — AI verdicts "
                        "are supplementary opinion, not grade inputs"),
        "counts": counts,
        "deterministic_errors": det_errors,
        "ai_confirmed_errors": ai_confirmed_errors,
        "total_findings": len(findings),
        "delta": delta,
        "top_risks": top3,
        "provenance": "deterministic",
    }

    # --- 2. findings ------------------------------------------------------
    traced = 0
    detail = []
    for f in findings:
        comp = lookup_compliance(f.get("rule_id"), f.get("tool"))
        trace = _taint_trace(f, target_dir)
        traced += 1 if trace else 0
        ai = f.get("ai_verdict") not in (None, "", "skipped")
        entry = {
            "finding_id": f.get("id"), "severity": f.get("severity"),
            "tool": f.get("tool"), "rule_id": f.get("rule_id"),
            "message": f.get("message"), "file": f.get("file"),
            "line": f.get("line"),
            "ai": {"verdict": f.get("ai_verdict"),
                   "confidence": f.get("ai_confidence"),
                   "explanation": f.get("ai_explanation"),
                   "provenance": "ai" if ai else "not-reviewed"},
            "compliance": comp or {"unmapped": True,
                                   "map_version":
                                   compliance_map().get("version"),
                                   "provenance": "deterministic"},
            "taint_trace": trace,
            "fix": ({"diff": f.get("fix_diff"),
                     "explanation": f.get("fix_explanation"),
                     "confidence": f.get("fix_confidence"),
                     "caveats": f.get("fix_caveats"),
                     "provenance": "ai"}
                    if f.get("fix_diff") else None),
        }
        detail.append(entry)

    # --- 3. honesty (mandatory, fail-closed) -------------------------------
    import json as _json
    engines = None
    try:
        engines = _json.loads(scan.get("engines_json") or "null")
    except Exception:  # noqa: BLE001
        engines = None
    if isinstance(engines, dict):  # tasks.py records a {name: version} dict
        engines = [{"name": k, "version": v} for k, v in engines.items()]
    if not isinstance(engines, list):
        engines = None
    ai_reviewed = sum(1 for f in findings
                      if f.get("ai_verdict") not in (None, "", "skipped"))
    sca_n = sum(1 for f in findings if f.get("tool") == "osv")
    with_fix = sum(1 for f in findings if f.get("fix_diff"))
    not_covered = []
    if sca_n:
        not_covered.append(f"SCA: {sca_n} dependency finding(s) recorded")
    else:
        not_covered.append("SCA: no dependency findings recorded — "
                           "manifests absent or SCA skipped for this scan")
    if ai_reviewed < len(findings):
        not_covered.append(
            f"AI review: {ai_reviewed}/{len(findings)} findings reviewed — "
            "unreviewed findings are still counted in the deterministic "
            "grade; AI confirmation is supplementary opinion only")
    else:
        not_covered.append(f"AI review: all {len(findings)} findings reviewed")
    taint_total = sum(1 for f in findings
                      if _is_taint_rule(f.get("rule_id")))
    if taint_total and not target_dir:
        not_covered.append(
            f"Taint traces: sources unavailable ({taint_total} taint "
            "finding(s)) — cleaned up per zero-retention policy")
    elif taint_total:
        not_covered.append(f"Taint traces: {traced}/{taint_total} attached")
    if not engines:
        not_covered.append("Engine versions: not recorded for this scan "
                           "(predates engine-version logging)")
    honesty = {
        "scope": {"scan_id": scan_id, "target": target,
                  "finished_at": scan.get("finished_at"),
                  "report_version": REPORT_VERSION},
        "engines": engines or [{"name": n, "version": "not recorded"}
                               for n in ("semgrep", "gitleaks",
                                         "braimsec-taint-rules")],
        "coverage": {"total": len(findings), "ai_reviewed": ai_reviewed,
                     "deterministic_errors": det_errors,
                     "ai_confirmed_errors": ai_confirmed_errors,
                     "with_fix": with_fix, "sca_findings": sca_n,
                     "taint_traced": traced},
        "not_covered": not_covered,
        "limitations": list(KNOWN_LIMITATIONS),
        "provenance": "deterministic",
    }
    if not honesty["not_covered"] or not honesty["limitations"]:
        raise ReportError("refusing: honesty appendix incomplete")

    # --- 4. compliance rollup ---------------------------------------------
    by_owasp, unmapped = {}, 0
    for f in findings:
        comp = lookup_compliance(f.get("rule_id"), f.get("tool"))
        if comp and comp.get("owasp"):
            code = comp["owasp"]["code"]
            by_owasp[code] = by_owasp.get(code, 0) + 1
        else:
            unmapped += 1
    compliance = {"by_owasp": by_owasp, "unmapped": unmapped,
                  "map_version": compliance_map().get("version"),
                  "provenance": "deterministic"}

    # --- 5. fix plan -------------------------------------------------------
    quick, arch = [], []
    for f in findings:
        item = {"finding_id": f.get("id"), "file": f.get("file"),
                "line": f.get("line"), "severity": f.get("severity"),
                "message": f.get("message"),
                "confidence": f.get("fix_confidence"),
                "caveats": f.get("fix_caveats"),
                "provenance": "ai"}
        if f.get("fix_diff") and (f.get("fix_confidence") or 0) >= 0.7:
            item["effort"] = "quick-win"
            quick.append(item)
        else:
            item["effort"] = "architectural" if f.get("severity") == "error" \
                else "review"
            arch.append(item)
    fix_plan = {"quick_wins": quick, "architectural": arch,
                "provenance": "deterministic"}

    return {
        "meta": {"report_version": REPORT_VERSION, "scan_id": scan_id,
                 "target": target, "generated_at": generated_at,
                 "provenance": "deterministic"},
        "executive": executive,
        "findings": detail,
        "honesty": honesty,
        "compliance": compliance,
        "fix_plan": fix_plan,
    }
