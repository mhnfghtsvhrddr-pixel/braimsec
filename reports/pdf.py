"""Deterministic PDF rendering for BraimSec reports (Proposal Part 5).

- Same report dict + same ``generated_at`` -> byte-identical PDF.
- One Unicode font (DejaVu Sans, embedded) for Latin AND Arabic.
  Arabic AI text is shaped (arabic_reshaper + bidi) into visual order;
  if Arabic is present but shaping is unavailable the render FAILS
  loudly instead of printing disconnected letters.
- Every AI-derived string is tagged ``[AI]`` with its confidence;
  deterministic sections carry no such tag.
"""

import datetime
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from fpdf import FPDF
except Exception:  # noqa: BLE001
    FPDF = None

try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    _AR_OK = True
except Exception:  # noqa: BLE001
    _AR_OK = False

from builder import ReportError  # noqa: E402

AR_FONT = None  # retired: DejaVu Sans covers Arabic too (v1 simplification)
LATIN_FONT = "DejaVu"
LATIN_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]
LATIN_BOLD_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]


def _find_font(candidates, fc_query=None):
    for p in candidates:
        if os.path.isfile(p):
            return p
    if fc_query:
        try:
            out = subprocess.run(["fc-match", "-f", "%{file}", fc_query],
                                 capture_output=True, text=True,
                                 timeout=10).stdout.strip()
            if out and os.path.isfile(out):
                return out
        except Exception:  # noqa: BLE001
            pass
    return None


def _has_arabic(text):
    return any("\u0600" <= c <= "\u06FF" or "\u0750" <= c <= "\u077F"
               or "\u08A0" <= c <= "\u08FF" or "\uFB50" <= c <= "\uFDFF"
               or "\uFE70" <= c <= "\uFEFF" for c in (text or ""))


def _shape(text):
    """Visual-order string for PDF. Raises ReportError if Arabic is
    present but the shaping stack is unavailable."""
    text = text or ""
    if not _has_arabic(text):
        return text, False
    if not _AR_OK:
        raise ReportError("refusing: Arabic text present but "
                          "arabic_reshaper/python-bidi not installed")
    return get_display(arabic_reshaper.reshape(text)), True


class _PDF(FPDF):
    def __init__(self, version):
        super().__init__()
        self._version = version
        self.set_auto_page_break(True, margin=20)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, "BraimSec Security Report", align="L")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"BraimSec  |  report v{self._version}  |  "
                         f"page {self.page_no()}/{{nb}}", align="C")


def _para(pdf, text, size=10, style="", align="L", latin_font=LATIN_FONT):
    shaped, is_ar = _shape(text)
    # Bold only if the bold variant was registered; never fake it.
    eff_style = ("B" if style == "B" and getattr(pdf, "_bold_ok", False)
                 else "")
    pdf.set_font(latin_font, eff_style, size)
    pdf.multi_cell(0, size * 0.55, shaped,
                   align="R" if is_ar else align)
    pdf.ln(1)


def _h(pdf, text, level=1):
    sizes = {1: 16, 2: 13, 3: 11}
    pdf.ln(4)
    _para(pdf, text, size=sizes[level], style="B")
    pdf.ln(1)


def _kv(pdf, rows):
    pdf.set_font("Helvetica", "", 10)
    for k, v in rows:
        _para(pdf, f"{k}: {v}", size=10)


def _ai_tag(conf):
    return f"  [AI{(' %.2f' % conf) if conf else ''}]"


def render_pdf(report):
    """report dict (from builder) -> PDF bytes. Deterministic."""
    if FPDF is None:
        raise ReportError("fpdf2 not installed")
    meta = report["meta"]
    version = meta["report_version"]
    pdf = _PDF(version)
    pdf.alias_nb_pages("{nb}")
    try:
        gen = datetime.datetime.fromisoformat(meta["generated_at"])
    except Exception:  # noqa: BLE001
        gen = datetime.datetime.now(datetime.timezone.utc)
    if gen.tzinfo is None:
        gen = gen.replace(tzinfo=datetime.timezone.utc)
    pdf.creation_date = gen
    pdf.set_title(f"BraimSec Security Report - {meta['target']}")
    pdf.set_creator(f"BraimSec report engine v{version}")

    latin_font = _find_font(LATIN_FONT_CANDIDATES, "DejaVu Sans")
    if not latin_font:
        raise ReportError("refusing: Unicode font (DejaVu Sans) not found")
    pdf.add_font(LATIN_FONT, "", latin_font)
    bold_font = _find_font(LATIN_BOLD_CANDIDATES)
    pdf._bold_ok = False
    if bold_font:
        pdf.add_font(LATIN_FONT, "B", bold_font)
        pdf._bold_ok = True

    exe = report["executive"]
    grade_colors = {"A": (34, 139, 34), "B": (60, 120, 200),
                    "C": (200, 140, 0), "D": (200, 80, 0), "F": (180, 0, 0)}

    # ---- cover ---------------------------------------------------------
    pdf.add_page()
    pdf.ln(30)
    _para(pdf, "BraimSec Security Report", size=26, style="B", align="C")
    pdf.ln(6)
    _para(pdf, meta["target"], size=14, align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 72)
    r, g, b = grade_colors.get(exe["grade"], (0, 0, 0))
    pdf.set_text_color(r, g, b)
    pdf.cell(0, 30, f"Grade {exe['grade']}", align="C", new_x="LMARGIN",
             new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)
    _para(pdf, exe["grade_basis"], size=10, align="C")
    pdf.ln(6)
    c = exe["counts"]
    _para(pdf, f"{c['error']} errors  |  {c['warning']} warnings  |  "
               f"{c['note']} notes  |  {exe['deterministic_errors']} "
               "deterministic errors"
               f"  |  {exe['ai_confirmed_errors']} AI-confirmed",
          size=11, align="C")
    pdf.ln(10)
    _kv(pdf, [("Scan", meta["scan_id"]),
              ("Generated", meta["generated_at"]),
              ("Report version", version),
              ("Generator", "BraimSec report engine (deterministic)")])

    # ---- 1. executive ---------------------------------------------------
    pdf.add_page()
    _h(pdf, "1. Executive summary", 1)
    d = exe["delta"]
    if "baseline" in d:
        _para(pdf, d["baseline"] + ".", size=10)
    else:
        _para(pdf, f"Delta vs {d['prev_scan_id']} "
                   f"({d['prev_finished_at']}): errors {d['error']:+d}, "
                   f"warnings {d['warning']:+d}, notes {d['note']:+d}; "
                   f"grade {d['grade']['prev']} -> {d['grade']['now']}.",
              size=10)
    _h(pdf, "Top risks", 2)
    if not exe["top_risks"]:
        _para(pdf, "No error-severity findings.", size=10)
    for i, t in enumerate(exe["top_risks"], 1):
        tag = _ai_tag(t["confidence"]) if t["provenance"] == "ai" \
            else "  [deterministic]"
        _para(pdf, f"{i}. [{t['finding_id']}] {t['file']}:{t['line']} — "
                   f"{t['message']}{tag}", size=10)

    # ---- 2. findings ----------------------------------------------------
    pdf.add_page()
    _h(pdf, "2. Findings detail", 1)
    if not report["findings"]:
        _para(pdf, "No findings recorded for this scan.", size=10)
    for f in report["findings"]:
        _h(pdf, f"F{f['finding_id']} [{f['severity'].upper()}] "
                f"{f['file']}:{f['line']}", 3)
        _para(pdf, f["message"] or "", size=10)
        _para(pdf, f"Rule: {f['tool']}/{f['rule_id']}", size=9)
        ai = f["ai"]
        if ai["provenance"] == "ai":
            _para(pdf, f"AI verdict: {ai['verdict']}"
                       f"{_ai_tag(ai['confidence'])}", size=10)
            if ai["explanation"]:
                _para(pdf, ai["explanation"], size=10)
        else:
            _para(pdf, "AI verdict: not reviewed.",
                  size=10)
        comp = f["compliance"]
        if comp.get("unmapped"):
            _para(pdf, "Compliance: unmapped "
                       f"(map v{comp.get('map_version')})", size=9)
        else:
            parts = []
            if comp.get("owasp"):
                parts.append(f"OWASP {comp['owasp']['code']}")
            if comp.get("cwe"):
                parts.append(comp["cwe"]["id"])
            _para(pdf, "Compliance: " + ", ".join(parts) +
                       f"  (map v{comp.get('map_version')})", size=9)
        if f.get("taint_trace"):
            _para(pdf, "Exploitation path (deterministic):", size=10,
                  style="B")
            for s in f["taint_trace"]["taint_path"]:
                _para(pdf, f"  [{s['type']}] "
                           f"{os.path.basename(s['file'])}:{s['line']} — "
                           f"{s['snippet'][:100]}", size=9)
        if f.get("fix"):
            fx = f["fix"]
            _para(pdf, f"Suggested fix{_ai_tag(fx['confidence'])}:",
                  size=10, style="B")
            if fx.get("explanation"):
                _para(pdf, fx["explanation"], size=10)
            pdf.set_font("Courier", "", 8)
            pdf.multi_cell(0, 4.5, (fx["diff"] or "")[:3000])
            pdf.ln(1)
            if fx.get("caveats"):
                _para(pdf, f"Caveats: {fx['caveats']}", size=9)

    # ---- 3. honesty appendix (mandatory) ---------------------------------
    pdf.add_page()
    _h(pdf, "3. Methodology & honesty appendix", 1)
    _para(pdf, "What this report is — and is not. This appendix is "
               "mandatory: a report without it is rejected by the "
               "generator.", size=10, style="I")
    hon = report["honesty"]
    _h(pdf, "Scope", 2)
    _kv(pdf, [(k, v) for k, v in hon["scope"].items()])
    _h(pdf, "Engines", 2)
    for e in hon["engines"]:
        _para(pdf, f"- {e['name']}: {e['version']}", size=10)
    _h(pdf, "Coverage", 2)
    _kv(pdf, [(k, str(v)) for k, v in hon["coverage"].items()])
    _h(pdf, "What was NOT covered", 2)
    for n in hon["not_covered"]:
        _para(pdf, f"- {n}", size=10)
    _h(pdf, "Known limitations", 2)
    for lim in hon["limitations"]:
        _para(pdf, f"- {lim}", size=10)

    # ---- 4. compliance ---------------------------------------------------
    pdf.add_page()
    _h(pdf, "4. Compliance mapping", 1)
    comp = report["compliance"]
    _para(pdf, f"Mapping version: {comp['map_version']} (conservative — "
               "unmapped findings are reported as unmapped, never "
               "force-fitted).", size=10)
    if comp["by_owasp"]:
        for code, n in sorted(comp["by_owasp"].items()):
            _para(pdf, f"- OWASP {code}: {n} finding(s)", size=10)
    _para(pdf, f"Unmapped findings: {comp['unmapped']}", size=10)

    # ---- 5. fix plan -----------------------------------------------------
    _h(pdf, "5. Fix plan", 1)
    fp = report["fix_plan"]
    _h(pdf, "Quick wins", 2)
    if not fp["quick_wins"]:
        _para(pdf, "None — no high-confidence fix suggestion available.",
              size=10)
    for q in fp["quick_wins"]:
        _para(pdf, f"[ ] F{q['finding_id']} {q['file']}:{q['line']} — "
                   f"{q['message']}{_ai_tag(q['confidence'])}", size=10)
    _h(pdf, "Architectural / needs review", 2)
    for q in fp["architectural"]:
        _para(pdf, f"[ ] F{q['finding_id']} [{q['effort']}] "
                   f"{q['file']}:{q['line']} — {q['message']}", size=10)

    return bytes(pdf.output())
