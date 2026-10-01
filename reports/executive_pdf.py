"""Deterministic RTL Arabic PDF rendering for the executive report.

Reuses the font/shaping stack from ``pdf.py`` (DejaVu Sans embedded,
arabic_reshaper + bidi for Arabic). Same report dict + same
``generated_at`` -> byte-identical PDF.
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from fpdf import FPDF  # noqa: F401  (kept for the availability check)
except Exception:  # noqa: BLE001
    FPDF = None

from pdf import (  # noqa: E402
    _find_font,
    _h,
    _kv,
    _para,
    _PDF,
    _shape,
    LATIN_BOLD_CANDIDATES,
    LATIN_FONT,
    LATIN_FONT_CANDIDATES,
    ReportError,
)

_SEV_COLORS = {"حرجة": (180, 0, 0), "متوسطة": (200, 140, 0),
               "منخفضة": (60, 120, 200)}


def _table(pdf, headers, rows, widths):
    """Simple RTL table: first column is the rightmost."""
    shaped_h = [_shape(h)[0] for h in headers]
    pdf.set_font(LATIN_FONT, "B" if getattr(pdf, "_bold_ok", False) else "",
                 10)
    pdf.set_fill_color(240, 240, 240)
    x0 = pdf.l_margin
    # column x positions, right-to-left
    xs = []
    x = x0 + sum(widths)
    for w in widths:
        x -= w
        xs.append(x)
    y = pdf.get_y()
    for xi, w, t in zip(xs, widths, shaped_h):
        pdf.set_xy(xi, y)
        pdf.cell(w, 8, t, border=1, align="C", fill=True)
    pdf.set_y(y + 8)
    pdf.set_font(LATIN_FONT, "", 10)
    pdf.set_fill_color(255, 255, 255)
    for row in rows:
        y = pdf.get_y()
        if y > 260:  # keep the table on-page
            pdf.add_page()
            y = pdf.get_y()
        shaped_r = [_shape(str(c))[0] for c in row]
        for xi, w, t in zip(xs, widths, shaped_r):
            pdf.set_xy(xi, y)
            pdf.cell(w, 8, t, border=1, align="C")
        pdf.set_y(y + 8)
    pdf.set_x(pdf.l_margin)  # restore cursor: multi_cell(0, ...) below
    pdf.ln(2)  # depends on current x


def render_executive_pdf(report):
    """Executive report dict (from executive.build_executive_report)
    -> PDF bytes. Deterministic."""
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
    pdf.set_title(f"BraimSec Executive Report - {meta['org']}")
    pdf.set_creator(f"BraimSec executive report engine v{version}")

    latin_font = _find_font(LATIN_FONT_CANDIDATES, "DejaVu Sans")
    if not latin_font:
        raise ReportError("refusing: Unicode font (DejaVu Sans) not found")
    pdf.add_font(LATIN_FONT, "", latin_font)
    bold_font = _find_font(LATIN_BOLD_CANDIDATES)
    pdf._bold_ok = False
    if bold_font:
        pdf.add_font(LATIN_FONT, "B", bold_font)
        pdf._bold_ok = True

    cover = report["cover"]
    posture = report["posture"]

    # ---- cover ---------------------------------------------------------
    pdf.add_page()
    pdf.ln(24)
    _para(pdf, "التقرير التنفيذي لأمن التطبيق", size=26, style="B",
          align="C")
    pdf.ln(4)
    _para(pdf, "BraimSec", size=14, align="C")
    pdf.ln(8)
    _para(pdf, f"المنظمة: {cover['org']}", size=13, align="C")
    if cover.get("project"):
        _para(pdf, f"المشروع: {cover['project']}", size=13, align="C")
    _para(pdf, f"التاريخ: {(cover['generated_at'] or '')[:10]}", size=12,
          align="C")
    pdf.ln(4)
    _para(pdf, f"النطاق: {cover['scope']}", size=11, align="C")
    pdf.ln(10)
    verdict = posture["verdict"]
    color = {"يتحسن": (34, 139, 34), "يتدهور": (180, 0, 0),
             "مستقر": (60, 120, 200)}.get(verdict, (120, 120, 120))
    pdf.set_text_color(*color)
    pdf.set_font(LATIN_FONT, "B" if pdf._bold_ok else "", 20)
    shaped, _ = _shape(f"الوضع العام: {verdict}")
    pdf.cell(0, 14, shaped, align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)
    _para(pdf, posture["summary"], size=11, align="C")
    pdf.ln(6)
    _kv(pdf, [
        ("الثغرات الحرجة", posture["critical"]),
        ("الثغرات المتوسطة", posture["high"]),
        ("إجمالي النتائج (أحدث فحص)", posture["total"]),
        ("إصدار التقرير", f"executive v{version}"),
    ])

    # ---- 1. risk table --------------------------------------------------
    pdf.add_page()
    _h(pdf, "1. جدول المخاطر حسب الخطورة", 1)
    _table(pdf,
           ["الخطورة", "العدد", "ماذا يعني ذلك"],
           [[r["severity"], r["count"], r["meaning"]]
            for r in report["risk_table"]],
           [30, 22, 138])

    # ---- 2. top findings -------------------------------------------------
    _h(pdf, "2. أهم الثغرات والتوصيات", 1)
    _para(pdf, "أهم عشر نتائج بلغة مبسطة، مع توصية عملية لكل واحدة.",
          size=10)
    if not report["top_findings"]:
        _para(pdf, "لا توجد نتائج في أحدث فحص — الوضع ممتاز.", size=11)
    for t in report["top_findings"]:
        r, g, b = _SEV_COLORS.get(t["severity"], (0, 0, 0))
        pdf.set_text_color(r, g, b)
        pdf.set_font(LATIN_FONT, "B" if pdf._bold_ok else "", 11)
        s, _ = _shape(f"{t['rank']}. {t['title']} [{t['severity']}]")
        pdf.multi_cell(0, 6.5, s, align="R")
        pdf.ln(1)  # reset x to margin (multi_cell leaves it at line end)
        pdf.set_text_color(0, 0, 0)
        _para(pdf, f"المشكلة: {t['meaning']}", size=10)
        _para(pdf, f"التوصية: {t['recommendation']}", size=10)
        _para(pdf, f"الموقع: {t['where']}", size=9)
        pdf.ln(2)

    # ---- 3. compliance ----------------------------------------------------
    pdf.add_page()
    _h(pdf, "3. وضع الامتثال", 1)
    comp = report["compliance"]
    _para(pdf, f"تغطية SOC 2: {comp['soc2_coverage_pct']}٪ "
               f"({comp['mapped_soc2']} من {comp['total']})", size=11)
    _para(pdf, f"تغطية ISO 27001:2022: {comp['iso_coverage_pct']}٪ "
               f"({comp['mapped_iso']} من {comp['total']})", size=11)
    pdf.ln(2)
    _para(pdf, comp["note"], size=10)
    _para(pdf, f"إصدار خريطة الامتثال: {comp['map_version']}", size=9)

    # ---- 4. recent scans ---------------------------------------------------
    _h(pdf, "4. ملخص الفحوصات الأخيرة", 1)
    if report["recent_scans"]:
        _table(pdf,
               ["الهدف", "التاريخ", "النتائج"],
               [[s["target"], (s["finished_at"] or "")[:10], s["total"]]
                for s in report["recent_scans"]],
               [90, 50, 50])
    else:
        _para(pdf, "لا توجد فحوصات مكتملة في النطاق.", size=10)

    # ---- 5. methodology note -----------------------------------------------
    _h(pdf, "5. ملاحظة منهجية", 1)
    hon = report["honesty"]
    _para(pdf, hon["scope"], size=10)
    _para(pdf, hon["severity_mapping"], size=10)
    _para(pdf, hon["method"], size=10)

    return bytes(pdf.output())
