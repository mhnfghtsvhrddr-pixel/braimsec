"""BraimSec executive report builder — manager-facing, deterministic.

Produces a plain-language (Arabic) report dict for non-technical readers
(managers / clients). Pure function of stored scan data: no rescan, no
LLM calls, no quota consumed. All prose is fixed Arabic templates —
nothing is generated or paraphrased at runtime.

Severity mapping (documented in the report itself):
  engine "error"   -> "حرجة"   (critical)
  engine "warning"  -> "متوسطة" (medium)
  engine "note"     -> "منخفضة" (low)

Recommendations are deterministic templates keyed on rule/tool/message
substrings, conservative by design: when no category matches, a generic
review recommendation is used instead of an invented one.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from builder import ReportError, SEVERITY_RANK  # noqa: E402

EXECUTIVE_REPORT_VERSION = "1.0.0"

SEVERITY_AR = {"error": "حرجة", "warning": "متوسطة", "note": "منخفضة"}
SEVERITY_MEANING = {
    "error": "ثغرات قد تسمح للمهاجم باختراق النظام أو سرقة البيانات — "
             "تتطلب معالجة فورية.",
    "warning": "نقاط ضعف متوسطة الخطورة قد تُستغل في ظروف معينة — "
               "تتطلب خطة معالجة قريبة.",
    "note": "ملاحظات تحسينية منخفضة الخطورة — تُعالج ضمن الصيانة الدورية.",
}

# (substrings, plain title, what it means, practical recommendation)
# Checked against (rule_id + " " + tool + " " + message).lower().
_PLAIN_CATEGORIES = [
    (("sqli", "sql-injection", "sql_injection"),
     "ثغرة حقن في قاعدة البيانات",
     "قد يتمكن المهاجم من التلاعب بقاعدة البيانات والوصول إلى بيانات العملاء.",
     "استخدم الاستعلامات المُعامَلة (parameterized queries) ولا تدمج مدخلات "
     "المستخدم في جمل SQL مباشرة."),
    (("xss", "cross-site-scripting", "cross_site"),
     "ثغرة برمجة عبر المواقع",
     "قد يتمكن المهاجم من تنفيذ سكربتات خبيثة في متصفحات المستخدمين.",
     "قم بترميز كل المخرجات المعروضة للمستخدم وتحقّق من المدخلات قبل عرضها."),
    (("command-injection", "command_injection", "shell-injection",
      "os-command", "exec-danger", "subprocess"),
     "ثغرة حقن أوامر النظام",
     "قد يتمكن المهاجم من تنفيذ أوامر على الخادم نفسه.",
     "تجنّب تنفيذ أوامر النظام بمدخلات المستخدم، واستخدم مكتبات آمنة "
     "بدل استدعاء الـshell."),
    (("ssrf", "server-side-request"),
     "ثغرة تزوير الطلب من الخادم",
     "قد يستغل المهاجم الخادم للوصول إلى خدمات داخلية حساسة.",
     "قيّد الروابط المسموح بها بقائمة بيضاء وتحقّق من عناوين URL "
     "قبل أن يطلبها الخادم."),
    (("dockerfile", "docker"),
     "مشكلة في إعداد حاوية Docker",
     "إعداد الحاوية قد يمنح صلاحيات زائدة أو يعرّض أسراراً للخطر.",
     "راجع ملف Dockerfile: لا تُشغّل كجذر (root)، ولا تضع أسراراً في ENV، "
     "وثبّت وسوم الصور الأساسية."),
    (("secret", "api-key", "apikey", "credential", "password-in",
      "secrets-in-env", "hardcoded"),
     "بيانات سرية مكشوفة في الكود",
     "مفاتيح أو كلمات سر موجودة في الكود قد تُسرق ممن يصل إلى المستودع.",
     "احذف السر من الكود فوراً، أبطل المفتاح المكشوف وأصدر بديلاً، وانقل "
     "الأسرار إلى متغيرات بيئة أو مخزن أسرار آمن."),
    (("path-traversal", "path_traversal", "directory-traversal",
      "path_traversal_open"),
     "ثغرة تجاوز مسارات الملفات",
     "قد يتمكن المهاجم من الوصول إلى ملفات خارج المجلد المسموح به.",
     "تحقّق من أسماء الملفات القادمة من المستخدم وقيّد الوصول داخل مجلد "
     "محدد."),
    (("deserial", "pickle", "yaml.load", "unsafe-load",
      "unrestricted-file-upload", "file-upload"),
     "معالجة غير آمنة لملفات أو بيانات",
     "بيانات خبيثة قد تنفّذ كوداً أو ترفع ملفات ضارة عند معالجتها.",
     "استخدم صيغاً آمنة (مثل JSON)، وتحقّق من نوع وحجم الملفات المرفوعة."),
    (("csrf", "cross-site-request"),
     "ثغرة تزوير الطلب عبر المواقع",
     "قد يُخدع المستخدم لتنفيذ إجراء في حسابه دون علمه.",
     "أضف رموز CSRF للنماذج وتحقق منها في كل طلب مُعدِّل للبيانات."),
    (("open-redirect", "open_redirect"),
     "إعادة توجيه مفتوحة",
     "قد يُستغل الرابط لخداع المستخدمين وتوجيههم لمواقع تصيّد.",
     "قيّد روابط إعادة التوجيه على نطاقات موثوقة فقط."),
    (("terraform", "sg-inline", "sg-open", "s3", "rds", "ebs",
      "security-group"),
     "مشكلة في إعداد البنية السحابية",
     "إعداد سحابي غير آمن قد يكشف الخدمات أو البيانات للإنترنت.",
     "راجع إعداد Terraform: فعّل التشفير للبيانات المخزنة وقيّد الوصول "
     "الشبكي على المنافذ الحساسة."),
    (("gha", "github-action", "ci-cd", "workflow"),
     "مشكلة في إعداد خط أنابيب البناء",
     "إعداد CI/CD غير آمن قد يسمح بحقن كود في عملية البناء.",
     "ثبّت إصدارات الإجراءات (pin by SHA) وراجع صلاحيات سير العمل."),
    (("vuln", "cve-", "osv", "dependency", "outdated"),
     "مكتبة خارجية فيها ثغرة معروفة",
     "المكتبة المستخدمة تحتوي ثغرة معلنة قد تُستغل.",
     "حدّث المكتبة إلى النسخة المُصلحة حسب توصية قاعدة بيانات الثغرات."),
]

_FALLBACK = (
    "نتيجة فحص تقنية",
    "رصد الفحص الآلي نمطاً يستحق المراجعة من الفريق التقني.",
    "اطلب من فريق التطوير مراجعة هذه النتيجة وتطبيق التوصية الخاصة بها.",
)


def _plain(rule_id, tool, message):
    """-> (title, meaning, recommendation): deterministic, conservative."""
    hay = f"{rule_id or ''} {tool or ''} {message or ''}".lower()
    for subs, title, meaning, rec in _PLAIN_CATEGORIES:
        if any(s in hay for s in subs):
            return title, meaning, rec
    return _FALLBACK


def _sev_ar(severity):
    return SEVERITY_AR.get(severity or "warning", "متوسطة")


def build_executive_report(org_name, project_name, scans, latest_findings,
                           prev_counts=None, compliance=None,
                           generated_at=None):
    """Build the manager-facing report dict.

    scans: chronological list of completed-scan dicts
           (id, target_name, created_at/finished_at, total_findings).
    latest_findings: findings of the most recent scan
           (tool, rule_id, severity, message, file, line).
    prev_counts: {severity: count} of the previous scan, or None when the
           latest scan is the first one in scope.
    compliance: {"soc2_mapped": n, "iso_mapped": n, "total": n,
                 "map_version": str} or None.
    Raises ReportError when there are no completed scans in scope —
    a report without scope would be dishonest.
    """
    scans = list(scans or [])
    if not scans:
        raise ReportError("refusing: no completed scans in scope — "
                          "an executive report without scope is dishonest")

    latest_findings = list(latest_findings or [])
    counts = {"error": 0, "warning": 0, "note": 0}
    for f in latest_findings:
        sev = f.get("severity") or "warning"
        counts[sev] = counts.get(sev, 0) + 1
    critical = counts.get("error", 0)
    high = counts.get("warning", 0)
    total = len(latest_findings)

    # --- posture / trend ------------------------------------------------
    if prev_counts is None:
        trend = "insufficient"
        verdict = "لا توجد بيانات كافية للمقارنة"
        trend_sentence = ("هذا هو أول فحص في النطاق المحدد، لذا لا يمكن "
                          "حساب الاتجاه بعد.")
    else:
        prev_total = sum((prev_counts or {}).get(s, 0)
                         for s in ("error", "warning", "note"))
        delta = total - prev_total
        if delta < 0:
            trend, verdict = "improving", "يتحسن"
            trend_sentence = ("الاتجاه يتحسن: عدد النتائج انخفض بمقدار "
                              f"{-delta} مقارنة بالفحص السابق.")
        elif delta > 0:
            trend, verdict = "worsening", "يتدهور"
            trend_sentence = ("الاتجاه يتدهور: عدد النتائج ارتفع بمقدار "
                              f"{delta} مقارنة بالفحص السابق — يُنصح "
                              "بتكثيف المعالجة.")
        else:
            trend, verdict = "stable", "مستقر"
            trend_sentence = "الوضع مستقر: عدد النتائج لم يتغير عن الفحص السابق."
    if critical == 0 and high == 0:
        posture_text = ("الوضع العام جيد: لم تُكتشف ثغرات حرجة أو متوسطة "
                        "في أحدث فحص. " + trend_sentence)
    else:
        posture_text = (f"أحدث فحص كشف عن {critical} ثغرة حرجة "
                        f"و{high} ثغرة متوسطة الخطورة. " + trend_sentence)

    # --- risk table ------------------------------------------------------
    risk_table = [
        {"severity": _sev_ar(s),
         "count": counts.get(s, 0),
         "meaning": SEVERITY_MEANING[s]}
        for s in ("error", "warning", "note")
    ]

    # --- top 10 in plain language ----------------------------------------
    ordered = sorted(
        latest_findings,
        key=lambda f: (-SEVERITY_RANK.get(f.get("severity") or "warning", 1),
                       f.get("file") or "", f.get("line") or 0))
    top = []
    for i, f in enumerate(ordered[:10], 1):
        title, meaning, rec = _plain(f.get("rule_id"), f.get("tool"),
                                     f.get("message"))
        where = (f.get("file") or "—")
        if f.get("line"):
            where = f"{where}:{f['line']}"
        top.append({
            "rank": i,
            "title": title,
            "meaning": meaning,
            "recommendation": rec,
            "where": where,
            "severity": _sev_ar(f.get("severity")),
            "provenance": "deterministic",
        })

    # --- compliance -------------------------------------------------------
    comp = compliance or {}
    c_total = comp.get("total", total)
    soc2_pct = round(100.0 * comp.get("soc2_mapped", 0) / c_total) \
        if c_total else 0
    iso_pct = round(100.0 * comp.get("iso_mapped", 0) / c_total) \
        if c_total else 0
    compliance_section = {
        "soc2_coverage_pct": soc2_pct,
        "iso_coverage_pct": iso_pct,
        "mapped_soc2": comp.get("soc2_mapped", 0),
        "mapped_iso": comp.get("iso_mapped", 0),
        "total": c_total,
        "map_version": comp.get("map_version", "unknown"),
        "note": ("نسبة التغطية = النتائج المرتبطة بضوابط المعيار ÷ إجمالي "
                 "النتائج. الربط متحفظ عمداً: ما لم يُربط بثقة يُحسب "
                 "غير مُغطّى."),
        "provenance": "deterministic",
    }

    # --- recent scans ------------------------------------------------------
    recent = [{
        "target": s.get("target_name") or s.get("id"),
        "finished_at": s.get("finished_at") or s.get("created_at"),
        "total": s.get("total_findings",
                       s.get("total", 0)),
    } for s in scans[-10:]]

    scope_text = (f"{len(scans)} فحص مكتمل"
                  + (f" ضمن المشروع «{project_name}»"
                     if project_name else " على مستوى المنظمة"))

    return {
        "meta": {
            "report_version": EXECUTIVE_REPORT_VERSION,
            "kind": "executive",
            "org": org_name,
            "project": project_name,
            "generated_at": generated_at,
            "provenance": "deterministic",
        },
        "cover": {
            "org": org_name,
            "project": project_name,
            "generated_at": generated_at,
            "scope": scope_text,
        },
        "posture": {
            "verdict": verdict,
            "trend": trend,
            "critical": critical,
            "high": high,
            "total": total,
            "summary": posture_text,
            "provenance": "deterministic",
        },
        "risk_table": risk_table,
        "top_findings": top,
        "compliance": compliance_section,
        "recent_scans": recent,
        "honesty": {
            "scope": scope_text,
            "severity_mapping": ("درجات الخطورة في هذا التقرير مبسطة: "
                                 "حرجة = error، متوسطة = warning، "
                                 "منخفضة = note."),
            "method": ("تقرير حتمي مولّد من بيانات الفحوصات المخزنة — لا "
                       "يُعيد الفحص ولا يستخدم الذكاء الاصطناعي. النصوص "
                       "قوالب ثابتة وليست آراء مولّدة."),
            "provenance": "deterministic",
        },
    }
