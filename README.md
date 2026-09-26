# BraimSec 🛡️

ماسح ثغرات SAST للمؤسسات — محرك فحص (Semgrep + gitleaks) مع طبقة AI لفهم السياق
(taint analysis) وبوابة جودة آلية تقيس الـF1 مع كل push.

## ما الذي يفعله؟

- `scanner/` — محرك الفحص: يشغّل Semgrep وgitleaks على مجلد كود ويوحّد النتائج بتقرير **SARIF 2.1.0**
- `api/` — واجهة FastAPI: رفع كود (مسار محلي أو ZIP)، تتبّع الفحوصات، استرجاع SARIF
- `ai/` — طبقة مراجعة AI: تحليل تلوث (taint analysis) يميّز الثغرة الحقيقية من الضجيج
  (مثلاً: `eval()` على `PYTHONSTARTUP` ليست ثغرة، على `request.args` ثغرة حرجة)
- `dashboard/` — لوحة تحكم عربية (RTL)
- `benchmark/` — عينة مُسمّاة + harness آلي يقيس F1 ويفشل البناء عند الانحدار

## الأرقام الحالية — بصدق

| المقياس | القيمة | الحالة |
|---|---|---|
| F1 آلي (بدون AI) | 0.846 | ✅ قابل للتكرار |
| F1 مع AI (يدوي) | 0.957 | ⚠️ تجريبي — غير قابل للتكرار (n=6 فقط) |
| المنافس (Bandit) | 0.750 | ✅ آلي |
| بوابة الانحدار: 329 قاعدة × 1334 حالة | F1=0.998 | ✅ آلية — **ليست دليل كشف** |

**توضيح مهم:** الـ0.846 يقيس قدرة الكشف الحقيقية على كود لم تره الأداة أثناء التطوير،
بينما الـ0.998 يقيس الاتساق الداخلي (القواعد ضد اختباراتها الخاصة). رقمان مختلفان
مفاهيمياً — لا تخلط بينهما.

## القيود المعروفة

- العينة صغيرة (n=24) — التوسيع إلى 200+ ملف مخطط له
- رقم الـAI يدوي وعينته n=6 — غير ذات دلالة إحصائية
- لا يوجد hold-out set بعد — الـmilestone القادم
- لا auth / rate-limit / عزل حاويات بعد — غير جاهز للعرض العام

## التشغيل

```bash
# 1. ثبّت الأدوات
pip install semgrep
# gitleaks: https://github.com/gitleaks/gitleaks/releases

# 2. افحص كوداً
python3 scanner/scan_engine.py /path/to/code -o results.sarif

# 3. شغّل الـbenchmark (بوابة الجودة)
python3 benchmark/ci_benchmark.py --tool ours --baseline 0.80

# 4. شغّل الـAPI
cd api && pip install -r requirements.txt && uvicorn main:app --reload
```

متغيرات البيئة: `SEMGREP_BIN`، `GITLEAKS_BIN`، `BANDIT_BIN`، `BRAIMSEC_CORPUS`
(كلها اختيارية — الافتراضي من `PATH`).
