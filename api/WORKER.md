# تشغيل طابور المهام — BraimSec Async Queue (Celery + Redis)

## الفكرة

`POST /api/scans` كان يشغّل الفحص داخل عملية الـ API نفسها
(FastAPI BackgroundTasks): أي crash أو restart أثناء الفحص = فحص ضائع.
الآن: الـ API ينشئ سجل الفحص ويرمي مهمة في طابور Redis،
وعامل (worker) منفصل يلتقطها وينفذها. عقد الـ HTTP لم يتغير:
`{"scan_id": ..., "status": "queued"}` ثم polling على
`GET /api/scans/{scan_id}` — أو webhook موقّع عند الاكتمال.

## التشغيل (إنتاج)

```bash
# 1) Redis
redis-server --daemonize yes   # أو خدمة مدارة (Upstash / ElastiCache...)

# 2) الـ API (من مجلد api/)
BRAIMSEC_BROKER_URL=redis://127.0.0.1:6379/0 \
BRAIMSEC_DB=/data/braimsec.db \
  uvicorn main:app --host 127.0.0.1 --port 8000

# 3) الـ worker (من مجلد api/ — نفس الجهاز أو مجلد مشترك)
BRAIMSEC_BROKER_URL=redis://127.0.0.1:6379/0 \
BRAIMSEC_DB=/data/braimsec.db \
  celery -A tasks worker --loglevel=info --concurrency=2
```

شروط إجبارية:
- الـ worker والـ API **يتشاركان نفس قاعدة البيانات** (`BRAIMSEC_DB`)
  و**نفس نظام الملفات** (أهداف الفحص مجلدات محلية).
- بدون `BRAIMSEC_BROKER_URL` يعمل النظام بالوضع الداخلي القديم
  (inline fallback) — مخصص للتطوير والباكند المؤقت، لا للإنتاج.

## تطوير محلي بدون Redis

للدخاني السريع يمكن استعمال filesystem transport (للتطوير فقط،
ليس للإنتاج):

```bash
export BRAIMSEC_BROKER_URL="filesystem://"
export BRAIMSEC_BROKER_DATA_FOLDER_IN=/tmp/q/queue
export BRAIMSEC_BROKER_DATA_FOLDER_OUT=/tmp/q/queue   # نفس المجلد إجباري
export BRAIMSEC_BROKER_DATA_FOLDER_PROCESSED=/tmp/q/done
```

## السلوكيات المهمة

| الحالة | السلوك |
|---|---|
| تعطل worker أثناء الفحص | المهمة تُعاد تلقائياً (acks_late) بدون تكرار النتائج |
| عطل عابر في المحرك | إعادة محاولة حتى 3 مرات مع backoff، ثم `failed` |
| تعطل الـ broker | الـ API يرد `503` فوراً بدل ابتلاع الفحص |
| انتهاء الفحص | `done`/`failed` + webhook موقّع إذا زوّد العميل `webhook_url` |
| حصة الفحص | تُستهلك لحظة الإنشاء (قبل الـ enqueue) — لا التفاف |
| حصة مراجعة الـ AI | تُستهلك لكل نتيجة داخل الـ worker — إعادة المحاولة لا تضاعف الخصم |

## الـ Webhook

عند إنشاء الفحص مع `webhook_url` (اختياري) يرد الـ API مرة واحدة
بـ `webhook_secret`. عند الوصول لحالة نهائية يرسل الـ worker:

```
POST {webhook_url}
X-BraimSec-Event: scan.completed | scan.failed
X-BraimSec-Signature: sha256=<hmac-sha256(body, webhook_secret)>
Content-Type: application/json
```

الجسم: `{event, scan_id, org_id, status, total_findings, finished_at, error}`.
التسليم best-effort (3 محاولات) ولا يُفشل الفحص عند تعذّره.

## الاختبارات

```bash
cd api && python -m pytest test_async_queue.py -q   # 13 اختباراً
```

تغطي: منطق المهام، idempotency عند إعادة التسليم، التوقيع،
التوجيه celery/inline، عقد v1، و503 عند تعطل الـ broker.
