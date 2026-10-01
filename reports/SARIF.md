# تصدير SARIF 2.1.0 وتكامل GitHub code scanning

يصدّر BraimSec نتائج أي فحص مكتمل بصيغة **SARIF v2.1.0** — الصيغة المعيارية
التي يفهمها GitHub code scanning ومعظم أدوات الأمان.

## التحميل

- **من اللوحة**: افتح تفاصيل الفحص ← زر «🧾 تحميل SARIF».
- **من الـAPI**:

```bash
curl -s -H "X-API-Key: $BRAIMSEC_API_KEY" \
  "https://api.braimsec.world/api/scans/<scan_id>/sarif" \
  -o braimsec.sarif
```

- الرد: `application/sarif+json` مع `Content-Disposition` للتحميل.
- نفس الفحص = نفس الملف دائماً (حتمي — بلا طوابع زمنية داخل الملف).
- `level` يُطابق خطورة المحرك: `error` / `warning` / `note`.
- كل نتيجة تحمل `fingerprints` مستقرة (`tool|rule_id|file|message` — بلا سطر/عمود)
  فيبقى أثرها ثابتاً حتى لو تحرك الكود.
- القواعد المعروفة تحمل `helpUri` لصفحة CWE على موقع MITRE.

## التكامل مع GitHub code scanning

ارفع ملف SARIF في CI لترى نتائج BraimSec في تبويب **Security** في مستودعك،
جنباً إلى جنب مع CodeQL.

### مثال workflow جاهز (`.github/workflows/braimsec.yml`)

```yaml
name: BraimSec scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  braimsec:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # مطلوب لرفع SARIF
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Zip the project
        run: |
          zip -r project.zip . \
            -x '.git/*' -x 'node_modules/*' -x '*.git*'

      - name: Submit scan to BraimSec
        id: scan
        run: |
          RESP=$(curl -s -X POST "$BRAIMSEC_URL/api/scans" \
            -H "X-API-Key: ${{ secrets.BRAIMSEC_API_KEY }}" \
            -F "file=@project.zip")
          echo "$RESP"
          echo "scan_id=$(echo "$RESP" | python3 -c \
            'import json,sys; print(json.load(sys.stdin)["scan_id"])')" \
            >> "$GITHUB_OUTPUT"

      - name: Wait for scan to finish
        run: |
          for i in $(seq 1 60); do
            STATUS=$(curl -s -H "X-API-Key: ${{ secrets.BRAIMSEC_API_KEY }}" \
              "$BRAIMSEC_URL/api/scans/${{ steps.scan.outputs.scan_id }}" \
              | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
            echo "status: $STATUS"
            [ "$STATUS" = "done" ] && break
            [ "$STATUS" = "failed" ] && exit 1
            sleep 20
          done

      - name: Download SARIF
        run: |
          curl -s -H "X-API-Key: ${{ secrets.BRAIMSEC_API_KEY }}" \
            "$BRAIMSEC_URL/api/scans/${{ steps.scan.outputs.scan_id }}/sarif" \
            -o braimsec.sarif

      - name: Upload to GitHub code scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: braimsec.sarif
          category: braimsec
```

### الإعداد

1. في GitHub: `Settings → Secrets → Actions` أضف:
   - `BRAIMSEC_API_KEY` — مفتاح API من لوحة BraimSec.
2. عدّل `BRAIMSEC_URL` (متغير بيئة في الـworkflow) إلى عنوان سيرفرك،
   مثلاً `https://api.braimsec.world`.
3. الـ`category: braimsec` يميّز نتائج BraimSec عن أدوات أخرى في تبويب Security.

## ملاحظات

- GitHub يقبل SARIF حتى 10MB لكل ملف — صادرات BraimSec أصغر من ذلك بكثير عادةً.
- النتائج المُعلَّمة «false positive» في BraimSec (triage) لا تُستثنى من ملف
  SARIF — الملف يعكس الفحص الخام. رشّحها من تبويب Security في GitHub إن أردت.
- البنية مُتحقق منها برمجياً (`validate_sarif` في `reports/sarif.py`) قبل كل رد.
