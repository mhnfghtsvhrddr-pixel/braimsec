"""
BraimSec AI Layer (prototype v0.1.0)
------------------------------------
Second-opinion review of scanner findings using an LLM:

  1. Verdict  - true_positive / false_positive with confidence + Arabic explanation
  2. Fix      - concrete, context-aware code fix suggestion
  3. Logic    - business-logic flaw detection (missing auth, IDOR, ...) [roadmap hook]

The layer is provider-agnostic: any OpenAI-compatible chat API works.
Configure via environment:
    AI_API_URL   e.g. https://api.openai.com/v1
    AI_API_KEY   secret key
    AI_MODEL     e.g. gpt-4o-mini (default)

Without configuration the layer degrades gracefully (verdict = "skipped").
"""
import json
import os
import urllib.request

DEFAULT_MODEL = "gpt-4o-mini"

FINDING_SYSTEM = (
    "You are a senior application security engineer. For each finding, perform TAINT ANALYSIS:\n"
    "1. SINK: what dangerous operation is flagged?\n"
    "2. SOURCE: where does the data reaching the sink come from? Trace it in the code context.\n"
    "3. TAINT: is the source attacker-controlled? Remote user input, request data, uploads, "
    "or environment controlled by the *deployer* facing the network = tainted. "
    "Developer-written constants, the developer's own local environment, or an internal "
    "serialize/deserialize round-trip = NOT tainted.\n"
    "4. VERDICT (base it on taint, never on 'developer intent' — most vulnerabilities live in "
    "intentional code):\n"
    '   - "true_positive": tainted source reaches a dangerous sink without effective sanitization.\n'
    '   - "false_positive": source is not attacker-controlled, OR effective sanitization/validation '
    "is present, OR the rule fired on the wrong framework/language pattern "
    "(e.g. a Django rule on Flask code).\n"
    '   - "needs_review": taint cannot be determined from the given context.\n'
    "Respond with JSON ONLY, no markdown fences, using this schema:\n"
    '{"verdict": "true_positive" | "false_positive" | "needs_review", '
    '"confidence": 0.0-1.0, '
    '"taint_source": "short description of the data source, in English", '
    '"explanation": "one or two sentences, in Arabic, citing source and sink", '
    '"fix": "concrete minimal code fix in the same language, or empty string if false positive"}'
)


class LLMClient:
    """Minimal OpenAI-compatible chat client (stdlib only)."""

    def __init__(self, api_url=None, api_key=None, model=None):
        self.api_url = (api_url or os.environ.get("AI_API_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("AI_API_KEY", "")
        self.model = model or os.environ.get("AI_MODEL", DEFAULT_MODEL)

    @property
    def configured(self):
        return bool(self.api_url and self.api_key)

    def chat(self, system, user, max_tokens=900, temperature=0.2):
        url = f"{self.api_url}/chat/completions"
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.load(resp)
        return data["choices"][0]["message"]["content"]


class MockLLMClient(LLMClient):
    """Deterministic stand-in for tests / demos (no API key needed)."""

    @property
    def configured(self):
        return True

    def chat(self, system, user, max_tokens=900, temperature=0.2):
        return json.dumps({
            "verdict": "true_positive",
            "confidence": 0.9,
            "taint_source": "request data (remote user input)",
            "explanation": "الكود يمرر مدخل المستخدم مباشرة إلى الدالة الحساسة دون تعقيم.",
            "fix": "# استخدم استعلامات مُعامَلة (parameterized queries) بدل تنسيق النصوص",
        }, ensure_ascii=False)


def read_snippet(path, line, radius=10):
    """Return source lines around `line` for LLM context."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = max(0, line - 1 - radius)
        end = min(len(lines), line + radius)
        return "".join(f"{i + 1:4}: {lines[i]}" for i in range(start, end))
    except (OSError, TypeError):
        return ""


def _parse_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`").split("\n", 1)[-1].rsplit("```", 1)[0]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("No JSON object in LLM response")
    return json.loads(text[start:end + 1])


def analyze_finding(client, finding, code_snippet=""):
    """
    finding: dict with tool, rule_id, severity, message, file, line
    Returns dict: ai_verdict, ai_confidence, ai_explanation, ai_fix
    """
    if not client.configured:
        return {"ai_verdict": "skipped", "ai_confidence": 0.0,
                "ai_explanation": "طبقة الـAI غير مُعدّة (لا يوجد مفتاح API).",
                "ai_fix": ""}

    user_msg = (
        f"Finding: [{finding.get('tool')}/{finding.get('rule_id')}] "
        f"({finding.get('severity')})\n"
        f"Message: {finding.get('message')}\n"
        f"Location: {finding.get('file')}:{finding.get('line')}\n"
    )
    if code_snippet:
        user_msg += f"\nCode context:\n```\n{code_snippet}\n```\n"

    try:
        raw = client.chat(FINDING_SYSTEM, user_msg)
        parsed = _parse_json(raw)
        verdict = parsed.get("verdict", "needs_review")
        if verdict not in ("true_positive", "false_positive", "needs_review"):
            verdict = "needs_review"
        return {
            "ai_verdict": verdict,
            "ai_confidence": float(parsed.get("confidence", 0.5)),
            "ai_explanation": str(parsed.get("explanation", ""))[:1000],
            "ai_fix": str(parsed.get("fix", ""))[:2000],
            "ai_taint_source": str(parsed.get("taint_source", ""))[:300],
        }
    except Exception as e:  # noqa: BLE001 - prototype: never break the pipeline
        return {"ai_verdict": "error", "ai_confidence": 0.0,
                "ai_explanation": f"تعذر تحليل النتيجة: {e}", "ai_fix": ""}


def review_findings(client, findings):
    """Run analyze_finding over a list; each item gains ai_* keys."""
    reviewed = []
    for f in findings:
        snippet = read_snippet(f.get("file", ""), f.get("line") or 0)
        result = dict(f)
        result.update(analyze_finding(client, f, snippet))
        reviewed.append(result)
    return reviewed
