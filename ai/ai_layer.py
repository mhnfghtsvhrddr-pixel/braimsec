"""
BraimSec AI Layer (prototype v0.1.0)
------------------------------------
Second-opinion review of scanner findings using an LLM:

  1. Verdict  - true_positive / false_positive with confidence + Arabic explanation
  2. Fix      - concrete, context-aware code fix suggestion
  3. Logic    - business-logic flaw detection (missing auth, IDOR, ...) [roadmap hook]

Semantic routing: findings are classified into families and each family gets
its own system prompt, because a taint-analysis frame is the wrong lens for
a leaked secret or a config flag:

  secret      leaked credential — the secret IS the vulnerability
  config      config/deployment flag — vulnerability depends on context
  taint       SAST/taint finding — classic source->sink analysis
  dependency  vulnerable library (OSV) — CVE triage + upgrade guidance
  sink        high-risk sink audit — handled by analyze_sink, not here

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

SECRETS_SYSTEM = (
    "You are a senior application security engineer reviewing a possible LEAKED SECRET.\n"
    "A leaked secret is a vulnerability IN ITSELF — there is no source/sink to trace.\n"
    "0. PLACEHOLDER GATE (mandatory — check this BEFORE anything else): if the flagged value "
    "is obviously a placeholder, example, documentation text, or test fixture — e.g. "
    "'your-api-key-here', 'xxx', 'test', 'example', 'changeme', 'TODO', a repeated single "
    "character, or it appears only in comments/docs/tests — the verdict MUST be "
    '"false_positive" with high confidence. Never flag documentation.\n'
    "1. REAL CREDENTIAL: high-entropy opaque string in a plausible credential format, "
    "located in shipped code or config (not docs/tests) = true_positive.\n"
    "2. UNCERTAIN: short or low-entropy token in ambiguous context = needs_review — "
    "say what would settle it.\n"
    "3. VERDICT (never base it on 'developer intent' — most leaks live in intentional code):\n"
    '   - "true_positive": a real credential is exposed in code/config.\n'
    '   - "false_positive": placeholder/example/docs/test, OR the matched text is not '
    "a credential at all.\n"
    '   - "needs_review": cannot determine from the given context.\n'
    "Respond with JSON ONLY, no markdown fences, using this schema:\n"
    '{"verdict": "true_positive" | "false_positive" | "needs_review", '
    '"confidence": 0.0-1.0, '
    '"secret_type": "e.g. api_key, jwt, private_key, password — in English", '
    '"explanation": "one or two sentences, in Arabic", '
    '"fix": "rotate the credential immediately and move it to a secrets manager / '
    "environment variable; never commit secrets — or empty string if false positive. "
    'NEVER echo the secret value itself in the fix."}'
)

CONFIG_SYSTEM = (
    "You are a senior application security engineer reviewing a CONFIGURATION / DEPLOYMENT "
    "finding (e.g. debug mode, CSRF disabled, permissive hosts, insecure transport).\n"
    "A config flag is a POTENTIAL vulnerability — its severity depends on deployment context, "
    "so do NOT use taint analysis here.\n"
    "1. MECHANISM: what does this setting do, concretely, if enabled in production?\n"
    "2. CONTEXT: is there evidence this is production-facing (deployment config, Dockerfile, "
    "prod settings module) vs dev/test-only? "
    "Unknown context is NOT safety — it means needs_review, never false_positive.\n"
    "3. VERDICT:\n"
    '   - "true_positive": the setting is risky AND (production-facing OR context unknown '
    "but the default/exposed posture is unsafe).\n"
    '   - "false_positive": clearly dev/test-only, OR the setting is already at its safe value.\n'
    '   - "needs_review": deployment context cannot be determined from the given context — '
    "say what would settle it.\n"
    "Respond with JSON ONLY, no markdown fences, using this schema:\n"
    '{"verdict": "true_positive" | "false_positive" | "needs_review", '
    '"confidence": 0.0-1.0, '
    '"explanation": "one or two sentences, in Arabic, citing the setting and the context", '
    '"fix": "concrete configuration change that removes the risk, '
    'or empty string if false positive"}'
)

DEPENDENCY_SYSTEM = (
    "You are a senior application security engineer triaging a VULNERABLE DEPENDENCY "
    "reported by an SCA scanner (OSV database).\n"
    "1. IMPACT: from the CVE summary and severity — what does exploitation achieve?\n"
    "2. APPLICABILITY: the installed version is inside the affected range (the scanner "
    "already matched it) — treat a well-formed report as true_positive. Mark false_positive "
    "ONLY if the report is malformed (e.g. version clearly outside the range, withdrawn CVE).\n"
    "3. FIX PATH: is a fixed version published? Name it exactly.\n"
    "Respond with JSON ONLY, no markdown fences, using this schema:\n"
    '{"verdict": "true_positive" | "false_positive" | "needs_review", '
    '"confidence": 0.0-1.0, '
    '"explanation": "one or two sentences, in Arabic, citing CVE id, severity, and fixed version", '
    '"fix": "upgrade <package> to >= <fixed version>, then rebuild and redeploy; '
    'or empty string if false positive"}'
)

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


# --- semantic routing ----------------------------------------------------

# Families: "secret" | "config" | "taint" | "dependency" | "sink".
# Order matters: config keywords are checked before secret keywords so that
# e.g. a csrf rule (which mentions "token") is not misrouted to secrets.

_CONFIG_KEYWORDS = ("csrf", "debug", "allowed-host", "disclosure",
                    "insecure-transport", "missing-tls", "config")
_SECRET_KEYWORDS = ("secret", "api-key", "apikey", "jwt", "password",
                    "passwd", "private-key", "privatekey", "token")

FAMILY_SYSTEMS = {
    "secret": SECRETS_SYSTEM,
    "config": CONFIG_SYSTEM,
    "taint": FINDING_SYSTEM,
    "dependency": DEPENDENCY_SYSTEM,
    # "sink" findings are reviewed by analyze_sink, never routed here;
    # if one ever arrives, taint analysis is the closest fallback.
    "sink": FINDING_SYSTEM,
}


def classify_finding(finding):
    """Classify a finding dict into a semantic family for prompt routing.

    Pure function of (tool, rule_id) — deterministic, no LLM involved.
    """
    tool = (finding.get("tool") or "").lower()
    rule = (finding.get("rule_id") or "").lower()
    if tool == "gitleaks":
        return "secret"
    if tool == "osv":
        return "dependency"
    if tool == "sink-audit":
        return "sink"
    if any(k in rule for k in _CONFIG_KEYWORDS):
        return "config"
    if any(k in rule for k in _SECRET_KEYWORDS):
        return "secret"
    return "taint"


def route_system(finding):
    """Return the system prompt for a finding's semantic family."""
    return FAMILY_SYSTEMS[classify_finding(finding)]


class LLMClient:
    """Minimal OpenAI-compatible chat client (stdlib only)."""

    def __init__(self, api_url=None, api_key=None, model=None):
        self.api_url = (api_url or os.environ.get("AI_API_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("AI_API_KEY", "")
        self.model = model or os.environ.get("AI_MODEL", DEFAULT_MODEL)

    @property
    def configured(self):
        return bool(self.api_url and self.api_key)

    def chat(self, system, user, max_tokens=900, temperature=0.2,
             timeout=None):
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
        with urllib.request.urlopen(req, timeout=timeout or 120) as resp:
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
    (+ ai_family, and ai_taint_source for taint-family findings).

    The system prompt is chosen by semantic routing (classify_finding):
    secrets/config/dependencies each get their own lens instead of the
    taint-analysis frame.
    """
    if not client.configured:
        return {"ai_verdict": "skipped", "ai_confidence": 0.0,
                "ai_explanation": "طبقة الـAI غير مُعدّة (لا يوجد مفتاح API).",
                "ai_fix": ""}

    family = classify_finding(finding)
    system = FAMILY_SYSTEMS[family]
    user_msg = (
        f"Finding: [{finding.get('tool')}/{finding.get('rule_id')}] "
        f"({finding.get('severity')})\n"
        f"Message: {finding.get('message')}\n"
        f"Location: {finding.get('file')}:{finding.get('line')}\n"
    )
    if code_snippet:
        user_msg += f"\nCode context:\n```\n{code_snippet}\n```\n"

    try:
        raw = client.chat(system, user_msg)
        parsed = _parse_json(raw)
        verdict = parsed.get("verdict", "needs_review")
        if verdict not in ("true_positive", "false_positive", "needs_review"):
            verdict = "needs_review"
        return {
            "ai_verdict": verdict,
            "ai_confidence": float(parsed.get("confidence", 0.5)),
            "ai_explanation": str(parsed.get("explanation", ""))[:1000],
            "ai_fix": str(parsed.get("fix", ""))[:2000],
            "ai_family": family,
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
