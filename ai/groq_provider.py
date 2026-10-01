"""Groq LLM provider for BraimSec AI features.

Provider abstraction over :mod:`ai_layer`:

- :class:`GroqClient` — OpenAI-compatible chat completions against
  ``https://api.groq.com/openai/v1``. The API key is read from
  ``BRAIMSEC_GROQ_API_KEY`` at *instantiation time* (never at import),
  so a deploy-time secret is honored without import-order tricks.
- :func:`make_llm_client` — factory: Groq when ``BRAIMSEC_GROQ_API_KEY``
  is set, otherwise the generic ``AI_API_URL`` / ``AI_API_KEY`` pair
  (any OpenAI-compatible endpoint). With nothing configured the client
  reports ``configured == False`` and callers answer 503 — fail-closed,
  never a fabricated suggestion.
- :func:`sanitize_text` — output hygiene for LLM-produced text before it
  is stored or rendered: strips script/style/iframe/object/embed/form
  blocks and control characters, and caps length. Code angle brackets
  (generics, comparisons) are preserved — the dashboard HTML-escapes on
  render; this is the defense-in-depth backend half.

Security posture:

- Only the minimal code excerpt (enclosing function + imports, capped at
  ``MAX_CONTEXT_CHARS`` by the caller in ``fix_suggestions.generate_fix``)
  is ever sent to the provider — never the whole customer file.
- Timeouts are explicit and ``max_tokens`` is capped, so a hung or
  runaway provider call cannot hang a request worker.
"""

import json  # noqa: F401  (re-exported for convenience in tests)
import os
import re
import urllib.request

from ai_layer import LLMClient

GROQ_API_URL = "https://api.groq.com/openai/v1"
DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
MAX_TOKENS_CAP = 2000
DEFAULT_TIMEOUT_S = 60
MAX_CONTEXT_CHARS = 6000


class GroqClient(LLMClient):
    """LLMClient bound to Groq's OpenAI-compatible chat endpoint."""

    def __init__(self, api_key=None, model=None, timeout=DEFAULT_TIMEOUT_S,
                 api_url=None):
        # NOTE: deliberately bypasses LLMClient.__init__ — its
        # ``api_key or os.environ.get("AI_API_KEY")`` fallback would bind a
        # *generic* key to Groq's URL. A Groq client uses only
        # BRAIMSEC_GROQ_API_KEY (or an explicitly passed key).
        self.api_url = (api_url or GROQ_API_URL).rstrip("/")
        self.api_key = (api_key if api_key is not None
                        else os.environ.get("BRAIMSEC_GROQ_API_KEY", ""))
        self.model = (model or os.environ.get("BRAIMSEC_GROQ_MODEL", "")
                      or DEFAULT_GROQ_MODEL)
        self.timeout = timeout

    @property
    def configured(self):
        return bool(self.api_key)

    def chat(self, system, user, max_tokens=900, temperature=0.2,
             timeout=None):
        try:
            max_tokens = max(1, min(int(max_tokens), MAX_TOKENS_CAP))
        except (TypeError, ValueError):
            max_tokens = 900
        return super().chat(system, user, max_tokens=max_tokens,
                            temperature=temperature,
                            timeout=timeout or self.timeout)


def make_llm_client():
    """Build the configured LLM client for BraimSec AI features.

    Groq first (``BRAIMSEC_GROQ_API_KEY``), then the generic
    OpenAI-compatible pair (``AI_API_URL`` + ``AI_API_KEY``). Returns an
    *unconfigured* client when nothing is set — callers must check
    ``.configured`` and answer 503.
    """
    if os.environ.get("BRAIMSEC_GROQ_API_KEY", ""):
        return GroqClient()
    return LLMClient()


_DANGEROUS_BLOCK_RE = re.compile(
    r"<\s*(script|style|iframe|object|embed|form)\b[^>]*>.*?"
    r"<\s*/\s*\1\s*>",
    re.IGNORECASE | re.DOTALL,
)


def sanitize_text(text, max_len=4000):
    """Hygiene for LLM-produced text before storage/rendering.

    - removes script/style/iframe/object/embed/form blocks (XSS payloads)
    - removes control characters except ``\\n`` and ``\\t``
    - truncates to ``max_len`` with an explicit Arabic marker
    """
    if not text:
        return ""
    text = _DANGEROUS_BLOCK_RE.sub("", str(text))
    text = "".join(ch for ch in text if ch in ("\n", "\t") or ord(ch) >= 32)
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len].rstrip() + "\n…[مقتطع]"
    return text
