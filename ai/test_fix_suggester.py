"""Groq provider tests — no live network, no real key.

Covers, against a local HTTP mock (never api.groq.com):

- GroqClient reads BRAIMSEC_GROQ_API_KEY at *runtime* (env set after import)
- request shape: POST path, Bearer auth, model selection, max_tokens cap,
  temperature passthrough, OpenAI-compatible message envelope
- BRAIMSEC_GROQ_MODEL override
- explicit timeout is honored (slow provider -> raises, no hang)
- make_llm_client(): Groq preferred, generic AI_* fallback, and the
  unconfigured client behind the endpoint's 503 path
- sanitize_text(): strips script blocks / control chars, caps length,
  preserves code angle brackets
- generate_fix(): the whole customer file is never shipped (context cap)
- provider failure -> exception propagates (no fabricated suggestion)

DB isolation: not needed — this module never imports api.main.
Env hygiene: monkeypatch only, never hard-set at import time.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from groq_provider import (
    DEFAULT_GROQ_MODEL,
    GROQ_API_URL,
    MAX_TOKENS_CAP,
    GroqClient,
    make_llm_client,
    sanitize_text,
)
from ai_layer import LLMClient
from fix_suggestions import generate_fix

FIX_JSON = json.dumps({
    "explanation": "شرح عربي للمشكلة",
    "original": '    os.system("ls " + cmd)',
    "patched": '    subprocess.run(["ls", cmd], check=True)',
    "confidence": 0.9,
    "caveats": "تحقق يدوياً",
}, ensure_ascii=False)


def _completion_payload(text=FIX_JSON):
    return {"choices": [{"message": {"content": text}}]}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.captured.append({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "body": body,
        })
        if getattr(self.server, "fail_with", 0):
            self.send_response(self.server.fail_with)
            self.end_headers()
            return
        delay = getattr(self.server, "delay", 0)
        if delay:
            import time
            time.sleep(delay)
        data = json.dumps(_completion_payload()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture()
def mock_groq():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.captured = []
    server.delay = 0
    server.fail_with = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join()


def _local_client(mock_groq, **kw):
    port = mock_groq.server_address[1]
    kw.setdefault("api_url", f"http://127.0.0.1:{port}")
    kw.setdefault("api_key", "gsk_test_123")
    return GroqClient(**kw)


# ---------------------------------------------------------------------------
# runtime key reading
# ---------------------------------------------------------------------------

def test_groq_client_reads_key_at_runtime(monkeypatch):
    """Key picked up from the environment after import (deploy-time secret)."""
    monkeypatch.delenv("BRAIMSEC_GROQ_API_KEY", raising=False)
    assert GroqClient().configured is False
    monkeypatch.setenv("BRAIMSEC_GROQ_API_KEY", "gsk_runtime_abc")
    client = GroqClient()
    assert client.configured is True
    assert client.api_key == "gsk_runtime_abc"
    assert client.api_url == GROQ_API_URL


def test_groq_client_ignores_generic_ai_key(monkeypatch):
    """A generic AI_API_KEY must NOT be sent to Groq's URL by accident."""
    monkeypatch.delenv("BRAIMSEC_GROQ_API_KEY", raising=False)
    monkeypatch.setenv("AI_API_KEY", "sk-generic")
    monkeypatch.setenv("AI_API_URL", "https://example.com/v1")
    client = GroqClient()
    assert client.configured is False
    assert client.api_key == ""


# ---------------------------------------------------------------------------
# request shape against the mock
# ---------------------------------------------------------------------------

def test_request_shape(mock_groq):
    client = _local_client(mock_groq)
    out = client.chat("system prompt", "user prompt", max_tokens=5000,
                      temperature=0.1)
    assert json.loads(out)["explanation"] == "شرح عربي للمشكلة"
    assert len(mock_groq.captured) == 1
    req = mock_groq.captured[0]
    # api_url is overridden to the mock root in tests, so the path is just
    # the chat-completions suffix (production: /openai/v1/chat/completions).
    assert req["path"] == "/chat/completions"
    assert req["auth"] == "Bearer gsk_test_123"
    body = json.loads(req["body"])
    assert body["model"] == DEFAULT_GROQ_MODEL
    assert body["max_tokens"] == MAX_TOKENS_CAP  # 5000 capped to 2000
    assert body["temperature"] == 0.1
    assert body["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "user prompt"},
    ]


def test_model_override_via_env(mock_groq, monkeypatch):
    monkeypatch.setenv("BRAIMSEC_GROQ_MODEL", "llama-3.1-8b-instant")
    client = _local_client(mock_groq)
    client.chat("s", "u")
    body = json.loads(mock_groq.captured[0]["body"])
    assert body["model"] == "llama-3.1-8b-instant"


def test_timeout_is_honored(mock_groq):
    """A hung provider raises instead of hanging the request worker."""
    mock_groq.delay = 2
    client = _local_client(mock_groq, timeout=0.5)
    with pytest.raises(Exception):
        client.chat("s", "u")


# ---------------------------------------------------------------------------
# factory
# ---------------------------------------------------------------------------

def test_factory_prefers_groq(monkeypatch):
    monkeypatch.setenv("BRAIMSEC_GROQ_API_KEY", "gsk_x")
    client = make_llm_client()
    assert isinstance(client, GroqClient)
    assert client.configured is True


def test_factory_falls_back_to_generic(monkeypatch):
    monkeypatch.delenv("BRAIMSEC_GROQ_API_KEY", raising=False)
    monkeypatch.setenv("AI_API_URL", "https://example.com/v1")
    monkeypatch.setenv("AI_API_KEY", "sk-generic")
    client = make_llm_client()
    assert type(client) is LLMClient
    assert client.configured is True


def test_factory_unconfigured_without_any_key(monkeypatch):
    """The client behind the endpoint's 503 path."""
    monkeypatch.delenv("BRAIMSEC_GROQ_API_KEY", raising=False)
    monkeypatch.delenv("AI_API_URL", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    client = make_llm_client()
    assert client.configured is False


# ---------------------------------------------------------------------------
# sanitize_text
# ---------------------------------------------------------------------------

def test_sanitize_strips_dangerous_blocks():
    dirty = ('<p>شرح</p><script>alert(1)</script>'
             '<iframe src="x"></iframe>نص')
    clean = sanitize_text(dirty)
    assert "<script>" not in clean and "<iframe" not in clean
    assert "شرح" in clean and "نص" in clean


def test_sanitize_strips_control_chars_but_keeps_code():
    dirty = "سطر\x00أول\x1f\nif x < y and z > w:\n\tpass"
    clean = sanitize_text(dirty)
    assert "\x00" not in clean and "\x1f" not in clean
    assert "if x < y and z > w:" in clean  # angle brackets preserved
    assert "\n" in clean and "\t" in clean


def test_sanitize_caps_length():
    long_text = "أ" * 5000
    clean = sanitize_text(long_text, max_len=100)
    assert len(clean) <= 110
    assert clean.endswith("[مقتطع]")


def test_sanitize_empty():
    assert sanitize_text("") == ""
    assert sanitize_text(None) == ""


# ---------------------------------------------------------------------------
# minimal code exfiltration
# ---------------------------------------------------------------------------

def test_generate_fix_never_sends_whole_file(mock_groq):
    """The request body carries a capped excerpt, not the customer file."""
    unrelated = "\n".join(f"def unrelated_{i}():\n    return {i}\n"
                          for i in range(400))
    finding = {"tool": "semgrep", "rule_id": "r", "severity": "error",
               "message": "m", "file": "app.py", "line": 5, "col": 1}
    func_src = 'def run(cmd):\n    os.system("ls " + cmd)\n' + unrelated
    client = _local_client(mock_groq)
    gen = generate_fix(client, finding, func_src, "import os")
    assert gen["fix_confidence"] == 0.9
    body = mock_groq.captured[0]["body"]
    assert b"unrelated_399" not in body  # tail of the file never sent
    assert b"context truncated" in body  # truncation is explicit
    assert len(body) < 20000


# ---------------------------------------------------------------------------
# fail-closed
# ---------------------------------------------------------------------------

def test_provider_failure_raises_no_fabrication(mock_groq):
    """HTTP 500 -> exception propagates; generate_fix never invents output."""
    mock_groq.fail_with = 500
    client = _local_client(mock_groq)
    with pytest.raises(Exception):
        client.chat("s", "u")
    with pytest.raises(Exception):
        generate_fix(client, {"tool": "t"}, "code", "")
