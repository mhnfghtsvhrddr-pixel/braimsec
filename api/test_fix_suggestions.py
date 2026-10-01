"""AI-Powered Auto-Fix Suggestions tests.

Covers, without any live LLM or network:

- extract_fix_context: enclosing-function + imports extraction, fail-soft
  on missing/unparseable files
- generate_fix: prompt/parse with a stub client, confidence coercion
- validate_fix: verbatim anchoring, difflib diff, Python syntax check
  (incl. broken patch), non-Python skip, missing file
- endpoint POST /api/findings/{id}/fix-suggestion: happy path, caching
  (no double billing), 402 on exhausted quota, 404 isolation, 502 on
  LLM failure, 503 when the AI provider is not configured

DB isolation: BRAIMSEC_DB points at a tmp file BEFORE any import.
"""
import json
import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-fix-test-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from billing import (  # noqa: E402
    create_org, provision_key, set_subscription_plan, usage_count,
)
from database import get_db, init_db  # noqa: E402
from fix_suggestions import (  # noqa: E402
    extract_fix_context, generate_fix, validate_fix,
)

HEADERS = {"x-api-key": "test-key-123"}

VULN_SRC = (
    "import os\n"
    "import subprocess\n"
    "\n"
    "def run(cmd):\n"
    "    os.system(\"ls \" + cmd)\n"
    "\n"
    "def ok():\n"
    "    return 1\n"
)

ORIG_BLOCK = '    os.system("ls " + cmd)'
PATCHED_BLOCK = '    subprocess.run(["ls", cmd], check=True)'


@pytest.fixture()
def vuln_file(tmp_path):
    p = tmp_path / "app.py"
    p.write_text(VULN_SRC)
    return str(p)


class StubClient:
    """Stand-in for ai_layer.LLMClient."""

    def __init__(self, payload=None, configured=True, fail=False):
        self.configured = configured
        self.payload = payload
        self.fail = fail
        self.calls = 0

    def chat(self, system, user, **kw):
        self.calls += 1
        if self.fail:
            raise RuntimeError("boom")
        return self.payload


def _fix_json(original=ORIG_BLOCK, patched=PATCHED_BLOCK, conf=0.9):
    return json.dumps({
        "explanation": "شرح عربي",
        "original": original,
        "patched": patched,
        "confidence": conf,
        "caveats": "تحقق يدوي",
    })


# ---------------------------------------------------------------------------
# extract_fix_context
# ---------------------------------------------------------------------------

def test_extract_fix_context_returns_function_and_imports(vuln_file):
    func, imports = extract_fix_context(vuln_file, 5)
    assert "def run(cmd):" in func
    assert "def ok():" not in func
    assert "import os" in imports and "import subprocess" in imports


def test_extract_fix_context_fail_soft():
    assert extract_fix_context("/does/not/exist.py", 1) == ("", "")
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write("def broken(:\n")
        bad = f.name
    assert extract_fix_context(bad, 1) == ("", "")
    os.unlink(bad)


# ---------------------------------------------------------------------------
# generate_fix (stubbed LLM)
# ---------------------------------------------------------------------------

def test_generate_fix_parses_stub_response():
    client = StubClient(_fix_json())
    finding = {"tool": "semgrep", "rule_id": "x", "severity": "error",
               "message": "m", "file": "app.py", "line": 5, "col": 1,
               "ai_verdict": "vulnerable", "ai_confidence": 0.95,
               "ai_explanation": "e"}
    gen = generate_fix(client, finding, "def run(cmd):\n" + ORIG_BLOCK + "\n",
                       "import os")
    assert gen["fix_explanation"] == "شرح عربي"
    assert gen["fix_original"] == ORIG_BLOCK
    assert gen["fix_patched"] == PATCHED_BLOCK
    assert gen["fix_confidence"] == 0.9
    assert gen["fix_caveats"] == "تحقق يدوي"
    assert client.calls == 1


def test_generate_fix_bad_confidence_coerced():
    gen = generate_fix(StubClient(_fix_json(conf="nonsense")), {})
    assert gen["fix_confidence"] == 0.0


def test_generate_fix_bad_json_raises():
    with pytest.raises(Exception):
        generate_fix(StubClient("not json at all {{{"), {})


# ---------------------------------------------------------------------------
# validate_fix
# ---------------------------------------------------------------------------

def test_validate_fix_applies_and_parses(vuln_file):
    checks = validate_fix(vuln_file, ORIG_BLOCK, PATCHED_BLOCK)
    assert checks["applies"] is True
    assert checks["syntax_ok"] is True
    assert checks["diff"].startswith("--- a/")
    assert "-" + ORIG_BLOCK in checks["diff"]
    assert "+" + PATCHED_BLOCK in checks["diff"]


def test_validate_fix_original_not_found(vuln_file):
    checks = validate_fix(vuln_file, "    no.such(code)", PATCHED_BLOCK)
    assert checks["applies"] is False
    assert checks["syntax_ok"] is None
    assert checks["diff"] == ""


def test_validate_fix_broken_patch_syntax(vuln_file):
    checks = validate_fix(vuln_file, ORIG_BLOCK, "def broken(:")
    assert checks["applies"] is True
    assert checks["syntax_ok"] is False


def test_validate_fix_non_python_skips_syntax(tmp_path):
    p = tmp_path / "app.js"
    p.write_text("const x = eval(userInput);\n")
    checks = validate_fix(str(p), "eval(userInput)", "safe(userInput)")
    assert checks["applies"] is True
    assert checks["syntax_ok"] is None  # not checked outside Python
    assert "--- a/app.js" in checks["diff"]


def test_validate_fix_missing_file():
    checks = validate_fix("/does/not/exist.py", ORIG_BLOCK, PATCHED_BLOCK)
    assert checks["applies"] is False


# ---------------------------------------------------------------------------
# endpoint
# ---------------------------------------------------------------------------

@pytest.fixture()
def seeded(tmp_path):
    """Fresh org (pro) + one scan + one finding anchored in a real file.

    A new org per test keeps the usage_ledger fully isolated between tests.
    """
    init_db()
    org_id = create_org("fixorg-" + os.urandom(3).hex(), plan="pro")
    headers = {"x-api-key": provision_key(org_id)}
    src = tmp_path / "app.py"
    src.write_text(VULN_SRC)
    db = get_db()
    scan_id = "scan_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        (scan_id, org_id, "t", "done", "2026-01-01T00:00:00+00:00"))
    cur = db.execute(
        "INSERT INTO findings (scan_id, tool, rule_id, severity, message,"
        " file, line, col) VALUES (?,?,?,?,?,?,?,?)",
        (scan_id, "semgrep", "python.lang.security.audit.os-system",
         "error", "os.system", str(src), 5, 5))
    finding_id = cur.lastrowid
    db.commit()
    db.close()
    return scan_id, finding_id, str(src), headers, org_id


def _other_org_finding(tmp_path):
    org2 = create_org("other-" + os.urandom(3).hex(), plan="pro")
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at)"
        " VALUES (?,?,?,?,?)",
        ("scan_other", org2, "t", "done", "2026-01-01T00:00:00+00:00"))
    cur = db.execute(
        "INSERT INTO findings (scan_id, tool, rule_id, severity, message,"
        " file, line, col) VALUES (?,?,?,?,?,?,?,?)",
        ("scan_other", "semgrep", "r", "error", "m", "x.py", 1, 1))
    other_id = cur.lastrowid
    db.commit()
    db.close()
    return other_id


def _stub_llm(monkeypatch, payload=None, configured=True, fail=False):
    stub = StubClient(payload or _fix_json(), configured, fail)
    monkeypatch.setattr(main, "make_llm_client", lambda: stub)
    return stub


def test_endpoint_happy_path_and_persists(seeded, monkeypatch):
    _, finding_id, _, headers, org_id = seeded
    stub = _stub_llm(monkeypatch)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/fix-suggestion",
                   headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cached"] is False
    sug = body["suggestion"]
    assert sug["explanation"] == "شرح عربي"
    assert sug["confidence"] == 0.9
    assert sug["caveats"] == "تحقق يدوي"
    assert sug["checks"]["applies"] is True
    assert sug["checks"]["syntax_ok"] is True
    assert "-" + ORIG_BLOCK in sug["diff"]
    assert "+" + PATCHED_BLOCK in sug["diff"]
    assert sug["generated_at"]
    assert stub.calls == 1
    # persisted + billed two ai_review units (x2 patch-generation weight)
    db = get_db()
    row = db.execute("SELECT fix_generated_at FROM findings WHERE id=?",
                     (finding_id,)).fetchone()
    db.close()
    assert row["fix_generated_at"]
    assert usage_count(org_id, "ai_review") == 2


def test_endpoint_cached_second_call_is_free(seeded, monkeypatch):
    _, finding_id, _, headers, org_id = seeded
    _stub_llm(monkeypatch)
    with TestClient(main.app) as c:
        c.post(f"/api/findings/{finding_id}/fix-suggestion", headers=headers)
        stub2 = _stub_llm(monkeypatch)  # fresh stub: must NOT be called
        r = c.post(f"/api/findings/{finding_id}/fix-suggestion",
                   headers=headers)
    assert r.status_code == 200
    assert r.json()["cached"] is True
    assert stub2.calls == 0
    assert usage_count(org_id, "ai_review") == 2


def test_endpoint_402_when_quota_exhausted(seeded, monkeypatch):
    _, finding_id, _, headers, org_id = seeded
    set_subscription_plan(org_id, "free")  # free: 0 ai_review units
    _stub_llm(monkeypatch)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/fix-suggestion",
                   headers=headers)
    assert r.status_code == 402, r.text
    assert usage_count(org_id, "ai_review") == 0


def test_endpoint_404_unknown_finding(seeded, monkeypatch):
    _, _, _, headers, _ = seeded
    _stub_llm(monkeypatch)
    with TestClient(main.app) as c:
        r = c.post("/api/findings/999999/fix-suggestion", headers=headers)
    assert r.status_code == 404


def test_endpoint_404_other_org_finding(seeded, monkeypatch, tmp_path):
    """Org isolation: one org cannot request a fix for another org's finding."""
    _, _, _, headers, _ = seeded
    other_id = _other_org_finding(tmp_path)
    _stub_llm(monkeypatch)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{other_id}/fix-suggestion",
                   headers=headers)
    assert r.status_code == 404


def test_endpoint_502_when_llm_fails(seeded, monkeypatch):
    _, finding_id, _, headers, org_id = seeded
    _stub_llm(monkeypatch, fail=True)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/fix-suggestion",
                   headers=headers)
    assert r.status_code == 502, r.text
    assert usage_count(org_id, "ai_review") == 0  # no usage recorded


def test_endpoint_503_when_ai_not_configured(seeded, monkeypatch):
    _, finding_id, _, headers, org_id = seeded
    _stub_llm(monkeypatch, configured=False)
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/fix-suggestion",
                   headers=headers)
    assert r.status_code == 503, r.text
    assert usage_count(org_id, "ai_review") == 0


def test_endpoint_401_without_key(seeded):
    _, finding_id, _, _, _ = seeded
    with TestClient(main.app) as c:
        r = c.post(f"/api/findings/{finding_id}/fix-suggestion")
    assert r.status_code == 401


def test_endpoint_live_llm_skipped_without_keys(seeded):
    """Real LLM smoke test — skipped unless AI keys are configured."""
    from ai_layer import LLMClient
    if not LLMClient().configured:
        pytest.skip("no AI provider keys configured")
