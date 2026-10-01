"""High-risk sink auditing tests.

Covers, without any LLM or network:

- AST discovery: sink inventory, import-alias resolution, line numbers,
  fail-soft on unparseable files
- taint pre-filter: constants skipped (no AI spend), user input / params /
  one-hop assignments become candidates
- analyze_sink: verdict mapping + precision gate (should_store)
- task wiring (_run_ai_review_impl): quota gating, per-call billing,
  pre-reviewed findings (no double billing), idempotent retry,
  SINK_AUDIT_OFF kill switch, missing-sources skip

DB isolation: BRAIMSEC_DB points at a tmp file BEFORE any import.
"""
import json
import os
import sys
import tempfile
from types import SimpleNamespace

import pytest

_tmp = tempfile.mkdtemp(prefix="braimsec-sink-test-")
os.environ["BRAIMSEC_DB"] = os.path.join(_tmp, "test.db")
os.environ["BRAIMSEC_API_KEY"] = "test-key-123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "ai"))

import tasks  # noqa: E402
from database import get_db, init_db  # noqa: E402
from sink_audit import (  # noqa: E402
    analyze_sink,
    audit_candidates,
    discover_sinks,
    min_confidence,
    should_store,
)

VULN_APP = '''
import requests
import os
from os import system
import subprocess as sp

def fetch():
    url = request.args.get("u")
    return requests.get(url).text

def safe_fetch():
    return requests.get("https://api.example.com/x").text

def run(cmd):
    os.system("ls " + cmd)

def aliased(target):
    system("echo " + target)
    sp.run(["ls", target])

def reader(p):
    return open(p).read()

def const_open():
    return open("/etc/hostname").read()

def env_reader():
    return open(os.environ.get("DATA")).read()

def typed_cli():
    import sys
    return open(sys.argv[1]).read()
'''


@pytest.fixture()
def target_dir():
    d = tempfile.mkdtemp(prefix="sink-target-")
    with open(os.path.join(d, "app.py"), "w") as f:
        f.write(VULN_APP)
    with open(os.path.join(d, "broken.py"), "w") as f:
        f.write("def oops(:\n  this is not python\n")
    return d


class FakeSelf:
    class RetryRaised(Exception):
        pass

    def __init__(self, max_retries=0):
        self.max_retries = max_retries
        self.request = SimpleNamespace(retries=0)

    def retry(self, exc=None, countdown=None):
        raise FakeSelf.RetryRaised()


class StubClient:
    """LLM stand-in: configured, returns canned JSON."""
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    @property
    def configured(self):
        return True

    def chat(self, system, user, max_tokens=900, temperature=0.2):
        self.calls += 1
        return json.dumps(self.payload, ensure_ascii=False)


def _mk_scan(target_dir=None):
    init_db()
    db = get_db()
    scan_id = "sink_" + os.urandom(4).hex()
    db.execute(
        "INSERT INTO scans (id, org_id, target_name, status, created_at,"
        " target_dir) VALUES (?,?,?,?,?,?)",
        (scan_id, "owner", "t", "done", "2026-01-01T00:00:00+00:00",
         target_dir))
    db.commit()
    db.close()
    return scan_id


# --- discovery ------------------------------------------------------------

def test_discover_finds_sinks_with_lines(target_dir):
    sites = discover_sinks(target_dir)
    by_line = {s["line"]: s for s in sites}
    assert by_line[9]["sink"] == "requests.get"
    assert by_line[9]["category"] == "ssrf"
    assert by_line[9]["function"] == "fetch"
    assert by_line[15]["sink"] == "os.system"
    assert by_line[15]["category"] == "command-injection"
    # import-alias resolution
    assert by_line[18]["sink"] == "os.system"       # from os import system
    assert by_line[19]["sink"] == "subprocess.run"  # import subprocess as sp
    assert by_line[22]["sink"] == "open"
    assert by_line[25]["sink"] == "open"
    assert by_line[32]["sink"] == "open"            # sys.argv[1]


def test_discover_skips_broken_files(target_dir):
    sites = discover_sinks(target_dir)
    assert all(s["file"].endswith("app.py") for s in sites)


def test_discover_ignores_non_py_and_missing_dir(target_dir):
    with open(os.path.join(target_dir, "notes.txt"), "w") as f:
        f.write("requests.get(url)")
    assert discover_sinks(os.path.join(target_dir, "nope")) == []
    assert all(s["file"].endswith(".py") for s in discover_sinks(target_dir))


# --- taint pre-filter -------------------------------------------------------

def test_prefilter_taint_verdicts(target_dir):
    sites = {s["line"]: s for s in discover_sinks(target_dir)}
    assert sites[9]["taint"] == "tainted"    # request.args.get("u")
    assert sites[12]["taint"] == "clean"     # constant URL — no AI spend
    assert sites[15]["taint"] == "tainted"   # function param
    assert sites[18]["taint"] == "tainted"   # alias, param
    assert sites[22]["taint"] == "tainted"   # open(param)
    assert sites[25]["taint"] == "clean"     # open(constant)
    assert sites[28]["taint"] == "unknown"   # os.environ — AI decides
    assert sites[32]["taint"] == "tainted"   # sys.argv[1]


def test_candidates_exclude_clean_and_cap(target_dir, monkeypatch):
    sites = discover_sinks(target_dir)
    cands = audit_candidates(sites)
    assert all(s["taint"] != "clean" for s in cands)
    assert len(cands) == 7  # 9 sites - 2 clean
    monkeypatch.setenv("SINK_AUDIT_MAX_PER_SCAN", "3")
    assert len(audit_candidates(sites)) == 3


# --- analyze_sink -----------------------------------------------------------

def test_analyze_sink_verdict_mapping():
    site = {"sink": "requests.get", "category": "ssrf", "file": "app.py",
            "line": 8, "function": "fetch", "taint": "tainted"}
    res = analyze_sink(StubClient({
        "verdict": "vulnerable", "confidence": 0.9,
        "taint_source": "request.args", "explanation": "شرح",
        "fix": "تحقق"}), site, "code")
    assert res["ai_verdict"] == "true_positive"
    assert res["ai_confidence"] == 0.9
    assert res["taint_source"] == "request.args"

    res = analyze_sink(StubClient({"verdict": "safe", "confidence": 0.95,
                                   "explanation": "", "fix": ""}), site, "")
    assert res["ai_verdict"] == "false_positive"

    res = analyze_sink(StubClient({"verdict": "needs_review", "confidence": 0.4,
                                   "explanation": "", "fix": ""}), site, "")
    assert res["ai_verdict"] == "needs_review"


def test_should_store_precision_gate(monkeypatch):
    assert should_store({"ai_verdict": "true_positive", "ai_confidence": 0.9})
    assert not should_store({"ai_verdict": "true_positive", "ai_confidence": 0.5})
    assert not should_store({"ai_verdict": "false_positive", "ai_confidence": 0.99})
    assert not should_store({"ai_verdict": "needs_review", "ai_confidence": 0.9})
    monkeypatch.setenv("SINK_AUDIT_MIN_CONFIDENCE", "0.95")
    assert min_confidence() == 0.95
    assert not should_store({"ai_verdict": "true_positive", "ai_confidence": 0.9})


# --- task wiring ------------------------------------------------------------

@pytest.fixture()
def wired(monkeypatch):
    """Task with stubbed LLM, open quota, and usage recording observed."""
    usage = []
    monkeypatch.setattr(tasks, "make_llm_client", lambda: StubClient({}))
    monkeypatch.setattr(tasks, "quota_check", lambda o, k, u=(1,): (True, 0, 200))
    monkeypatch.setattr(tasks, "record_usage",
                        lambda o, k, s, wall_time_ms=0: usage.append((o, k, s)))
    monkeypatch.delenv("SINK_AUDIT_OFF", raising=False)
    return usage


def _sink_findings(scan_id):
    db = get_db()
    rows = db.execute("SELECT * FROM findings WHERE scan_id=? AND tool='sink-audit'",
                      (scan_id,)).fetchall()
    db.close()
    return [dict(r) for r in rows]


def test_task_confirms_vulnerable_sink(monkeypatch, wired, target_dir):
    def fake_analyze(client, site, snippet=""):
        return {"ai_verdict": "true_positive", "ai_confidence": 0.9,
                "ai_explanation": "SSRF عبر request.args", "ai_fix": "allowlist",
                "taint_source": "request.args"}
    monkeypatch.setattr(tasks, "analyze_sink", fake_analyze)
    scan_id = _mk_scan(target_dir)
    out = tasks._run_ai_review_impl(FakeSelf(), scan_id)
    rows = _sink_findings(scan_id)
    assert out["sink_audit"]["status"] == "audited"
    assert out["sink_audit"]["confirmed"] == len(rows) >= 1
    ssrf = [r for r in rows if r["rule_id"] == "ssrf-sink"]
    assert ssrf and ssrf[0]["ai_verdict"] == "true_positive"  # pre-reviewed
    assert ssrf[0]["ai_confidence"] == 0.9
    # billed once per AI call from the same ai_review pool as finding reviews
    assert len(wired) == out["sink_audit"]["audited"]
    assert all(k == "ai_review" for _, k, _ in wired)
    # total_findings grew
    db = get_db()
    total = db.execute("SELECT total_findings FROM scans WHERE id=?",
                       (scan_id,)).fetchone()["total_findings"]
    db.close()
    assert total == len(rows)


def test_task_skips_safe_verdicts(monkeypatch, wired, target_dir):
    monkeypatch.setattr(tasks, "analyze_sink",
                        lambda c, s, snippet="": {
                            "ai_verdict": "false_positive", "ai_confidence": 0.95,
                            "ai_explanation": "", "ai_fix": "", "taint_source": ""})
    scan_id = _mk_scan(target_dir)
    out = tasks._run_ai_review_impl(FakeSelf(), scan_id)
    assert out["sink_audit"]["audited"] > 0
    assert out["sink_audit"]["confirmed"] == 0
    assert _sink_findings(scan_id) == []
    assert len(wired) == out["sink_audit"]["audited"]  # quota still spent


def test_task_idempotent_on_retry(monkeypatch, wired, target_dir):
    monkeypatch.setattr(tasks, "analyze_sink",
                        lambda c, s, snippet="": {
                            "ai_verdict": "true_positive", "ai_confidence": 0.9,
                            "ai_explanation": "x", "ai_fix": "y", "taint_source": ""})
    scan_id = _mk_scan(target_dir)
    tasks._run_ai_review_impl(FakeSelf(), scan_id)
    first = len(_sink_findings(scan_id))
    assert first > 0
    tasks._run_ai_review_impl(FakeSelf(), scan_id)  # retry must not duplicate
    rows = _sink_findings(scan_id)
    assert len(rows) == first
    keys = [(r["rule_id"], r["file"], r["line"]) for r in rows]
    assert len(keys) == len(set(keys))


def test_task_quota_exhausted_spends_nothing(monkeypatch, wired, target_dir):
    monkeypatch.setattr(tasks, "quota_check", lambda o, k, u=1: (False, 200, 200))
    calls = []
    monkeypatch.setattr(tasks, "analyze_sink",
                        lambda c, s, snippet="": calls.append(s) or {})
    scan_id = _mk_scan(target_dir)
    out = tasks._run_ai_review_impl(FakeSelf(), scan_id)
    assert calls == []
    assert out["sink_audit"]["audited"] == 0
    assert out["sink_audit"]["skipped_quota"] == out["sink_audit"]["candidates"] > 0
    assert _sink_findings(scan_id) == []
    assert wired == []


def test_task_respects_kill_switch(monkeypatch, wired, target_dir):
    monkeypatch.setenv("SINK_AUDIT_OFF", "1")
    scan_id = _mk_scan(target_dir)
    out = tasks._run_ai_review_impl(FakeSelf(), scan_id)
    assert out["sink_audit"]["status"] == "disabled"
    assert _sink_findings(scan_id) == []


def test_task_skips_when_sources_gone(monkeypatch, wired):
    scan_id = _mk_scan("/nonexistent/dir")
    out = tasks._run_ai_review_impl(FakeSelf(), scan_id)
    assert out["sink_audit"]["status"] == "skipped_no_sources"
    scan_id2 = _mk_scan(None)
    out2 = tasks._run_ai_review_impl(FakeSelf(), scan_id2)
    assert out2["sink_audit"]["status"] == "skipped_no_sources"


def test_sink_findings_not_rebilled(monkeypatch, wired, target_dir):
    """Pre-reviewed sink findings (ai_verdict set) are invisible to the
    pending-findings loop — no double billing on a later review run."""
    reviewed = []
    monkeypatch.setattr(tasks, "analyze_sink",
                        lambda c, s, snippet="": {
                            "ai_verdict": "true_positive", "ai_confidence": 0.9,
                            "ai_explanation": "x", "ai_fix": "y", "taint_source": ""})
    monkeypatch.setattr(tasks, "analyze_finding",
                        lambda c, f, s="": reviewed.append(f["id"]) or {})
    scan_id = _mk_scan(target_dir)
    tasks._run_ai_review_impl(FakeSelf(), scan_id)
    n1 = len(_sink_findings(scan_id))
    assert n1 > 0
    tasks._run_ai_review_impl(FakeSelf(), scan_id)
    assert reviewed == []  # sink findings already carry ai_verdict


def test_task_no_llm_configured_skips(monkeypatch, target_dir):
    class DeadClient:
        @property
        def configured(self):
            return False
    monkeypatch.setattr(tasks, "make_llm_client", DeadClient)
    scan_id = _mk_scan(target_dir)
    out = tasks._run_ai_review_impl(FakeSelf(), scan_id)
    assert out["sink_audit"]["status"] == "skipped_no_llm"


# --- live LLM (skipped without credentials) ---------------------------------

def test_live_sink_audit_skipped_without_llm(target_dir):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "ai"))
    from ai_layer import LLMClient
    if not LLMClient().configured:
        pytest.skip("no LLM credentials configured")
    sites = [s for s in discover_sinks(target_dir) if s["line"] == 9]
    assert sites, "expected the SSRF sink at app.py:9"
    from ai_layer import read_snippet
    res = analyze_sink(LLMClient(), sites[0],
                       read_snippet(sites[0]["file"], sites[0]["line"], radius=30))
    assert res["ai_verdict"] in ("true_positive", "false_positive", "needs_review")
    assert 0.0 <= res["ai_confidence"] <= 1.0
