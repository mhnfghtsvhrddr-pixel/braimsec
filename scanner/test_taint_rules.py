"""Custom taint-rule pack tests (scanner/rules/braimsec-taint.yaml).

- Rule-pack hygiene: 4 rules, taint mode, braimsec.taint.* ids (no binary needed)
- Behavior: vuln snippets fire / safe snippets stay silent (needs semgrep;
  skipped when the binary is absent)
- Engine wiring: run_semgrep passes the pack via --config; empty
  BRAIMSEC_TAINT_RULES disables it (no binary needed — _run is stubbed)
- Fresh-holdout eval runner exits 0 on the shipped set (needs semgrep)

Semgrep binary resolution: $SEMGREP_BIN, else PATH, else ~/workspace/venvs/sgvenv.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "rules", "braimsec-taint.yaml")
EVAL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "eval", "run_eval.py")


def _semgrep():
    for cand in (os.environ.get("SEMGREP_BIN"),
                 shutil.which("semgrep"),
                 os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


SG = _semgrep()
needs_sg = pytest.mark.skipif(SG is None, reason="semgrep binary not found")


def _run_rules(files):
    """Run ONLY the braimsec pack on {name: source} dict -> [(rule, file, line)]."""
    d = tempfile.mkdtemp(prefix="taint-test-")
    for name, src in files.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(src)
    out = os.path.join(d, "out.json")
    subprocess.run([SG, "--config", RULES, "--json", "-o", out, d],
                   capture_output=True, timeout=300)
    with open(out) as f:
        data = json.load(f)
    res = []
    for r in data.get("results", []):
        rid = r["check_id"]
        i = rid.find("braimsec.taint.")
        if i != -1:
            res.append((rid[i:], os.path.basename(r["path"]),
                        r["start"]["line"]))
    return res


# ---------------------------------------------------------------------------
# pack hygiene (no binary)
# ---------------------------------------------------------------------------

def test_pack_has_four_taint_rules():
    with open(RULES) as f:
        pack = yaml.safe_load(f)
    rules = pack["rules"]
    assert len(rules) == 4
    ids = sorted(r["id"] for r in rules)
    assert ids == ["braimsec.taint.path-traversal-open",
                   "braimsec.taint.ssrf-requests",
                   "braimsec.taint.ssrf-urllib",
                   "braimsec.taint.unrestricted-file-upload"]
    assert all(r["mode"] == "taint" for r in rules)
    assert all("python" in r["languages"] for r in rules)


# ---------------------------------------------------------------------------
# behavior (needs binary)
# ---------------------------------------------------------------------------

VULN = {
    "ssrf.py": ("import requests\nfrom flask import request\n"
                "def f():\n    u = request.args.get('u')\n"
                "    return requests.get(u).text\n"),
    "upload.py": ("import os\nfrom flask import request\n"
                  "def f():\n    x = request.files['x']\n"
                  "    x.save(os.path.join('/t', x.filename))\n"),
    "trav.py": ("from flask import request\n"
                "def f():\n    p = request.args.get('p')\n"
                "    return open(p).read()\n"),
}
SAFE = {
    "const.py": ("import requests\n"
                 "def f():\n"
                 "    return requests.get('https://api.example.com/x').text\n"),
    "san.py": ("import os\nfrom flask import request\n"
               "from werkzeug.utils import secure_filename\n"
               "def f():\n    x = request.files['x']\n"
               "    x.save(os.path.join('/t', secure_filename(x.filename)))\n"
               "def g():\n    p = request.args.get('p')\n"
               "    return open(os.path.basename(p)).read()\n"),
}


@needs_sg
def test_vuln_snippets_fire():
    got = {(r, f) for r, f, _ in _run_rules(VULN)}
    assert ("braimsec.taint.ssrf-requests", "ssrf.py") in got
    assert ("braimsec.taint.unrestricted-file-upload", "upload.py") in got
    assert ("braimsec.taint.path-traversal-open", "trav.py") in got


@needs_sg
def test_safe_snippets_silent():
    assert _run_rules(SAFE) == []


@needs_sg
def test_source_expression_itself_does_not_fire():
    # Regression: generic $S.get(...) sink patterns used to match the
    # SOURCE call (request.args.get("u")) itself. Must stay silent.
    got = _run_rules({"s.py": "from flask import request\n"
                              "def f():\n"
                              "    u = request.args.get('u')\n"
                              "    return u\n"})
    assert got == []


# ---------------------------------------------------------------------------
# engine wiring (no binary — _run stubbed)
# ---------------------------------------------------------------------------

def test_scan_engine_passes_custom_config(monkeypatch):
    import scan_engine
    seen = {}

    def fake_run(cmd, timeout=600):
        seen["cmd"] = cmd
        class R:  # noqa: D106
            returncode = 0
        return R()

    monkeypatch.setattr(scan_engine, "_run", fake_run)
    monkeypatch.setattr(scan_engine, "BRAIMSEC_TAINT_RULES", RULES)
    with tempfile.TemporaryDirectory() as d:
        with monkeypatch.context() as m:
            m.setattr("json.load", lambda f: {"results": []})
            scan_engine.run_semgrep(d)
    cmd = seen["cmd"]
    assert "--config" in cmd
    assert RULES in cmd
    assert cmd.count("--config") == 2  # auto + braimsec pack


def test_scan_engine_taint_rules_can_be_disabled(monkeypatch):
    import scan_engine
    seen = {}

    def fake_run(cmd, timeout=600):
        seen["cmd"] = cmd
        class R:  # noqa: D106
            returncode = 0
        return R()

    monkeypatch.setattr(scan_engine, "_run", fake_run)
    monkeypatch.setattr(scan_engine, "BRAIMSEC_TAINT_RULES", "")
    with tempfile.TemporaryDirectory() as d:
        with monkeypatch.context() as m:
            m.setattr("json.load", lambda f: {"results": []})
            scan_engine.run_semgrep(d)
    assert seen["cmd"].count("--config") == 1  # auto only


# ---------------------------------------------------------------------------
# fresh-holdout eval runner
# ---------------------------------------------------------------------------

@needs_sg
def test_fresh_holdout_eval_passes():
    env = dict(os.environ, SEMGREP_BIN=SG)
    p = subprocess.run([sys.executable, EVAL], capture_output=True, text=True,
                       timeout=600, env=env)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "precision=1.000 recall=1.000" in p.stdout
