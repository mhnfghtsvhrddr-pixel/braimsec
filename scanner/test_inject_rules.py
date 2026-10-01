"""Custom injection-rule pack tests (scanner/rules/braimsec-inject.yaml).

- Rule-pack hygiene: 9 rules, braimsec.inject.* ids (no binary needed)
- Behavior: paired vuln/safe snippets — every rule fires on its true
  positive and stays silent on clean code (needs semgrep; skipped when
  the binary is absent). This is the FP-discipline gate: a rule that
  fires on a SAFE sample fails the suite.
- Engine wiring: run_semgrep passes the pack via --config; empty
  BRAIMSEC_INJECT_RULES disables it (no binary needed — _run is stubbed)

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
                     "rules", "braimsec-inject.yaml")


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
    """Run ONLY the braimsec inject pack on {name: source} -> [(rule, file, line)]."""
    d = tempfile.mkdtemp(prefix="inject-test-")
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
        i = rid.find("braimsec.inject.")
        if i != -1:
            res.append((rid[i:], os.path.basename(r["path"]),
                        r["start"]["line"]))
    return res


# ---------------------------------------------------------------------------
# pack hygiene (no binary)
# ---------------------------------------------------------------------------

EXPECTED_IDS = [
    "braimsec.inject.command-injection",
    "braimsec.inject.deserialization",
    "braimsec.inject.js-code-eval",
    "braimsec.inject.js-dom-xss",
    "braimsec.inject.python-code-eval",
    "braimsec.inject.sqli",
    "braimsec.inject.xss-render-template-string",
    "braimsec.inject.xxe-tainted-parse",
    "braimsec.inject.xxe-unsafe-parser",
]

TAINT_IDS = [i for i in EXPECTED_IDS if i != "braimsec.inject.xxe-unsafe-parser"]


def test_pack_has_nine_inject_rules():
    with open(RULES) as f:
        pack = yaml.safe_load(f)
    rules = pack["rules"]
    assert len(rules) == 9
    assert sorted(r["id"] for r in rules) == EXPECTED_IDS


def test_taint_rules_are_taint_mode_and_python_or_js():
    with open(RULES) as f:
        pack = yaml.safe_load(f)
    by_id = {r["id"]: r for r in pack["rules"]}
    for rid in TAINT_IDS:
        assert by_id[rid]["mode"] == "taint", rid
    py_ids = {"braimsec.inject.command-injection",
              "braimsec.inject.xxe-tainted-parse",
              "braimsec.inject.deserialization", "braimsec.inject.sqli",
              "braimsec.inject.python-code-eval",
              "braimsec.inject.xss-render-template-string"}
    js_ids = {"braimsec.inject.js-code-eval", "braimsec.inject.js-dom-xss"}
    for rid in py_ids:
        assert "python" in by_id[rid]["languages"], rid
    for rid in js_ids:
        assert "javascript" in by_id[rid]["languages"], rid
        assert "typescript" in by_id[rid]["languages"], rid


# ---------------------------------------------------------------------------
# behavior: paired vuln / safe snippets (needs binary)
# ---------------------------------------------------------------------------

VULN = {
    "cmd.py": ("import os, subprocess, sys\nfrom flask import request\n"
               "def f():\n    c = request.args.get('c')\n"
               "    os.system(c)\n"
               "    subprocess.call(c, shell=True)\n"
               "    os.popen(sys.argv[1])\n"),
    "xxe.py": ("from lxml import etree\nfrom flask import request\n"
               "def f():\n    p = etree.XMLParser()\n"
               "    return etree.fromstring(request.data)\n"),
    "deser.py": ("import pickle, yaml\nfrom flask import request\n"
                 "def f():\n    a = pickle.loads(request.data)\n"
                 "    b = yaml.load(request.form['y'])\n"
                 "    return (a, b)\n"),
    "sqli.py": ("from flask import request\n"
                "def f(cur):\n    u = request.args.get('u')\n"
                "    cur.execute(\"SELECT * FROM t WHERE n='%s'\" % u)\n"
                "    q = \"SELECT * FROM t WHERE n='{}'\".format(u)\n"
                "    cur.execute(q)\n"),
    "xss.py": ("from flask import request, render_template_string\n"
               "def f():\n    n = request.args.get('n')\n"
               "    return render_template_string('<h1>' + n + '</h1>')\n"),
    "eval.js": ("function h(req) {\n"
                "    eval(req.query.cmd);\n"
                "    const f = new Function(req.body.code);\n"
                "    setTimeout(req.query.t, 100);\n"
                "}\n"),
    "domxss.js": ("function h(req) {\n"
                  "    el.innerHTML = req.query.name;\n"
                  "    el.insertAdjacentHTML('beforeend', req.body.html);\n"
                  "}\n"),
    "peval.py": ("from flask import request\n"
                 "def calc():\n"
                 "    expr = request.args.get('expr', '')\n"
                 "    return str(eval(expr))\n"
                 "def run():\n"
                 "    exec(request.form['code'])\n"),
}

SAFE = {
    # constants are never tainted -> silent by construction
    "cmd_safe.py": ("import os, subprocess, shlex\nfrom flask import request\n"
                    "def f():\n"
                    "    subprocess.run(['ls', '-l'], check=True)\n"
                    "    os.system('echo hello')\n"
                    "    os.system('echo ' + shlex.quote(request.args.get('c')))\n"),
    "xxe_safe.py": ("from lxml import etree\n"
                    "def f():\n"
                    "    p = etree.XMLParser(resolve_entities=False, no_network=True)\n"
                    "    return etree.fromstring(b'<a/>', p)\n"),
    "deser_safe.py": ("import pickle, yaml\nfrom flask import request\n"
                      "def f():\n"
                      "    a = yaml.safe_load(request.form['y'])\n"
                      "    b = yaml.load(request.form['y'], Loader=yaml.SafeLoader)\n"
                      "    c = pickle.loads(b'static')\n"
                      "    return (a, b, c)\n"),
    # parameterized / constant queries are never tainted -> silent
    "sqli_safe.py": ("def f(cur, uid):\n"
                     "    cur.execute('SELECT * FROM t WHERE id = %s', (uid,))\n"
                     "    cur.execute('SELECT * FROM t')\n"),
    "xss_safe.py": ("from flask import render_template_string\n"
                    "def f():\n"
                    "    return render_template_string('<h1>hello</h1>')\n"),
    "js_safe.js": ("function h(req) {\n"
                   "    eval('2+2');\n"
                   "    el.textContent = req.query.name;\n"
                   "    el.innerHTML = DOMPurify.sanitize(req.body.html);\n"
                   "    el.innerHTML = '<b>static</b>';\n"
                   "}\n"),
    # eval/exec on constants and ast.literal_eval are not code execution sinks
    "peval_safe.py": ("import ast\nfrom flask import request\n"
                      "def f():\n"
                      "    a = eval('1+2')\n"
                      "    b = ast.literal_eval(request.args.get('e'))\n"
                      "    return (a, b)\n"),
}


@needs_sg
def test_vuln_snippets_fire():
    got = {(r, f) for r, f, _ in _run_rules(VULN)}
    assert ("braimsec.inject.command-injection", "cmd.py") in got
    assert ("braimsec.inject.xxe-unsafe-parser", "xxe.py") in got
    assert ("braimsec.inject.xxe-tainted-parse", "xxe.py") in got
    assert ("braimsec.inject.deserialization", "deser.py") in got
    assert ("braimsec.inject.sqli", "sqli.py") in got
    assert ("braimsec.inject.xss-render-template-string", "xss.py") in got
    assert ("braimsec.inject.js-code-eval", "eval.js") in got
    assert ("braimsec.inject.js-dom-xss", "domxss.js") in got
    assert ("braimsec.inject.python-code-eval", "peval.py") in got


@needs_sg
def test_safe_snippets_silent():
    # FP-discipline gate: clean code must produce zero inject-pack findings.
    assert _run_rules(SAFE) == []


@needs_sg
def test_source_expression_itself_does_not_fire():
    # Regression guard: the taint SOURCE call alone must not be a finding.
    got = _run_rules({"s.py": "from flask import request\n"
                              "def f():\n"
                              "    u = request.args.get('u')\n"
                              "    return u\n"})
    assert got == []


# ---------------------------------------------------------------------------
# engine wiring (no binary — _run stubbed)
# ---------------------------------------------------------------------------

def test_scan_engine_passes_inject_config(monkeypatch):
    import scan_engine
    seen = {}

    def fake_run(cmd, timeout=600):
        seen["cmd"] = cmd
        class R:  # noqa: D106
            returncode = 0
        return R()

    monkeypatch.setattr(scan_engine, "_run", fake_run)
    monkeypatch.setattr(scan_engine, "BRAIMSEC_INJECT_RULES", RULES)
    with tempfile.TemporaryDirectory() as d:
        with monkeypatch.context() as m:
            m.setattr("json.load", lambda f: {"results": []})
            scan_engine.run_semgrep(d)
    cmd = seen["cmd"]
    assert "--config" in cmd
    assert RULES in cmd
    assert scan_engine.BRAIMSEC_TAINT_RULES in cmd
    assert scan_engine.BRAIMSEC_GHA_RULES in cmd
    assert cmd.count("--config") == 4  # auto + taint + gha + inject packs


def test_scan_engine_inject_rules_can_be_disabled(monkeypatch):
    import scan_engine
    seen = {}

    def fake_run(cmd, timeout=600):
        seen["cmd"] = cmd
        class R:  # noqa: D106
            returncode = 0
        return R()

    monkeypatch.setattr(scan_engine, "_run", fake_run)
    monkeypatch.setattr(scan_engine, "BRAIMSEC_INJECT_RULES", "")
    with tempfile.TemporaryDirectory() as d:
        with monkeypatch.context() as m:
            m.setattr("json.load", lambda f: {"results": []})
            scan_engine.run_semgrep(d)
    assert seen["cmd"].count("--config") == 3  # auto + taint + gha packs
