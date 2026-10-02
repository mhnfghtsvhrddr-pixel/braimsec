"""Language-scoped semgrep rule selection (scanner/rule_scope.py).

- detect_languages: extension/basename -> semgrep language names, from a
  target tree or an incremental scope list.
- scoped_base_configs: a vendored-rules directory is narrowed to the
  per-language subdirs (+ always-on generic/secrets); registry names and
  unknown layouts pass through untouched (fail closed).
- select_rule_configs: honors BRAIMSEC_FULL_RULES=1 and falls back to the
  full set when detection finds nothing recognizable.
- engine e2e: a python fixture with a known taint finding still yields it
  with scoped rules; the engine command shows the narrowing.
"""
import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rule_scope import (detect_languages, scoped_base_configs,
                        select_rule_configs)


def _semgrep():
    for cand in (os.environ.get("SEMGREP_BIN"),
                 shutil.which("semgrep"),
                 os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


SG = _semgrep()
needs_sg = pytest.mark.skipif(SG is None, reason="semgrep binary not found")

TAINT_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "rules", "braimsec-taint.yaml")

SSRF_SNIPPET = ("import requests\nfrom flask import request\n"
                "def f():\n    u = request.args.get('u')\n"
                "    return requests.get(u).text\n")


def _tree(files):
    d = tempfile.mkdtemp(prefix="rulescope-")
    for rel, content in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
    return d


# ---------------------------------------------------------------------------
# detect_languages
# ---------------------------------------------------------------------------

def test_detect_languages_from_tree(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "Dockerfile").write_text("FROM x\n")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("on: push\n")
    (tmp_path / "main.tf").write_text('resource "x" "y" {}\n')
    (tmp_path / "notes.txt").write_text("hello\n")
    assert detect_languages(str(tmp_path)) == {
        "python", "dockerfile", "yaml", "terraform"}


def test_detect_languages_from_scope_list():
    scope = ["/t/a.js", "/t/b.ts", "/t/README.md"]
    assert detect_languages("/t", scope) == {"javascript", "typescript"}


def test_detect_languages_empty_dir(tmp_path):
    assert detect_languages(str(tmp_path)) == set()


def test_detect_languages_case_insensitive_and_h_header(tmp_path):
    (tmp_path / "A.PY").write_text("x=1\n")
    (tmp_path / "x.h").write_text("int f();\n")
    langs = detect_languages(str(tmp_path))
    assert "python" in langs
    assert {"c", "cpp"} <= langs  # .h is ambiguous: keep both


# ---------------------------------------------------------------------------
# scoped_base_configs
# ---------------------------------------------------------------------------

def _vendored_layout(root):
    for sub in ("python", "javascript", "generic", "secrets"):
        os.makedirs(os.path.join(root, sub))
        with open(os.path.join(root, sub, "r.yaml"), "w") as f:
            f.write("rules: []\n")
    return root


def test_scoped_base_configs_narrows_vendored_dir(tmp_path):
    vendored = _vendored_layout(str(tmp_path / "rules"))
    got = scoped_base_configs([vendored], {"python"})
    assert os.path.join(vendored, "python") in got
    assert os.path.join(vendored, "generic") in got
    assert os.path.join(vendored, "secrets") in got
    assert not any("javascript" in c for c in got)
    assert vendored not in got  # the whole dir is replaced, not duplicated


def test_scoped_base_configs_unknown_layout_kept_whole(tmp_path):
    # No generic/secrets marker subdirs -> not a vendored layout:
    # fail closed, keep the whole directory.
    other = str(tmp_path / "other")
    os.makedirs(os.path.join(other, "python"))
    assert scoped_base_configs([other], {"python"}) == [other]


def test_scoped_base_configs_registry_passthrough():
    assert scoped_base_configs(["auto"], {"python"}) == ["auto"]


def test_scoped_base_configs_no_languages_is_identity(tmp_path):
    vendored = _vendored_layout(str(tmp_path / "rules"))
    assert scoped_base_configs([vendored], set()) == [vendored]
    assert scoped_base_configs([vendored], None) == [vendored]


# ---------------------------------------------------------------------------
# select_rule_configs
# ---------------------------------------------------------------------------

def _packs(tmpdir):
    """Real pack files on disk: (name, path, languages)."""
    specs = [
        ("taint", "taint.yaml", {"python"}),
        ("gha", "gha.yaml", {"yaml"}),
        ("inject", "inject.yaml", {"python", "javascript", "typescript"}),
    ]
    out = []
    for name, fname, langs in specs:
        p = os.path.join(str(tmpdir), fname)
        with open(p, "w") as f:
            f.write("rules: []\n")
        out.append((name, p, langs))
    return out


def test_select_rule_configs_filters_packs_by_language(tmp_path):
    d = _tree({"a.py": "x=1\n"})
    base, packs = select_rule_configs(["auto"], _packs(tmp_path), d)
    assert base == ["auto"]
    assert {n for n, _p in packs} == {"taint", "inject"}  # gha dropped


def test_select_rule_configs_empty_detection_falls_back(tmp_path):
    d = _tree({"notes.txt": "hi\n"})
    base, packs = select_rule_configs(["auto"], _packs(tmp_path), d)
    assert base == ["auto"]  # full set, not narrowed
    assert {n for n, _p in packs} == {"taint", "gha", "inject"}


def test_select_rule_configs_full_rules_env_restores(tmp_path, monkeypatch):
    monkeypatch.setenv("BRAIMSEC_FULL_RULES", "1")
    d = _tree({"a.py": "x=1\n"})
    base, packs = select_rule_configs(["auto"], _packs(tmp_path), d)
    assert base == ["auto"]
    assert {n for n, _p in packs} == {"taint", "gha", "inject"}


def test_select_rule_configs_scoping_off_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BRAIMSEC_RULE_SCOPING", "0")
    d = _tree({"a.py": "x=1\n"})
    base, packs = select_rule_configs(["auto"], _packs(tmp_path), d)
    assert {n for n, _p in packs} == {"taint", "gha", "inject"}


# ---------------------------------------------------------------------------
# engine integration
# ---------------------------------------------------------------------------

def test_engine_cmd_shows_scoping_narrowing(monkeypatch, tmp_path):
    """A python-only target keeps python packs, drops the rest."""
    import scan_engine
    seen = {}

    def fake_run(cmd, timeout=600):
        seen["cmd"] = cmd

        class R:  # noqa: D106
            returncode = 0
        return R()

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setattr(scan_engine, "_run", fake_run)
    monkeypatch.delenv("BRAIMSEC_FULL_RULES", raising=False)
    with monkeypatch.context() as m:
        m.setattr("json.load", lambda f: {"results": []})
        scan_engine.run_semgrep(str(tmp_path))
    cmd = seen["cmd"]
    cfgs = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--config"]
    assert "auto" in cfgs  # registry lookup passes through
    assert scan_engine.BRAIMSEC_TAINT_RULES in cfgs
    assert scan_engine.BRAIMSEC_INJECT_RULES in cfgs
    assert scan_engine.BRAIMSEC_GHA_RULES not in cfgs
    assert scan_engine.BRAIMSEC_DOCKERFILE_RULES not in cfgs
    assert scan_engine.BRAIMSEC_TERRAFORM_RULES not in cfgs


@needs_sg
def test_e2e_scoped_python_target_still_finds_taint(monkeypatch, tmp_path):
    """A known python finding survives rule scoping (no network: the
    registry 'auto' config is replaced with an empty base)."""
    import scan_engine
    (tmp_path / "ssrf.py").write_text(SSRF_SNIPPET)
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
    monkeypatch.setattr(scan_engine, "SEMGREP_BIN", SG)
    monkeypatch.setattr(scan_engine, "BRAIMSEC_TAINT_RULES", TAINT_RULES)
    monkeypatch.setattr(scan_engine, "BRAIMSEC_GHA_RULES", "")
    monkeypatch.setattr(scan_engine, "BRAIMSEC_INJECT_RULES", "")
    monkeypatch.setattr(scan_engine, "BRAIMSEC_DOCKERFILE_RULES", "")
    monkeypatch.setattr(scan_engine, "BRAIMSEC_TERRAFORM_RULES", "")
    monkeypatch.delenv("BRAIMSEC_FULL_RULES", raising=False)
    findings = scan_engine.run_semgrep(str(tmp_path), base_configs=[])
    rule_ids = {f["rule_id"] for f in findings}
    assert any("braimsec.taint.ssrf-requests" in r for r in rule_ids), \
        f"scoped scan lost the taint finding; got: {sorted(rule_ids)}"
