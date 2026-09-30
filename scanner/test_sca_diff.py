"""Tests for scanner/sca_diff.py (diff-aware SCA) and its prbot wiring.

Unit (real git repo, mocked OSV):
- manifest filtering from the diff
- new/changed pin detection vs base (added, bumped, unchanged, new file)
- one aggregated finding per pin (multiple CVEs -> single comment)
- unchanged vulnerable pin -> silence, zero OSV queries for it
- safe upgrade -> no comment
- OSV/network failure -> fail-soft, bot never breaks
- no manifest in diff -> OSV never touched

End-to-end (real git repo + real semgrep, mocked OSV):
- new vulnerable dep -> exactly 1 inline comment on the manifest line
- --no-sca disables it
"""
import os
import subprocess
import sys

import pytest

os.environ.setdefault("SEMGREP_BIN",
                      os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep"))
os.environ.setdefault("GITLEAKS_BIN",
                      os.path.expanduser("~/workspace/bin/gitleaks"))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sca
import sca_diff
import prbot
from sca_diff import changed_manifests, new_pins, run_sca_on_diff

SG_OK = os.path.isfile(os.environ["SEMGREP_BIN"])

VULN_CRIT = {
    "id": "GHSA-req-crit",
    "aliases": ["CVE-2023-1234"],
    "summary": "Requests critical test vuln",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{
        "package": {"name": "requests", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "2.28"}, {"fixed": "2.31.0"}]}]}],
}

VULN_MED = {
    "id": "GHSA-req-med",
    "aliases": [],
    "summary": "Requests moderate test vuln",
    "database_specific": {"severity": "MODERATE"},
    "affected": [{
        "package": {"name": "requests", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "2.2"}, {"fixed": "2.32.0"}]}]}],
}


def _git(repo, *args):
    subprocess.run(["git", "-C", repo, *args], check=True,
                   capture_output=True, timeout=60)


def _make_repo(tmp_path, base_files, head_files):
    repo = str(tmp_path / "repo")
    os.makedirs(repo, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")

    def write_all(files):
        for name, content in files.items():
            p = os.path.join(repo, name)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(content)

    write_all(base_files)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    write_all(head_files)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "head")
    return repo


def _added(repo):
    return prbot.added_lines(prbot.git_diff(repo, "HEAD~1", "HEAD"))


def _canned_batch(url, payload, timeout):
    assert url.endswith("/v1/querybatch")
    results = []
    for q in payload["queries"]:
        name, ver = q["package"]["name"], q["version"]
        if name == "requests" and ver == "2.28.0":
            results.append({"vulns": [{"id": "GHSA-req-crit",
                                       "modified": "2024-01-01T00:00:00Z"},
                                      {"id": "GHSA-req-med",
                                       "modified": "2024-01-01T00:00:00Z"}]})
        else:
            results.append({})
    return {"results": results}


def _canned_details(ids, deadline, max_workers=10):
    return {"GHSA-req-crit": VULN_CRIT, "GHSA-req-med": VULN_MED}


@pytest.fixture()
def mock_osv(monkeypatch):
    monkeypatch.setattr(sca, "_post_json", _canned_batch)
    monkeypatch.setattr(sca, "fetch_vuln_details", _canned_details)


# ---------------------------------------------------------------------------
# Manifest filtering + pin delta
# ---------------------------------------------------------------------------

def test_changed_manifests_filter():
    added = {"app.py": {1}, "requirements.txt": {2},
             "backend/package-lock.json": {7}, "README.md": {3}}
    assert changed_manifests(added) == ["backend/package-lock.json",
                                        "requirements.txt"]


def test_changed_manifests_none():
    assert changed_manifests({"app.py": {1}}) == []


def test_new_pins_added_changed_unchanged(tmp_path):
    repo = _make_repo(
        tmp_path,
        {"requirements.txt": "django==3.2.0\nflask==2.0.0\n"},
        {"requirements.txt":
         "django==3.2.13\nflask==2.0.0\nrequests==2.28.0\n"})
    pins = new_pins(repo, "HEAD~1", "requirements.txt")
    got = {(p.name, p.version, p.line) for p in pins}
    # django bumped (line 1), requests added (line 3); flask untouched
    assert got == {("django", "3.2.13", 1), ("requests", "2.28.0", 3)}


def test_new_pins_new_manifest(tmp_path):
    repo = _make_repo(tmp_path, {"app.py": "x = 1\n"},
                      {"app.py": "x = 1\n",
                       "requirements.txt": "django==3.2.0\n"})
    pins = new_pins(repo, "HEAD~1", "requirements.txt")
    assert [(p.name, p.version) for p in pins] == [("django", "3.2.0")]


def test_new_pins_downgrade_counts(tmp_path):
    # a downgrade to a vulnerable version is still a NEW pin to check
    repo = _make_repo(tmp_path,
                      {"requirements.txt": "django==3.2.25\n"},
                      {"requirements.txt": "django==3.2.0\n"})
    pins = new_pins(repo, "HEAD~1", "requirements.txt")
    assert [(p.name, p.version) for p in pins] == [("django", "3.2.0")]


# ---------------------------------------------------------------------------
# run_sca_on_diff
# ---------------------------------------------------------------------------

def test_new_vulnerable_pin_one_aggregated_finding(tmp_path, mock_osv):
    repo = _make_repo(tmp_path,
                      {"requirements.txt": "django==3.2.0\n"},
                      {"requirements.txt":
                       "django==3.2.0\nrequests==2.28.0\n"})
    findings = run_sca_on_diff(repo, "HEAD~1", _added(repo))
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "osv"
    assert os.path.basename(f["file"]) == "requirements.txt"
    assert os.path.isabs(f["file"]) and f["line"] == 2
    assert f["severity"] == "error"          # worst of CRITICAL/MODERATE
    assert "GHSA-req-crit" in f["message"]
    assert "GHSA-req-med" in f["message"]    # both CVEs in ONE comment
    assert "CVE-2023-1234" in f["message"]
    assert "2.31.0" in f["message"]          # branch-matched fixed version
    assert "requests 2.28.0" in f["message"]


def test_unchanged_vuln_pin_silent_and_unqueried(tmp_path, monkeypatch):
    # django 3.2.0 is "vulnerable" per the canned batch, but the PR did
    # not touch it -> no finding AND never sent to OSV.
    repo = _make_repo(tmp_path,
                      {"requirements.txt": "django==3.2.0\n"},
                      {"requirements.txt": "django==3.2.0\n",
                       "app.py": "x = 1\n"})
    queried = []

    def recording_batch(url, payload, timeout):
        queried.extend((q["package"]["name"], q["version"])
                       for q in payload["queries"])
        return _canned_batch(url, payload, timeout)

    monkeypatch.setattr(sca, "_post_json", recording_batch)
    monkeypatch.setattr(sca, "fetch_vuln_details", _canned_details)
    assert run_sca_on_diff(repo, "HEAD~1", _added(repo)) == []
    assert queried == []  # nothing new -> zero OSV queries


def test_safe_upgrade_no_comment(tmp_path, mock_osv):
    # the new pin (3.2.13) has no canned vulns -> silence
    repo = _make_repo(tmp_path,
                      {"requirements.txt": "django==3.2.0\n"},
                      {"requirements.txt": "django==3.2.13\n"})
    assert run_sca_on_diff(repo, "HEAD~1", _added(repo)) == []


def test_osv_failure_fail_soft(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path,
                      {"requirements.txt": "django==3.2.0\n"},
                      {"requirements.txt":
                       "django==3.2.0\nrequests==2.28.0\n"})

    def boom(url, payload, timeout):
        raise ConnectionError("net down")

    monkeypatch.setattr(sca, "_post_json", boom)
    assert run_sca_on_diff(repo, "HEAD~1", _added(repo)) == []


def test_offline_never_touches_network(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path,
                      {"requirements.txt": "django==3.2.0\n"},
                      {"requirements.txt":
                       "django==3.2.0\nrequests==2.28.0\n"})
    monkeypatch.setattr(sca, "SCA_OFFLINE", True)

    def must_not_run(*a, **k):
        raise AssertionError("network must not be touched when offline")

    monkeypatch.setattr(sca, "_post_json", must_not_run)
    assert run_sca_on_diff(repo, "HEAD~1", _added(repo)) == []


def test_no_manifest_no_sca_calls(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path, {"app.py": "x = 1\n"},
                      {"app.py": "x = 2\n"})

    def must_not_run(*a, **k):
        raise AssertionError("OSV must not be queried without manifests")

    monkeypatch.setattr(sca, "query_osv", must_not_run)
    assert run_sca_on_diff(repo, "HEAD~1", _added(repo)) == []


def test_cargo_lock_version_line_anchors_comment(tmp_path, monkeypatch):
    base = ('[[package]]\nname = "serde"\nversion = "1.0.188"\n')
    head = ('[[package]]\nname = "serde"\nversion = "1.0.130"\n')

    def batch(url, payload, timeout):
        assert payload["queries"][0]["package"]["name"] == "serde"
        return {"results": [{"vulns": [{"id": "GHSA-serde",
                                        "modified": "2024-01-01T00:00:00Z"}]}]}

    vuln = dict(VULN_CRIT, id="GHSA-serde",
                affected=[{"package": {"name": "serde",
                                       "ecosystem": "crates.io"},
                           "ranges": [{"type": "ECOSYSTEM", "events": [
                               {"introduced": "1.0"},
                               {"fixed": "1.0.188"}]}]}])
    monkeypatch.setattr(sca, "_post_json", batch)
    monkeypatch.setattr(sca, "fetch_vuln_details",
                        lambda ids, deadline, max_workers=10:
                        {"GHSA-serde": vuln})
    repo = _make_repo(tmp_path, {"Cargo.lock": base}, {"Cargo.lock": head})
    added = _added(repo)
    # the version line (3) is the added line, not the [[package]] header
    assert added["Cargo.lock"] == {3}
    findings = run_sca_on_diff(repo, "HEAD~1", added)
    assert len(findings) == 1
    assert findings[0]["line"] == 3


# ---------------------------------------------------------------------------
# prbot wiring end-to-end
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SG_OK, reason="semgrep not installed")
def test_run_bot_sca_comment_e2e(tmp_path, mock_osv):
    repo = _make_repo(tmp_path,
                      {"requirements.txt": "django==3.2.0\n",
                       "app.py": "x = 1\n"},
                      {"requirements.txt":
                       "django==3.2.0\nrequests==2.28.0\n",
                       "app.py": "x = 1\n"})
    res = prbot.run_bot(repo, "HEAD~1", "HEAD", ai=False, sca=True)
    assert res["stats"]["sca_findings"] == 1
    assert res["stats"]["comments"] == 1, res["stats"]
    c = res["comments"][0]
    assert c["path"] == "requirements.txt" and c["line"] == 2
    assert "GHSA-req-crit" in c["body"]
    assert "CVE-2023-1234" in c["body"]
    assert "OSV" in c["body"]  # deterministic explanation, not AI text


@pytest.mark.skipif(not SG_OK, reason="semgrep not installed")
def test_run_bot_no_sca_flag_disables(tmp_path, mock_osv, monkeypatch):
    repo = _make_repo(tmp_path,
                      {"requirements.txt": "django==3.2.0\n"},
                      {"requirements.txt":
                       "django==3.2.0\nrequests==2.28.0\n"})

    def must_not_run(*a, **k):
        raise AssertionError("SCA must not run with sca=False")

    monkeypatch.setattr(sca, "query_osv", must_not_run)
    res = prbot.run_bot(repo, "HEAD~1", "HEAD", ai=False, sca=False)
    assert res["stats"]["sca_findings"] == 0
    assert res["comments"] == []
