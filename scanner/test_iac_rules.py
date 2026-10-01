"""Custom IaC rule-pack tests
(scanner/rules/braimsec-dockerfile.yaml + braimsec-terraform.yaml).

- Rule-pack hygiene: 13 rules, braimsec.dockerfile.* / braimsec.terraform.*
  ids (no binary needed)
- Behavior: paired vuln/safe snippets — every rule fires on its true
  positive and stays silent on clean code (needs semgrep; skipped when
  the binary is absent). This is the FP-discipline gate: a rule that
  fires on a SAFE sample fails the suite.
- Engine wiring: run_semgrep passes both packs via --config; empty
  BRAIMSEC_DOCKERFILE_RULES / BRAIMSEC_TERRAFORM_RULES disables them
  (no binary needed — _run is stubbed)

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

DOCKERFILE_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "rules", "braimsec-dockerfile.yaml")
TERRAFORM_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "rules", "braimsec-terraform.yaml")


def _semgrep():
    for cand in (os.environ.get("SEMGREP_BIN"),
                 shutil.which("semgrep"),
                 os.path.expanduser("~/workspace/venvs/sgvenv/bin/semgrep")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


SG = _semgrep()
needs_sg = pytest.mark.skipif(SG is None, reason="semgrep binary not found")


def _run_rules(configs, files):
    """Run the given pack(s) on {name: source} -> [(rule, file, line)]."""
    d = tempfile.mkdtemp(prefix="iac-test-")
    for name, src in files.items():
        with open(os.path.join(d, name), "w") as f:
            f.write(src)
    out = os.path.join(d, "out.json")
    cmd = [SG, "--json", "-o", out]
    for c in configs:
        cmd += ["--config", c]
    cmd.append(d)
    subprocess.run(cmd, capture_output=True, timeout=300)
    with open(out) as f:
        data = json.load(f)
    res = []
    for r in data.get("results", []):
        rid = r["check_id"]
        i = rid.find("braimsec.")
        if i != -1:
            res.append((rid[i:], os.path.basename(r["path"]),
                        r["start"]["line"]))
    return res


def _run_dockerfile(files):
    return _run_rules([DOCKERFILE_RULES], files)


def _run_terraform(files):
    return _run_rules([TERRAFORM_RULES], files)


# ---------------------------------------------------------------------------
# pack hygiene (no binary)
# ---------------------------------------------------------------------------

EXPECTED_DOCKERFILE_IDS = [
    "braimsec.dockerfile.add-remote-url",
    "braimsec.dockerfile.apt-no-cleanup",
    "braimsec.dockerfile.curl-pipe-shell",
    "braimsec.dockerfile.explicit-root-user",
    "braimsec.dockerfile.exposed-sensitive-port",
    "braimsec.dockerfile.mutable-base-tag",
    "braimsec.dockerfile.secrets-in-env",
]

EXPECTED_TERRAFORM_IDS = [
    "braimsec.terraform.ebs-no-encryption",
    "braimsec.terraform.rds-no-backup",
    "braimsec.terraform.rds-no-encryption",
    "braimsec.terraform.s3-public-acl",
    "braimsec.terraform.sg-inline-open-to-world",
    "braimsec.terraform.sg-rule-open-to-world",
]


def _load(path):
    with open(path) as f:
        return yaml.safe_load(f)


def test_packs_have_expected_rules():
    df = _load(DOCKERFILE_RULES)["rules"]
    tf = _load(TERRAFORM_RULES)["rules"]
    assert len(df) == 7
    assert len(tf) == 6
    assert sorted(r["id"] for r in df) == EXPECTED_DOCKERFILE_IDS
    assert sorted(r["id"] for r in tf) == EXPECTED_TERRAFORM_IDS


def test_packs_use_correct_languages():
    for r in _load(DOCKERFILE_RULES)["rules"]:
        assert r["languages"] == ["dockerfile"], r["id"]
    for r in _load(TERRAFORM_RULES)["rules"]:
        assert r["languages"] == ["terraform"], r["id"]


def test_packs_have_severity_and_metadata():
    for path in (DOCKERFILE_RULES, TERRAFORM_RULES):
        for r in _load(path)["rules"]:
            assert r["severity"] in ("ERROR", "WARNING"), r["id"]
            assert r["metadata"]["category"] == "security", r["id"]
            assert r["metadata"]["cwe"].startswith("CWE-"), r["id"]


# ---------------------------------------------------------------------------
# behavior: paired vuln / safe snippets (needs binary)
# ---------------------------------------------------------------------------

VULN_DOCKERFILE = {
    "Dockerfile": (
        "FROM ubuntu:latest\n"
        "ENV DB_PASSWORD=s3cr3t\n"
        "ARG API_KEY=abc123\n"
        "RUN apt-get update && apt-get install -y curl\n"
        "RUN curl -fsSL https://example.com/install.sh | sh\n"
        "ADD https://example.com/tool.tar.gz /opt/\n"
        "EXPOSE 22 8080\n"
        "USER root\n"
    ),
    # untagged base (no :tag at all) — also mutable
    "untagged.Dockerfile": "FROM ubuntu\nRUN echo hi\n",
}

SAFE_DOCKERFILE = {
    # pinned tag, cleaned apt, COPY not ADD, non-root user, digest pin
    "Dockerfile": (
        "FROM ubuntu:22.04 AS base\n"
        "ENV APP_ENV=production\n"
        "ENV PORT=8080\n"
        "ARG VERSION=1.2.3\n"
        "RUN apt-get update && apt-get install -y curl "
        "&& rm -rf /var/lib/apt/lists/*\n"
        "RUN curl -fsSL -o /tmp/tool.tar.gz https://example.com/tool.tar.gz\n"
        "COPY app/ /app/\n"
        "ADD app.tar.gz /srv/\n"
        "EXPOSE 8080\n"
        "USER appuser\n"
        "FROM alpine@sha256:abc123def456 AS final\n"
        "COPY --from=base /app /app\n"
    ),
    # word-boundary traps for the secrets rule: TURKEY / MONKEY / TOKENIZER
    # must NOT fire (bare "key"/"token" deliberately excluded)
    "Dockerfile.words": (
        "FROM ubuntu:22.04\n"
        "ENV TURKEY_SIZE=large\n"
        "ENV MONKEY_BUSINESS=no\n"
        "ENV TOKENIZER=v1\n"
        "USER 1000\n"
    ),
}

VULN_TERRAFORM = {
    "main.tf": (
        'resource "aws_security_group" "web" {\n'
        '  ingress {\n'
        '    from_port   = 22\n'
        '    to_port     = 22\n'
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '  ingress {\n'
        '    from_port   = 0\n'
        '    to_port     = 0\n'
        '    protocol    = "-1"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n'
        'resource "aws_security_group_rule" "db" {\n'
        '  type        = "ingress"\n'
        '  from_port   = 3306\n'
        '  to_port     = 3306\n'
        '  protocol    = "tcp"\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n'
        '}\n'
        'resource "aws_s3_bucket" "data" {\n'
        '  acl = "public-read"\n'
        '}\n'
        'resource "aws_db_instance" "db" {\n'
        '  storage_encrypted       = false\n'
        '  backup_retention_period = 0\n'
        '}\n'
        'resource "aws_ebs_volume" "vol" {\n'
        '  encrypted = false\n'
        '}\n'
    ),
}

SAFE_TERRAFORM = {
    "main.tf": (
        '# 22 open only to a private range + 443 open to the world:\n'
        '# neither is "sensitive port to the world" — must stay silent.\n'
        'resource "aws_security_group" "web" {\n'
        '  ingress {\n'
        '    from_port   = 22\n'
        '    to_port     = 22\n'
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["192.168.1.0/24"]\n'
        '  }\n'
        '  ingress {\n'
        '    from_port   = 443\n'
        '    to_port     = 443\n'
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n'
        '# egress to the world is not ingress — must stay silent.\n'
        'resource "aws_security_group_rule" "out" {\n'
        '  type        = "egress"\n'
        '  from_port   = 0\n'
        '  to_port     = 0\n'
        '  protocol    = "-1"\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n'
        '}\n'
        'resource "aws_s3_bucket" "data" {\n'
        '  acl = "private"\n'
        '}\n'
        'resource "aws_s3_bucket_server_side_encryption_configuration" "e" {\n'
        '  bucket = "data"\n'
        '}\n'
        'resource "aws_db_instance" "db" {\n'
        '  storage_encrypted       = true\n'
        '  backup_retention_period = 7\n'
        '}\n'
        'resource "aws_ebs_volume" "vol" {\n'
        '  encrypted = true\n'
        '}\n'
    ),
}


@needs_sg
def test_dockerfile_vuln_snippets_fire():
    got = {(r, f) for r, f, _ in _run_dockerfile(VULN_DOCKERFILE)}
    for rid in EXPECTED_DOCKERFILE_IDS:
        assert any(r == rid for r, f in got), rid
    # both :latest and untagged bases fire the mutable-tag rule
    assert ("braimsec.dockerfile.mutable-base-tag", "Dockerfile") in got
    assert ("braimsec.dockerfile.mutable-base-tag",
            "untagged.Dockerfile") in got


@needs_sg
def test_dockerfile_safe_snippets_silent():
    # FP-discipline gate: clean Dockerfiles must produce zero findings.
    assert _run_dockerfile(SAFE_DOCKERFILE) == []


@needs_sg
def test_terraform_vuln_snippets_fire():
    got = {(r, f) for r, f, _ in _run_terraform(VULN_TERRAFORM)}
    for rid in EXPECTED_TERRAFORM_IDS:
        assert any(r == rid for r, f in got), rid


@needs_sg
def test_terraform_safe_snippets_silent():
    # FP-discipline gate: clean Terraform must produce zero findings —
    # notably the mixed SG (22/private + 443/world) and the egress rule.
    assert _run_terraform(SAFE_TERRAFORM) == []


# ---------------------------------------------------------------------------
# engine wiring (no binary — _run stubbed)
# ---------------------------------------------------------------------------

def test_scan_engine_passes_iac_configs(monkeypatch):
    import scan_engine
    seen = {}

    def fake_run(cmd, timeout=600):
        seen["cmd"] = cmd

        class R:  # noqa: D106
            returncode = 0
        return R()

    monkeypatch.setattr(scan_engine, "_run", fake_run)
    monkeypatch.setattr(scan_engine, "BRAIMSEC_DOCKERFILE_RULES",
                        DOCKERFILE_RULES)
    monkeypatch.setattr(scan_engine, "BRAIMSEC_TERRAFORM_RULES",
                        TERRAFORM_RULES)
    with tempfile.TemporaryDirectory() as d:
        with monkeypatch.context() as m:
            m.setattr("json.load", lambda f: {"results": []})
            scan_engine.run_semgrep(d)
    cmd = seen["cmd"]
    assert "--config" in cmd
    assert DOCKERFILE_RULES in cmd
    assert TERRAFORM_RULES in cmd
    # auto + taint + gha + inject + dockerfile + terraform packs
    assert cmd.count("--config") == 6


def test_scan_engine_iac_packs_can_be_disabled(monkeypatch):
    import scan_engine
    seen = {}

    def fake_run(cmd, timeout=600):
        seen["cmd"] = cmd

        class R:  # noqa: D106
            returncode = 0
        return R()

    monkeypatch.setattr(scan_engine, "_run", fake_run)
    monkeypatch.setattr(scan_engine, "BRAIMSEC_DOCKERFILE_RULES", "")
    monkeypatch.setattr(scan_engine, "BRAIMSEC_TERRAFORM_RULES", "")
    with tempfile.TemporaryDirectory() as d:
        with monkeypatch.context() as m:
            m.setattr("json.load", lambda f: {"results": []})
            scan_engine.run_semgrep(d)
    # auto + taint + gha + inject packs
    assert seen["cmd"].count("--config") == 4
    assert DOCKERFILE_RULES not in seen["cmd"]
    assert TERRAFORM_RULES not in seen["cmd"]
