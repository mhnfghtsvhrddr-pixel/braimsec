"""Semantic routing tests for ai/ai_layer.py.

No LLM needed: classify_finding is a pure function, and analyze_finding is
tested with a recording fake client that captures the chosen system prompt.
"""
import json
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_layer import (  # noqa: E402
    classify_finding,
    route_system,
    analyze_finding,
    SECRETS_SYSTEM,
    CONFIG_SYSTEM,
    DEPENDENCY_SYSTEM,
    FINDING_SYSTEM,
    FAMILY_SYSTEMS,
)


def f(tool, rule_id):
    return {"tool": tool, "rule_id": rule_id, "severity": "error",
            "message": "m", "file": "a.py", "line": 1}


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool,rule_id,expected", [
    ("gitleaks", "generic-api-key", "secret"),
    ("gitleaks", "jwt", "secret"),
    ("semgrep", "generic-api-key", "secret"),
    ("semgrep", "jwt-hardcode", "secret"),
    ("semgrep", "private-key-detected", "secret"),
    ("semgrep", "python.flask.security.debug.debug-enabled", "config"),
    ("semgrep", "python.django.security.csrf.csrf-disabled", "config"),
    ("semgrep", "app-run-param-config", "config"),
    ("semgrep", "braimsec.taint.ssrf-requests", "taint"),
    ("semgrep", "braimsec.taint.path-traversal-open", "taint"),
    ("semgrep", "python.sqlalchemy.security.sqlalchemy-execute-raw-query", "taint"),
    ("semgrep", "python.requests.best-practice.use-timeout", "taint"),
    ("osv", "GHSA-xxxx", "dependency"),
    ("sink-audit", "ssrf-sink", "sink"),
    ("semgrep", "something-entirely-unknown", "taint"),  # default family
])
def test_classify_finding(tool, rule_id, expected):
    assert classify_finding(f(tool, rule_id)) == expected


def test_csrf_not_misrouted_to_secrets():
    # csrf rule ids mention "token"; config must win over the secret keyword.
    assert classify_finding(
        f("semgrep", "python.django.security.csrf.csrf-token-missing")) == "config"


def test_route_system_returns_family_prompt():
    assert route_system(f("gitleaks", "x")) is SECRETS_SYSTEM
    assert route_system(f("semgrep", "debug-enabled")) is CONFIG_SYSTEM
    assert route_system(f("osv", "GHSA-1")) is DEPENDENCY_SYSTEM
    assert route_system(f("semgrep", "taint-rule")) is FINDING_SYSTEM
    assert set(FAMILY_SYSTEMS) == {"secret", "config", "taint",
                                   "dependency", "sink"}


# ---------------------------------------------------------------------------
# prompt content contracts
# ---------------------------------------------------------------------------

def test_secrets_prompt_has_mandatory_placeholder_gate():
    assert "PLACEHOLDER GATE" in SECRETS_SYSTEM
    assert "false_positive" in SECRETS_SYSTEM


def test_config_prompt_treats_unknown_context_as_needs_review():
    assert "needs_review" in CONFIG_SYSTEM
    assert "NOT safety" in CONFIG_SYSTEM or "not safety" in CONFIG_SYSTEM.lower()


@pytest.mark.parametrize("prompt", [SECRETS_SYSTEM, CONFIG_SYSTEM,
                                    DEPENDENCY_SYSTEM, FINDING_SYSTEM])
def test_every_prompt_demands_unified_json_schema(prompt):
    for key in ('"verdict"', '"confidence"', '"explanation"', '"fix"'):
        assert key in prompt, f"{key} missing from a family prompt"


def test_dependency_prompt_names_fixed_version():
    assert "fixed version" in DEPENDENCY_SYSTEM


# ---------------------------------------------------------------------------
# analyze_finding routes internally (recording fake client)
# ---------------------------------------------------------------------------

class RecordingClient:
    configured = True

    def __init__(self):
        self.calls = []

    def chat(self, system, user, max_tokens=900, temperature=0.2):
        self.calls.append((system, user))
        return json.dumps({"verdict": "true_positive", "confidence": 0.8,
                           "explanation": "x", "fix": "y"})


@pytest.mark.parametrize("tool,rule_id,expected_prompt", [
    ("gitleaks", "generic-api-key", SECRETS_SYSTEM),
    ("semgrep", "debug-enabled", CONFIG_SYSTEM),
    ("osv", "GHSA-1", DEPENDENCY_SYSTEM),
    ("semgrep", "braimsec.taint.ssrf-requests", FINDING_SYSTEM),
])
def test_analyze_finding_uses_routed_prompt(tool, rule_id, expected_prompt):
    client = RecordingClient()
    res = analyze_finding(client, f(tool, rule_id), "snippet")
    assert client.calls[0][0] is expected_prompt
    assert res["ai_verdict"] == "true_positive"
    assert res["ai_family"] == classify_finding(f(tool, rule_id))
