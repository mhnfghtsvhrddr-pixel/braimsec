"""Quick test of the AI layer (mock + graceful degradation)."""
from ai_layer import MockLLMClient, LLMClient, analyze_finding, review_findings

finding = {
    "tool": "semgrep",
    "rule_id": "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
    "severity": "error",
    "message": "Possible SQL injection",
    "file": "app.py",
    "line": 19,
}
snippet = 'query = "SELECT * FROM users WHERE x = \'%s\'" % username'

# 1. Mock client (simulates a real LLM response)
r = analyze_finding(MockLLMClient(), finding, snippet)
print("mock verdict:", r["ai_verdict"], "| conf:", r["ai_confidence"])
assert r["ai_verdict"] == "true_positive"
assert r["ai_fix"], "mock should return a fix"

# 2. Unconfigured client -> graceful skip (no crash)
r2 = analyze_finding(LLMClient(), finding)
print("unconfigured verdict:", r2["ai_verdict"])
assert r2["ai_verdict"] == "skipped"

# 3. Batch review over multiple findings
batch = review_findings(MockLLMClient(), [finding, finding])
print("batch:", len(batch), "| all reviewed:", all("ai_verdict" in b for b in batch))
assert len(batch) == 2

print("AI LAYER OK")
