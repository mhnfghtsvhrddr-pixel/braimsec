"""AI-Powered Auto-Fix Suggestions — actionable patches for findings.

The AI review layer already produces a one-line ``ai_fix`` hint per finding.
This module goes one step further: for any single finding, on demand, it
asks the LLM for a MINIMAL code change, then mechanically verifies it:

1. ``extract_fix_context(path, line)`` — the enclosing function plus the
   file's top-level imports (what the model needs to write a correct patch).
2. ``generate_fix(client, finding, context)`` — one LLM call with a dedicated
   fix prompt. The model returns the exact ``original`` code block (copied
   character-for-character from the shown code) and its ``patched``
   replacement, an Arabic explanation, confidence, and manual caveats.
3. ``validate_fix(file_path, original, patched)`` — checks the ``original``
   block occurs verbatim in the file, builds the patched file, generates the
   authoritative unified diff with difflib (the model never hand-writes the
   diff), and — for Python — verifies the result still parses.

What the checks mean (honest labels, surfaced to the caller):
- ``applies``: the original block was found verbatim — the patch is anchored.
- ``syntax_ok``: the patched Python file parses. This is syntactic sanity
  ONLY: it does not prove the vulnerability is fixed or that behavior is
  preserved. For non-Python files the check is skipped (null).

Fixes are NEVER applied automatically. This is suggestions, not auto-patch.

``ai/`` must be on ``sys.path`` (same convention as ``api/tasks.py``).
"""

import ast
import difflib
import os

from ai_layer import _parse_json  # noqa: F401  (shared JSON extractor)


def extract_fix_context(path, line, max_import_chars=2000):
    """(function_source, imports_source) around ``line``.

    Fail-soft: returns ("", "") when the file is missing or unparseable.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            src = f.read()
        tree = ast.parse(src, filename=path)
    except (OSError, SyntaxError, ValueError):
        return "", ""
    target = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            if start <= line <= end:
                if target is None or start >= target.lineno:
                    target = node
    func_src = ""
    if target is not None:
        try:
            func_src = ast.get_source_segment(src, target) or ""
        except Exception:  # noqa: BLE001 - best effort
            func_src = ""
    imports = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            try:
                seg = ast.get_source_segment(src, node) or ""
            except Exception:  # noqa: BLE001 - best effort
                seg = ""
            if seg:
                imports.append(seg)
    imports_src = "\n".join(imports)[:max_import_chars]
    return func_src, imports_src


FIX_SYSTEM = (
    "You are a senior application security engineer writing a MINIMAL, SAFE code fix.\n"
    "You are given a CONFIRMED security finding and the surrounding code.\n"
    "Write the smallest change that eliminates the vulnerability while preserving "
    "behavior for legitimate inputs. Use standard safe patterns (parameterized queries, "
    "allowlists, path normalization + containment checks, shlex.quote, SafeLoader, "
    "version upgrades for vulnerable dependencies). Do NOT rewrite unrelated logic.\n"
    "The 'original' field MUST be copied character-for-character from the shown code — "
    "it is used to anchor the patch mechanically. If no code change applies "
    "(e.g. the fix is 'rotate the secret'), put the offending line(s) in 'original' "
    "and the remediation steps as code comments in 'patched'.\n"
    "Respond with JSON ONLY, no prose outside the object: "
    '{"explanation": "1-2 sentences in Arabic: what was wrong and what the fix does", '
    '"original": "exact code block to replace, copied from the shown code", '
    '"patched": "replacement code block", '
    '"confidence": 0.0-1.0, '
    '"caveats": "what the developer must verify manually (tests, edge cases), in Arabic, or empty string"}'
)


def _cap_context(src, limit):
    """Truncate LLM-bound code context with an explicit marker."""
    src = src or ""
    if len(src) > limit:
        return src[:limit].rstrip() + "\n…[context truncated]"
    return src


def generate_fix(client, finding, func_src="", imports_src="",
                 max_context_chars=6000):
    """One LLM call -> dict with explanation/original/patched/confidence/caveats.

    Only a capped excerpt of the customer code is sent (the enclosing
    function + imports); the whole file never leaves the server.
    """
    location = f"{finding.get('file')}:{finding.get('line')}"
    func_src = _cap_context(func_src, max_context_chars)
    imports_src = _cap_context(imports_src, max_context_chars)
    user = (
        f"Finding: [{finding.get('tool')}] {finding.get('rule_id')} "
        f"({finding.get('severity')}) at {location}\n"
        f"Message: {finding.get('message') or ''}\n"
        f"AI review verdict: {finding.get('ai_verdict') or 'n/a'} "
        f"(confidence {finding.get('ai_confidence')})\n"
        f"AI explanation: {finding.get('ai_explanation') or ''}\n\n"
        f"File imports:\n{imports_src or '(unavailable)'}\n\n"
        f"Relevant code:\n{func_src or '(unavailable)'}\n"
    )
    text = client.chat(FIX_SYSTEM, user, max_tokens=1200, temperature=0.2)
    data = _parse_json(text)
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    return {
        "fix_explanation": str(data.get("explanation", "")),
        "fix_original": str(data.get("original", "")),
        "fix_patched": str(data.get("patched", "")),
        "fix_confidence": conf,
        "fix_caveats": str(data.get("caveats", "")),
    }


def validate_fix(file_path, original, patched):
    """Mechanically anchor + diff + syntax-check a suggested fix.

    Returns {"applies": bool, "syntax_ok": bool|None, "diff": str}.
    ``syntax_ok`` is None for non-Python files (check skipped).
    """
    checks = {"applies": False, "syntax_ok": None, "diff": ""}
    if not original or not file_path:
        return checks
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            src = f.read()
    except OSError:
        return checks
    if original not in src:
        return checks
    checks["applies"] = True
    new_src = src.replace(original, patched, 1)
    name = os.path.basename(file_path)
    checks["diff"] = "".join(difflib.unified_diff(
        src.splitlines(keepends=True), new_src.splitlines(keepends=True),
        fromfile="a/" + name, tofile="b/" + name))
    if file_path.endswith(".py"):
        try:
            ast.parse(new_src)
            checks["syntax_ok"] = True
        except SyntaxError:
            checks["syntax_ok"] = False
    return checks
