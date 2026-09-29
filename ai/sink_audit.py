"""High-Risk Sink Auditing — proactive AI second pass over dangerous sinks.

Why this exists
--------------
Static engines (Semgrep rule packs) only fire where a rule exists. Proven
gap (2026-09-26 holdout): SSRF and unrestricted file upload have NO rules
in the default packs, so those sinks were invisible. This module hunts the
sinks directly instead of waiting for a rule to fire:

1. ``discover_sinks(target_dir)`` — AST scan of every ``.py`` file for calls
   to a curated list of high-risk sinks (``requests.get``, ``os.system``,
   ``open``, ...), with basic import-alias resolution
   (``import subprocess as sp`` / ``from os import system``).
2. Taint pre-filter — a cheap intra-procedural heuristic: a sink whose
   arguments are pure constants is skipped WITHOUT spending AI quota.
   Anything that may carry user input becomes an audit candidate.
3. ``analyze_sink(client, site, snippet)`` — one LLM call per candidate with
   a dedicated sink-audit prompt (not the finding-review prompt: here there
   is no scanner finding, we are hunting).

Cost control
------------
- candidates per scan are capped (``SINK_AUDIT_MAX_PER_SCAN``, default 25)
- every LLM call consumes one ``ai_review`` quota unit — the same pool as
  finding reviews, so free plans (quota 0) get none
- only ``vulnerable`` verdicts at confidence >= ``SINK_AUDIT_MIN_CONFIDENCE``
  (default 0.7) become findings — precision-first
- ``SINK_AUDIT_OFF=1`` disables the whole pass

``ai/`` must be on ``sys.path`` (same convention as ``api/tasks.py``).
"""

import ast
import os

from ai_layer import _parse_json  # noqa: F401  (shared JSON extractor)

# --- Sink inventory -------------------------------------------------------
# dotted call name -> (category, default severity, short help for the prompt)
# v1 is Python-only; the benchmark corpus and the known gaps are Python.
SINKS = {
    # SSRF — outbound requests an attacker URL can steer
    "requests.get": ("ssrf", "error", "outbound HTTP request"),
    "requests.post": ("ssrf", "error", "outbound HTTP request"),
    "requests.put": ("ssrf", "error", "outbound HTTP request"),
    "requests.delete": ("ssrf", "error", "outbound HTTP request"),
    "requests.patch": ("ssrf", "error", "outbound HTTP request"),
    "requests.head": ("ssrf", "error", "outbound HTTP request"),
    "requests.options": ("ssrf", "error", "outbound HTTP request"),
    "requests.request": ("ssrf", "error", "outbound HTTP request"),
    "urllib.request.urlopen": ("ssrf", "error", "outbound HTTP request"),
    # Command injection
    "os.system": ("command-injection", "error", "shell command execution"),
    "os.popen": ("command-injection", "error", "shell command execution"),
    "subprocess.run": ("command-injection", "error", "subprocess execution"),
    "subprocess.call": ("command-injection", "error", "subprocess execution"),
    "subprocess.Popen": ("command-injection", "error", "subprocess execution"),
    "subprocess.check_output": ("command-injection", "error", "subprocess execution"),
    "subprocess.check_call": ("command-injection", "error", "subprocess execution"),
    # Code execution
    "eval": ("code-execution", "error", "dynamic code evaluation"),
    "exec": ("code-execution", "error", "dynamic code evaluation"),
    # Deserialization
    "pickle.loads": ("deserialization", "error", "unsafe deserialization"),
    "pickle.load": ("deserialization", "error", "unsafe deserialization"),
    "marshal.loads": ("deserialization", "error", "unsafe deserialization"),
    "marshal.load": ("deserialization", "error", "unsafe deserialization"),
    "yaml.load": ("deserialization", "error",
                 "unsafe deserialization unless Loader=SafeLoader"),
    "shelve.open": ("deserialization", "error", "unsafe deserialization"),
    # Path traversal / file access (any mode — the AI judges read vs write)
    "open": ("path-traversal", "warning",
             "file open — attacker-controlled path = arbitrary file access"),
}

CATEGORY_HELP = {
    "ssrf": "server-side request forgery: the server fetches a URL the attacker may control",
    "command-injection": "OS command injection: attacker input may reach a shell",
    "code-execution": "arbitrary code execution via dynamic evaluation",
    "deserialization": "insecure deserialization of attacker-controlled bytes",
    "path-traversal": "path traversal: attacker-controlled paths may escape the intended directory",
}

SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules",
             ".tox", "dist", "build", "eggs"}

# Attribute roots that carry remote-user input (Flask/Django-style).
SOURCE_ATTRS = {"args", "form", "data", "json", "values", "files", "GET",
                "POST", "body", "params", "query_params", "headers"}


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def max_per_scan():
    return _env_int("SINK_AUDIT_MAX_PER_SCAN", 25)


def min_confidence():
    try:
        return float(os.environ.get("SINK_AUDIT_MIN_CONFIDENCE", 0.7))
    except (TypeError, ValueError):
        return 0.7


def enabled():
    return os.environ.get("SINK_AUDIT_OFF", "") != "1"


# --- AST helpers ----------------------------------------------------------

def _collect_aliases(tree):
    """Map local names to dotted paths: import X as Y / from M import N."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                key = a.asname or a.name.split(".")[0]
                val = a.name if a.asname else a.name.split(".")[0]
                aliases[key] = val
        elif isinstance(node, ast.ImportFrom):
            if not node.module:  # relative import — skip
                continue
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _dotted(func, aliases):
    """Dotted name of a Call's func, with aliases resolved. None if exotic."""
    parts = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    parts.reverse()
    if parts[0] in aliases:
        parts[0] = aliases[parts[0]]
    return ".".join(parts)


def _attr_chain(node):
    """(root_name, [attrs...]) for an Attribute chain; root None if exotic."""
    attrs = []
    while isinstance(node, ast.Attribute):
        attrs.append(node.attr)
        node = node.value
    return (node.id if isinstance(node, ast.Name) else None), attrs


def _is_request_source(node):
    """True for request.<source-attr>... (Flask/Django-style user input)."""
    target = node.func if isinstance(node, ast.Call) else node
    if not isinstance(target, ast.Attribute):
        return False
    root, attrs = _attr_chain(target)
    return root == "request" and bool(set(attrs) & SOURCE_ATTRS)


def _is_environ(node):
    """True for os.environ[...] / os.getenv(...) — deployer-controlled."""
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name) and target.id == "getenv":
        return True
    if isinstance(target, ast.Attribute):
        root, attrs = _attr_chain(target)
        return root == "os" and "environ" in attrs
    return False


def _is_sys_argv(node):
    if isinstance(node, ast.Attribute):
        root, attrs = _attr_chain(node)
        return root == "sys" and attrs == ["argv"]
    return False


def _combine(states):
    if "tainted" in states:
        return "tainted"
    if "unknown" in states:
        return "unknown"
    return "clean"


def _classify(node, params):
    """Tri-state taint of an expression: tainted | unknown | clean."""
    if isinstance(node, ast.Constant):
        return "clean"
    if isinstance(node, ast.Name):
        return "tainted" if node.id in params else "unknown"
    if isinstance(node, ast.JoinedStr):  # f-string
        vals = [v.value for v in node.values
                if isinstance(v, ast.FormattedValue)]
        return _combine([_classify(v, params) for v in vals]) if vals else "clean"
    if isinstance(node, ast.BinOp):
        return _combine([_classify(node.left, params),
                         _classify(node.right, params)])
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            return "tainted"
        if _is_request_source(node):
            return "tainted"
        if _is_environ(node):
            return "unknown"
        kids = [_classify(a, params) for a in node.args]
        kids += [_classify(k.value, params) for k in node.keywords]
        return _combine(kids) if kids else "unknown"
    if isinstance(node, ast.Attribute):
        if _is_request_source(node):
            return "tainted"
        if _is_environ(node):
            return "unknown"
        return _classify(node.value, params)
    if isinstance(node, ast.Subscript):
        if _is_sys_argv(node.value):
            return "tainted"
        if _is_environ(node.value):
            return "unknown"
        return _combine([_classify(node.value, params),
                         _classify(node.slice, params)])
    kids = [_classify(c, params) for c in ast.iter_child_nodes(node)]
    return _combine(kids) if kids else "unknown"


def _enclosing_func(tree, target):
    """Nearest enclosing FunctionDef/AsyncFunctionDef, or None (module)."""
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    node, seen = target, set()
    while node in parents and id(node) not in seen:
        seen.add(id(node))
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


def classify_site(call_node, func_node):
    """Taint verdict for one sink call: tainted | unknown | clean.

    Intra-procedural, one assignment hop:
    ``url = request.args.get("u"); requests.get(url)`` resolves ``url``.
    """
    params, assigns = set(), {}
    if func_node is not None:
        a = func_node.args
        params = {x.arg for x in list(a.args) + list(a.kwonlyargs)}
        if a.vararg:
            params.add(a.vararg.arg)
        if a.kwarg:
            params.add(a.kwarg.arg)
        for node in ast.walk(func_node):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)):
                assigns[node.targets[0].id] = node.value
            elif (isinstance(node, ast.AnnAssign)
                    and isinstance(node.target, ast.Name) and node.value):
                assigns[node.target.id] = node.value
    arg_nodes = list(call_node.args) + [k.value for k in call_node.keywords]
    if not arg_nodes:
        return "clean"  # a sink with no arguments has no data flow into it
    results = []
    for arg in arg_nodes:
        node = arg
        if isinstance(node, ast.Name) and node.id in assigns:
            node = assigns[node.id]  # one hop
        results.append(_classify(node, params))
    return _combine(results)


def discover_sinks(target_dir):
    """Find high-risk sink call sites under target_dir.

    Returns a list of site dicts: file (abs), line, col, sink, category,
    severity, function, taint. Fail-soft: unreadable/unparseable files are
    skipped, never fatal.
    """
    sites = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs
                   if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    tree = ast.parse(f.read(), filename=path)
            except (OSError, SyntaxError, ValueError):
                continue
            aliases = _collect_aliases(tree)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                dotted = _dotted(node.func, aliases)
                if dotted not in SINKS:
                    continue
                category, severity, _help = SINKS[dotted]
                func_node = _enclosing_func(tree, node)
                sites.append({
                    "file": path,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "sink": dotted,
                    "category": category,
                    "severity": severity,
                    "function": (func_node.name if func_node
                                 else "<module>"),
                    "taint": classify_site(node, func_node),
                })
    sites.sort(key=lambda s: (s["file"], s["line"]))
    return sites


def audit_candidates(sites):
    """Sites worth one AI call each: tainted or unknown, capped per scan."""
    return [s for s in sites if s["taint"] != "clean"][:max_per_scan()]


# --- LLM audit ------------------------------------------------------------

SINK_AUDIT_SYSTEM = (
    "You are a senior application security engineer doing PROACTIVE SINK AUDITING.\n"
    "A static scan found a call to a HIGH-RISK SINK below. No scanner rule fired here — "
    "you are the safety net. Decide, from the code shown, whether this call is exploitable.\n"
    "1. SINK: what dangerous operation does this call perform?\n"
    "2. SOURCE: trace the data flowing into the sink's arguments IN THE SHOWN CODE. "
    "Attacker-controlled means: remote user input (request data, uploads, URL/query params), "
    "CLI args of a network-facing tool, or values derived from them. "
    "Developer constants, deployer-written config, and test-only code are NOT attacker-controlled. "
    "The 'taint pre-analysis' line is a cheap heuristic — VERIFY it yourself, do not trust it blindly.\n"
    "3. SANITIZATION: is there effective validation (allowlist, parameterized API, "
    "path normalization + containment check)? String formatting or 'looks safe' is not sanitization.\n"
    "4. VERDICT:\n"
    '   - "vulnerable": attacker-controlled data reaches the sink without effective sanitization.\n'
    '   - "safe": arguments are constants, properly sanitized, or provably not attacker-controlled.\n'
    '   - "needs_review": cannot be determined from the shown context alone.\n'
    "Respond with JSON ONLY, no prose outside the object: "
    '{"verdict": "vulnerable|safe|needs_review", "confidence": 0.0-1.0, '
    '"taint_source": "where the attacker data comes from, or empty string", '
    '"explanation": "one or two sentences, in Arabic, citing the source and the sink", '
    '"fix": "concrete minimal fix, or empty string"}'
)

_VERDICT_MAP = {
    "vulnerable": "true_positive", "true_positive": "true_positive",
    "safe": "false_positive", "false_positive": "false_positive",
}


def analyze_sink(client, site, snippet=""):
    """Audit one sink site. Returns dict with ai_* fields (finding-review vocabulary)."""
    user = (
        f"Sink call: {site['sink']} "
        f"(category: {site['category']} — {CATEGORY_HELP[site['category']]})\n"
        f"Location: {os.path.basename(site['file'])}:{site['line']} "
        f"(in {site['function']}())\n"
        f"Taint pre-analysis: {site['taint']} (heuristic — verify it yourself)\n\n"
        f"Code:\n{snippet}\n"
    )
    text = client.chat(SINK_AUDIT_SYSTEM, user, max_tokens=900, temperature=0.2)
    data = _parse_json(text)
    verdict = str(data.get("verdict", "")).strip().lower()
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    return {
        "ai_verdict": _VERDICT_MAP.get(verdict, "needs_review"),
        "ai_confidence": conf,
        "ai_explanation": str(data.get("explanation", "")),
        "ai_fix": str(data.get("fix", "")),
        "taint_source": str(data.get("taint_source", "")),
    }


def should_store(res):
    """Precision-first gate: only confident 'vulnerable' verdicts become findings."""
    return (res["ai_verdict"] == "true_positive"
            and res["ai_confidence"] >= min_confidence())
