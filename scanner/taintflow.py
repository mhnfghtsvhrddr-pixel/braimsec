"""Taint flow & exploitation path — Proposal Part 3 (v1: linear trace).

Turns "a warning on an isolated line" into a structured, step-by-step
data-flow trace: source -> propagation* -> sink, so a reviewer can see
*how* untrusted input reaches the dangerous call.

Pipeline (per the proposal's review amendments):
  1. ``--dataflow-traces`` is tried first, on the finding's own file, but
     Semgrep OSS 1.178.0 exposes traces ONLY in the human-readable text
     output (the flag's own help says: "only affects text and SARIF
     output", and SARIF carries no trace locations). The text is parsed
     defensively; when it yields nothing we fall through to:
  2. AST backward slicing — the primary deterministic engine. Intra-file,
     intra-procedural, Python-only (v1).

Every step carries ``origin``:
  - ``"semgrep-trace"`` — from Semgrep's own taint engine
  - ``"ast-slice"``     — from our backward slicer
  - ``"ai-inferred"``   — RESERVED for the AI layer. This engine never
    emits it; any consumer (PDF export, dashboard) MUST render
    ai-inferred steps as inference, not fact.

Sanitization verdict is tri-state, per the proposal:
  - ``unsanitized`` — no sanitizer on the path
  - ``sanitized``   — a known-good sanitizer wraps the tainted value
  - ``uncertain``   — an unverified transform sits on the path. Per the
    proposal this is NOT a flaw until the AI layer supplies a concrete
    bypass payload (which would arrive as an ``ai-inferred`` step).

Honest limits (v1):
  - intra-file only: cross-file propagation is NOT followed
  - the sanitizer list is deliberately conservative; anything else is
    ``uncertain``, never silently trusted
  - ``syntax`` of snippets is best-effort; the verdict is a review aid,
    not a proof of exploitability
"""

import ast
import os
import re
import subprocess

ORIGIN_SEMGREP = "semgrep-trace"
ORIGIN_AST = "ast-slice"
ORIGIN_AI = "ai-inferred"  # reserved — never emitted by this module

ENGINE_VERSION = "taintflow-v1"
MAX_STEPS = 25

SEMGREP_BIN = os.environ.get("SEMGREP_BIN", "semgrep")
TAINT_RULES = os.environ.get(
    "BRAIMSEC_TAINT_RULES",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "rules", "braimsec-taint.yaml"),
)

# ---------------------------------------------------------------------------
# Knowledge: sources and sanitizers (Python, v1 — deliberately conservative)
# ---------------------------------------------------------------------------

# Dotted-name suffixes that mark a value as attacker-controlled.
_SOURCE_SUFFIXES = (
    "request.args.get", "request.form.get", "request.values.get",
    "request.args", "request.form", "request.values",
    "request.data", "request.json", "request.get_json",
    "request.GET.get", "request.POST.get", "request.GET", "request.POST",
    "input", "sys.argv", "sys.stdin.read", "sys.stdin.readline",
    "os.environ.get", "os.getenv", "os.environ",
)

# Dotted-name suffixes / bare names we TRUST as sanitizers. Anything else
# applied to tainted data -> "uncertain", never silently trusted.
_SANITIZER_SUFFIXES = (
    "html.escape", "markupsafe.escape", "flask.escape",
    "shlex.quote", "urllib.parse.quote", "bleach.clean",
)
_SANITIZER_BARE = {"secure_filename", "basename"}

# ---------------------------------------------------------------------------
# Small AST helpers
# ---------------------------------------------------------------------------


def _dotted(node):
    """Dotted name of a Name/Attribute/Call-func node, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _endswith_any(dotted, suffixes):
    return bool(dotted) and any(
        dotted == s or dotted.endswith("." + s) for s in suffixes)


def _is_source_value(node):
    """True if an assignment RHS is (or wraps) a known taint source."""
    if isinstance(node, ast.Call):
        return _endswith_any(_dotted(node.func), _SOURCE_SUFFIXES)
    if isinstance(node, ast.Subscript):
        # request.args["u"], os.environ["K"], sys.argv[1]
        return _endswith_any(_dotted(node.value), _SOURCE_SUFFIXES)
    return False


def _call_info(node):
    """(dotted_name, is_method_call) for a Call node, else (None, False)."""
    if not isinstance(node, ast.Call):
        return None, False
    func = node.func
    dotted = _dotted(func)
    is_method = (isinstance(func, ast.Attribute)
                 and isinstance(func.value, ast.Name))
    return dotted, is_method


def _is_sanitizer_call(node):
    dotted, _ = _call_info(node)
    if not dotted:
        return False
    if _endswith_any(dotted, _SANITIZER_SUFFIXES):
        return True
    return "." not in dotted and dotted in _SANITIZER_BARE


def _is_unverified_transform(node):
    """A call on the path that is neither source nor known-good sanitizer.

    Method calls on the tainted value itself (``x.strip()``) count as plain
    propagation — a sanitizer is almost always a module-level or bare
    function, and flagging every ``.strip()`` as uncertain would drown the
    verdict in noise. Documented heuristic, v1.
    """
    if not isinstance(node, ast.Call):
        return None
    if _is_source_value(node) or _is_sanitizer_call(node):
        return None
    dotted, is_method = _call_info(node)
    if not dotted or is_method:
        return None
    return dotted


def _used_names(node):
    return {n.id for n in ast.walk(node)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _iter_scope_stmts(tree, line):
    """Statements of the innermost function containing ``line`` (else the
    module), in source order, without descending into nested defs."""
    scope = tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            if start <= line <= end:
                if scope is tree or start >= scope.lineno:
                    scope = node

    stmts = []

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                stmts.append(child)
            if not isinstance(child,
                              (ast.FunctionDef, ast.AsyncFunctionDef,
                               ast.ClassDef, ast.Lambda)):
                visit(child)

    visit(scope)
    stmts.sort(key=lambda s: s.lineno)
    return stmts


def _defines_name(stmt, name):
    """Assignment targets binding ``name`` (Assign/AnnAssign/AugAssign/
    NamedExpr/for/with). Returns the value node or None."""
    if isinstance(stmt, ast.Assign):
        for t in stmt.targets:
            if isinstance(t, ast.Name) and t.id == name:
                return stmt.value
            if isinstance(t, ast.Tuple) and any(
                    isinstance(e, ast.Name) and e.id == name for e in t.elts):
                return stmt.value
    elif isinstance(stmt, ast.AnnAssign):
        if isinstance(stmt.target, ast.Name) and stmt.target.id == name:
            return stmt.value
    elif isinstance(stmt, ast.AugAssign):
        if isinstance(stmt.target, ast.Name) and stmt.target.id == name:
            return stmt.value
    elif isinstance(stmt, ast.For):
        if isinstance(stmt.target, ast.Name) and stmt.target.id == name:
            return stmt.iter
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            if (isinstance(item.optional_vars, ast.Name)
                    and item.optional_vars.id == name):
                return item.context_expr
    elif isinstance(stmt, ast.NamedExpr):
        if isinstance(stmt.target, ast.Name) and stmt.target.id == name:
            return stmt.value
    return None


def _snippet(src, node):
    try:
        seg = ast.get_source_segment(src, node)
    except Exception:  # noqa: BLE001 - best effort
        seg = None
    if seg:
        return " ".join(seg.split())
    lines = src.splitlines()
    start = max(node.lineno - 1, 0)
    end = min(getattr(node, "end_lineno", node.lineno) or node.lineno,
              len(lines))
    return " ".join(l.strip() for l in lines[start:end])[:300]


# ---------------------------------------------------------------------------
# Engine 1: semgrep --dataflow-traces (text output, parsed defensively)
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_RULE_RE = re.compile(r"^\s*❯❯❱\s+(.+?)\s*$")
_LOCLINE_RE = re.compile(r"^\s*(\d+)┆\s?(.*?)\s*$")
_SECTION_RE = re.compile(
    r"^\s*(Taint comes from|Taint flows through these intermediate "
    r"variables|This is how taint reaches the sink):\s*$")


def parse_dataflow_text(text):
    """Parse ``semgrep --dataflow-traces`` text output.

    Returns a list of blocks: {rule, sink_line, sink_snippet, sources: [(line,
    snippet)], intermediates: [(line, snippet)]}. Best-effort: anything
    unrecognized is skipped, never misattributed.
    """
    text = _ANSI_RE.sub("", text)
    blocks, cur, section = [], None, None
    for raw in text.splitlines():
        m = _RULE_RE.match(raw)
        if m:
            cur = {"rule": m.group(1), "sink_line": None, "sink_snippet": "",
                   "sources": [], "intermediates": []}
            blocks.append(cur)
            section = None
            continue
        if cur is None:
            continue
        ms = _SECTION_RE.match(raw)
        if ms:
            section = ms.group(1)
            continue
        ml = _LOCLINE_RE.match(raw)
        if ml:
            line, snip = int(ml.group(1)), ml.group(2)
            if section is None and cur["sink_line"] is None:
                cur["sink_line"], cur["sink_snippet"] = line, snip
            elif section == "Taint comes from":
                cur["sources"].append((line, snip))
            elif section == "Taint flows through these intermediate variables":
                cur["intermediates"].append((line, snip))
            # "This is how taint reaches the sink" repeats the sink line —
            # deliberately ignored (dedupe).
    return [b for b in blocks if b["sink_line"] is not None]


def _rules_match(block_rule, rule_id):
    if not block_rule or not rule_id:
        return False
    return (block_rule == rule_id or block_rule.endswith(rule_id)
            or rule_id.endswith(block_rule))


def _semgrep_trace_steps(abs_path, rule_id, line, timeout=120):
    """Best-effort: run semgrep --dataflow-traces scoped to one file."""
    if not os.path.isfile(SEMGREP_BIN) and not _which(SEMGREP_BIN):
        return None
    if "braimsec.taint." in (rule_id or "") and os.path.isfile(TAINT_RULES):
        cfg = TAINT_RULES
    else:
        cfg = "auto"
    cmd = [SEMGREP_BIN, "--config", cfg, "--dataflow-traces",
           "--quiet", abs_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout,
                              env={**os.environ, "NO_COLOR": "1"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    blocks = parse_dataflow_text(proc.stdout)
    blk = next((b for b in blocks
                if _rules_match(b["rule"], rule_id)
                and b["sink_line"] == line), None)
    if blk is None:
        blk = next((b for b in blocks if b["sink_line"] == line), None)
    if blk is None:
        return None
    steps = []
    seen = set()
    for i, (ln, snip) in enumerate(blk["sources"]):
        if (ln, snip) not in seen:
            seen.add((ln, snip))
            steps.append(_mk_step(i + 1, "source", abs_path, ln, snip,
                                 ORIGIN_SEMGREP))
    for ln, snip in sorted(set(blk["intermediates"])):
        if (ln, snip) not in seen:
            seen.add((ln, snip))
            steps.append(_mk_step(len(steps) + 1, "propagation", abs_path,
                                 ln, snip, ORIGIN_SEMGREP))
    steps.append(_mk_step(len(steps) + 1, "sink", abs_path, blk["sink_line"],
                         blk["sink_snippet"], ORIGIN_SEMGREP))
    return steps or None


def _which(prog):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, prog)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


# ---------------------------------------------------------------------------
# Engine 2: AST backward slicing (primary deterministic engine)
# ---------------------------------------------------------------------------

def ast_backward_slice(abs_path, line, max_steps=MAX_STEPS):
    """Walk backwards from the statement at ``line`` following assignments.

    Intra-file, intra-procedural, Python-only. Returns steps ordered
    source -> ... -> sink with origin ``ast-slice``.
    """
    try:
        with open(abs_path, encoding="utf-8", errors="replace") as f:
            src = f.read()
        tree = ast.parse(src, filename=abs_path)
    except (OSError, SyntaxError, ValueError):
        return []
    stmts = _iter_scope_stmts(tree, line)
    if not stmts:
        return []
    sink_stmt = None
    for s in stmts:
        end = getattr(s, "end_lineno", None) or s.lineno
        if s.lineno <= line <= end:
            sink_stmt = s
    if sink_stmt is None:
        below = [s for s in stmts if s.lineno <= line]
        sink_stmt = below[-1] if below else stmts[0]

    rel = abs_path
    steps = [_mk_step(1, "sink", rel, sink_stmt.lineno,
                      _snippet(src, sink_stmt), ORIGIN_AST,
                      node=sink_stmt)]

    # Source calls used directly at the sink (no assignment in between).
    seen_src = set()
    for node in ast.walk(sink_stmt):
        if isinstance(node, ast.Call) and _is_source_value(node):
            dotted = _dotted(node.func) or "?"
            if dotted not in seen_src:
                seen_src.add(dotted)
                steps.append(_mk_step(0, "source", rel, node.lineno,
                                     _snippet(src, node), ORIGIN_AST,
                                     node=node))

    defined_here = set()
    for t in getattr(sink_stmt, "targets", []):
        defined_here.update(n.id for n in ast.walk(t)
                            if isinstance(n, ast.Name))
    worklist = [n for n in sorted(_used_names(sink_stmt))
                if n not in defined_here]
    visited = set()
    chain = []  # (name, stmt, value_node) newest-first
    while worklist and len(chain) + len(steps) < max_steps:
        name = worklist.pop(0)
        if name in visited:
            continue
        visited.add(name)
        cand, value = None, None
        for s in reversed(stmts):
            if s.lineno >= sink_stmt.lineno:
                continue
            v = _defines_name(s, name)
            if v is not None:
                cand, value = s, v
                break
        if cand is None:
            continue
        chain.append((name, cand, value))
        worklist.extend(sorted(_used_names(value) - visited))

    for name, stmt, value in reversed(chain):
        stype = "source" if _is_source_value(value) else "propagation"
        steps.append(_mk_step(0, stype, rel, stmt.lineno,
                              _snippet(src, stmt), ORIGIN_AST, node=value))

    # Order: sources first (by line), then propagations (by line), sink last.
    srcs = sorted([s for s in steps if s["type"] == "source"],
                  key=lambda s: s["line"])
    props = sorted([s for s in steps if s["type"] == "propagation"],
                   key=lambda s: s["line"])
    sinks = [s for s in steps if s["type"] == "sink"]
    ordered = srcs + props + sinks
    for i, s in enumerate(ordered, 1):
        s["step"] = i
        s.pop("_node", None)
    return ordered


def _mk_step(i, stype, path, line, snippet, origin, node=None):
    step = {"step": i, "type": stype, "file": path, "line": line,
            "snippet": snippet[:300], "origin": origin}
    if node is not None:
        step["_node"] = node  # internal only; stripped before output
    return step


# ---------------------------------------------------------------------------
# Sanitization verdict (tri-state)
# ---------------------------------------------------------------------------

_CALL_RE = re.compile(r"([A-Za-z_][\w.]*)\s*\(")


def _calls_in_snippet(snippet):
    """(sanitizers, unverified) call names found in a snippet string."""
    san, unv = [], []
    try:
        tree = ast.parse(snippet)
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        strs = []
    except SyntaxError:
        calls, strs = [], _CALL_RE.findall(snippet)
    for node in calls:
        dotted, is_method = _call_info(node)
        if not dotted:
            continue
        if _endswith_any(dotted, _SANITIZER_SUFFIXES) or (
                "." not in dotted and dotted in _SANITIZER_BARE):
            san.append(dotted)
        elif not is_method and not _endswith_any(dotted, _SOURCE_SUFFIXES):
            unv.append(dotted)
    for dotted in strs:
        if _endswith_any(dotted, _SANITIZER_SUFFIXES) or (
                "." not in dotted and dotted in _SANITIZER_BARE):
            if dotted not in san:
                san.append(dotted)
        elif "." in dotted and dotted.split(".")[0] not in (
                "request", "sys", "os"):
            if dotted not in unv:
                unv.append(dotted)
    return san, unv


def sanitize_verdict(steps):
    """Tri-state verdict over a step list.

    Returns (verdict, details). ``uncertain`` is NOT a flaw — per the
    proposal it needs a concrete bypass payload from the AI layer.
    """
    sanitizers, unverified = [], []
    for s in steps:
        if s["type"] == "sink":
            continue
        node = s.pop("_node", None) if "_node" in s else None
        if node is not None and isinstance(node, ast.AST):
            if _is_sanitizer_call(node):
                dotted, _ = _call_info(node)
                sanitizers.append(f"{dotted}@line {s['line']}")
                continue
            unv = _is_unverified_transform(node)
            if unv:
                unverified.append(f"{unv}@line {s['line']}")
                continue
        san, unv = _calls_in_snippet(s.get("snippet", ""))
        sanitizers.extend(f"{c}@line {s['line']}" for c in san
                          if f"{c}@line {s['line']}" not in sanitizers)
        unverified.extend(f"{c}@line {s['line']}" for c in unv
                          if f"{c}@line {s['line']}" not in unverified)
    if sanitizers:
        return "sanitized", {
            "sanitizers": sanitizers, "unverified_transforms": unverified}
    if unverified:
        return "uncertain", {
            "sanitizers": [],
            "unverified_transforms": unverified,
            "note": ("An unverified transform sits on the path. Per the "
                     "proposal this is not a flaw until the AI layer "
                     "supplies a concrete bypass payload.")},
    return "unsanitized", {"sanitizers": [], "unverified_transforms": []}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def extract_taint_path(finding, target_dir, semgrep_timeout=120):
    """Build the linear taint trace for one finding.

    ``finding``: dict with tool / rule_id / file / line (+ id).
    Returns the proposal §2 JSON schema, or {"available": False, ...}.
    """
    fid = finding.get("id")
    rel = (finding.get("file") or "").strip()
    line = finding.get("line") or 0
    base = os.path.realpath(target_dir or "")
    abs_path = os.path.realpath(os.path.join(base, rel)) if rel else ""
    if not base or not abs_path.startswith(base + os.sep):
        return {"available": False, "finding_id": fid,
                "reason": "file path escapes the scan directory"}
    if not os.path.isfile(abs_path):
        return {"available": False, "finding_id": fid,
                "reason": "source file not found (deleted after scan?)"}

    steps, origin = None, None
    if finding.get("tool") == "semgrep" and abs_path.endswith(".py"):
        steps = _semgrep_trace_steps(abs_path, finding.get("rule_id") or "",
                                     line, timeout=semgrep_timeout)
        if steps:
            origin = ORIGIN_SEMGREP
    if not steps:
        if not abs_path.endswith(".py"):
            return {"available": False, "finding_id": fid,
                    "reason": "AST slicing supports Python only (v1)"}
        steps = ast_backward_slice(abs_path, line)
        origin = ORIGIN_AST if steps else None
    if not steps:
        return {"available": False, "finding_id": fid,
                "reason": "could not reconstruct a taint path"}

    for s in steps:
        s["origin"] = origin
        s.pop("_node", None)
    verdict, details = sanitize_verdict(steps)
    details = dict(details)
    details["verdict"] = verdict
    return {
        "available": True,
        "finding_id": fid,
        "rule_id": finding.get("rule_id"),
        "file": rel,
        "line": line,
        "engine": ENGINE_VERSION,
        "trace_origin": origin,
        "taint_path": steps,
        "sanitization": details,
        "limits": [
            "intra-file analysis only — cross-file propagation is not "
            "followed (v1)",
            "the sanitizer list is deliberately conservative; unknown "
            "transforms yield 'uncertain', never silent trust",
            "no step in this trace is AI-generated: this engine never "
            "emits origin 'ai-inferred'",
        ],
    }
