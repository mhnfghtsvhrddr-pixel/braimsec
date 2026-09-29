#!/usr/bin/env python3
"""BraimSec incremental (diff) scan engine — prototype v1.

Avoids re-scanning an entire repository when only a few files changed:

  fingerprint_tree(root) -> {relpath: sha256}
  diff_fingerprints(old, new) -> added / modified / deleted
  plan_incremental(...)      -> scope files + whether SCA is needed
  merge_findings(...)        -> carried (unchanged-file) + fresh findings
  escape_rate(...)           -> honesty metric vs a full scan

Scope-expansion rule (mandatory per PROPOSAL §4.2): the scan scope is the
changed files PLUS one call-graph hop in both directions — files the changed
files import, and files importing the changed files. This closes the silent
hole where a tainted source moves in one file and the sink sits unchanged in
another. Python imports are resolved with ast; other languages expand to the
changed file itself (documented limitation).

Constraints (PROPOSAL §4):
- Works only with persistent git/checkout targets. Zip uploads are always
  full scans (their sources are deleted after the scan — zero retention).
- SCA runs only when a package manifest changed; a periodic full SCA
  (daily/weekly, scheduled outside this module) is still required to catch
  newly published CVEs on old packages.
- A periodic FULL scan is the ground truth: compare with escape_rate() to
  prove the incremental path misses nothing. Never mix partial-scan results
  into full-scan trend statistics.
- The claimed time/token saving is a HYPOTHESIS until measured on real PRs.
  Measured 2026-09-30: with the current engine setup, semgrep's fixed
  startup cost (~8s for rule loading) dominates — a 150-file full scan took
  9.0s vs 8.3s for a 1-file scoped scan. So at this scale the wall-time win
  is marginal; the REAL incremental savings are (1) AI-review quota: carried
  findings keep their verdicts and are never re-billed, and (2) SCA cost:
  skipped unless a manifest changed. Time savings appear only on much larger
  repos or slower engines — do not advertise otherwise.
"""
import ast
import hashlib
import os

SCANABLE_EXTS = (".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb",
                 ".java", ".php", ".cs")

MANIFEST_NAMES = {
    "requirements.txt", "package-lock.json", "package.json", "yarn.lock",
    "pnpm-lock.yaml", "go.mod", "go.sum", "Cargo.lock", "Gemfile.lock",
    "poetry.lock", "composer.lock",
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def fingerprint_tree(root):
    """Map relpath -> sha256 hex for every scannable file under root."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            # Manifests are fingerprinted too: a changed requirements.txt /
            # package-lock.json must trigger the conditional SCA run, even
            # though manifests are not SAST-scannable sources.
            if not name.endswith(SCANABLE_EXTS) and name not in MANIFEST_NAMES:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                with open(full, "rb") as f:
                    out[rel] = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                continue
    return out


def diff_fingerprints(old, new):
    """Return (added, modified, deleted) as sets of relpaths."""
    old, new = old or {}, new or {}
    added = set(new) - set(old)
    deleted = set(old) - set(new)
    modified = {p for p in set(old) & set(new) if old[p] != new[p]}
    return added, modified, deleted


def _module_name(relpath):
    """app/utils.py -> app.utils ; app/__init__.py -> app."""
    no_ext = relpath[: -len(".py")]
    parts = no_ext.split(os.sep)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _parse_imports(full_path):
    """Return (imported_top_levels, imported_modules) for a .py file.

    imported_modules: dotted names from `import a.b` / `from a.b import ...`.
    Fail-soft: unparseable files contribute nothing.
    """
    imported = set()
    try:
        with open(full_path, encoding="utf-8", errors="replace") as f:
            tree = ast.parse(f.read())
    except (OSError, SyntaxError):
        return imported
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module)
    return imported


def import_hops(root, changed):
    """One-hop call-graph expansion (both directions) for changed .py files.

    Returns a set of relpaths: files imported BY the changed files, plus
    files importing the changed modules. Non-Python files expand to
    themselves only.
    """
    changed = set(changed)
    py_changed = {c for c in changed if c.endswith(".py")}
    if not py_changed:
        return set(changed)

    # Index every .py file: module name -> relpath, and its imports.
    mod_to_rel = {}
    imports_of = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            mod_to_rel[_module_name(rel)] = rel
            imports_of[rel] = _parse_imports(full)

    changed_mods = {_module_name(c) for c in py_changed}
    expanded = set(changed)

    # Forward hop: modules imported by changed files.
    for c in py_changed:
        for mod in imports_of.get(c, ()):
            target = mod_to_rel.get(mod)
            if target:
                expanded.add(target)
            else:
                # submodule of a package: app.utils.x -> app.utils
                for i in range(mod.count("."), 0, -1):
                    parent = ".".join(mod.split(".")[:i])
                    target = mod_to_rel.get(parent)
                    if target:
                        expanded.add(target)
                        break

    # Reverse hop: files importing any changed module.
    for rel, imported in imports_of.items():
        if rel in expanded:
            continue
        for mod in imported:
            parts = mod.split(".")
            if any(".".join(parts[:i]) in changed_mods
                   for i in range(1, len(parts) + 1)):
                expanded.add(rel)
                break

    return expanded


def plan_incremental(old_fp, new_fp, root):
    """Decide what an incremental scan must do.

    Returns dict with: no_change, added, modified, deleted,
    scope_files (sorted relpaths to (re)scan), sca_needed.
    """
    added, modified, deleted = diff_fingerprints(old_fp, new_fp)
    changed = added | modified
    if not changed and not deleted:
        return {"no_change": True, "added": set(), "modified": set(),
                "deleted": set(), "scope_files": [], "sca_needed": False}
    scope = import_hops(root, changed)
    manifests = {os.path.basename(p) for p in changed}
    return {"no_change": False,
            "added": added, "modified": modified, "deleted": deleted,
            "scope_files": sorted(scope),
            "sca_needed": bool(manifests & MANIFEST_NAMES)}


def _key(f):
    return (f.get("tool"), f.get("rule_id"), f.get("file"),
            f.get("line"))


def merge_findings(old_findings, fresh_findings, invalidated):
    """Carry findings from unchanged files; drop stale; add fresh.

    invalidated: relpaths (added+modified+deleted) whose old findings are
    stale. old_findings / fresh_findings: dicts with tool/rule_id/file/line,
    where file is the relpath under the scan root.
    """
    invalidated = set(invalidated)
    carried = [f for f in old_findings if f.get("file") not in invalidated]
    return carried + list(fresh_findings)


def escape_rate(incremental_findings, full_findings):
    """Findings the incremental path missed vs the full-scan ground truth.

    Returns (escaped_count, full_count, escaped_keys). 0 escaped is the
    honesty proof a CISO asks for; measure it on the nightly full scan.
    """
    full_keys = {_key(f) for f in full_findings}
    incr_keys = {_key(f) for f in incremental_findings}
    escaped = full_keys - incr_keys
    return len(escaped), len(full_keys), sorted(escaped)
