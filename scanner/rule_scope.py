"""Language-scoped semgrep rule selection.

Production scans load thousands of vendored rules into every sandbox run,
and rule-loading dominates scan latency on small hosts (~8 min/scan on
1 vCPU). This module detects which languages are present in the scan
target and narrows the semgrep ``--config`` list to the rule files that
can actually match:

- vendored-rules directories (the docker sandbox image freezes a snapshot
  of semgrep-rules at /opt/rules with per-language subdirs) -> select
  only the subdirs for detected languages, plus the always-on
  ``generic``/``secrets`` packs;
- BraimSec's own custom packs -> each pack declares the languages its
  rules target; packs for absent languages are skipped;
- registry configs (``auto``) -> passed through untouched: the registry
  lookup already scopes to the project's languages, and there is no local
  directory to narrow.

Fail-closed guarantees (coverage is never silently narrowed to zero):
- ``BRAIMSEC_FULL_RULES=1`` forces the full rule set (escape hatch);
- ``BRAIMSEC_RULE_SCOPING=0`` disables scoping entirely;
- if language detection finds nothing recognizable, the full set is used
  and the fallback is logged;
- a config directory that does not follow the per-language vendored
  layout is kept whole.

The selected rule subset is always logged, so a scan's coverage is
auditable from the worker log.
"""
import logging
import os

log = logging.getLogger(__name__)

FULL_RULES_ENV = "BRAIMSEC_FULL_RULES"
SCOPING_ENV = "BRAIMSEC_RULE_SCOPING"

# Subdirs of a vendored rules snapshot that are language-agnostic and must
# always be loaded (generic rules + the secrets pack, which is the
# semgrep-side equivalent of secret coverage; gitleaks runs separately).
ALWAYS_ON_SUBDIRS = ("generic", "secrets")

# Extension -> semgrep language name(s). Language names match the
# per-language subdirs of the vendored semgrep-rules snapshot
# (deploy/docker/scan-runner.Dockerfile sparse-checkout set).
_EXT_TO_LANGUAGES = {
    ".py": {"python"}, ".pyi": {"python"},
    ".js": {"javascript"}, ".jsx": {"javascript"},
    ".mjs": {"javascript"}, ".cjs": {"javascript"},
    ".ts": {"typescript"}, ".tsx": {"typescript"},
    ".mts": {"typescript"}, ".cts": {"typescript"},
    ".go": {"go"},
    ".java": {"java"},
    ".rb": {"ruby"}, ".erb": {"ruby"},
    ".php": {"php"},
    ".cs": {"csharp"},
    ".kt": {"kotlin"}, ".kts": {"kotlin"},
    ".swift": {"swift"},
    ".scala": {"scala"}, ".sc": {"scala"},
    ".rs": {"rust"},
    ".c": {"c"}, ".h": {"c", "cpp"},
    ".cpp": {"cpp"}, ".cc": {"cpp"}, ".cxx": {"cpp"},
    ".hpp": {"cpp"}, ".hh": {"cpp"}, ".hxx": {"cpp"},
    ".sh": {"bash"},
    ".tf": {"terraform"}, ".tfvars": {"terraform"},
    ".yml": {"yaml"}, ".yaml": {"yaml"},
    ".json": {"json"},
}


def _languages_for_path(path: str) -> set:
    """Semgrep language names plausibly present in one file path."""
    base = os.path.basename(path).lower()
    # Semgrep's dockerfile language only targets files named Dockerfile
    # and *.Dockerfile (verified 2026-10-01).
    if base == "dockerfile" or base.startswith("dockerfile."):
        return {"dockerfile"}
    _root, ext = os.path.splitext(base)
    return set(_EXT_TO_LANGUAGES.get(ext, ()))


def detect_languages(target_dir: str, scope=None) -> set:
    """Detect semgrep language names present in the scan target.

    scope: optional iterable of file paths (incremental scans) — detect
    from those instead of walking the whole target directory.
    Returns a (possibly empty) set; empty means "nothing recognizable".
    """
    langs = set()
    if scope is not None:
        for p in scope:
            langs.update(_languages_for_path(p))
        return langs
    if os.path.isfile(target_dir):
        return _languages_for_path(target_dir)
    if not os.path.isdir(target_dir):
        return set()
    for _root, _dirs, files in os.walk(target_dir):
        for f in files:
            langs.update(_languages_for_path(f))
    return langs


def scoping_active() -> bool:
    """False when the operator forced the full rule set or disabled scoping."""
    if os.environ.get(FULL_RULES_ENV) == "1":
        return False
    return os.environ.get(SCOPING_ENV, "1") != "0"


def _vendored_subdirs(cfg: str, languages: set) -> list:
    """Narrow a vendored-rules directory to per-language subdirs.

    Returns [] when cfg is not a directory, or not a per-language
    vendored layout (recognized by the always-on ``generic``/``secrets``
    marker subdirs) — the caller then keeps the directory whole
    (fail closed).
    """
    if not os.path.isdir(cfg):
        return []  # registry name ("auto") or single file: not narrowable
    try:
        entries = set(os.listdir(cfg))
    except OSError:
        return []
    if not (entries & set(ALWAYS_ON_SUBDIRS)):
        return []  # unknown layout: never silently narrow
    picked = []
    for lang in sorted(languages):
        d = os.path.join(cfg, lang)
        if d not in picked and os.path.isdir(d):
            picked.append(d)
    for always in ALWAYS_ON_SUBDIRS:
        d = os.path.join(cfg, always)
        if d not in picked and os.path.isdir(d):
            picked.append(d)
    return picked


def scoped_base_configs(base_configs, languages: set | None) -> list:
    """Narrow base configs to the detected languages.

    languages=None (or empty) -> return the configs unchanged (fail closed
    toward coverage). Registry names pass through; vendored directories
    are replaced by their per-language subdirs (+ always-on packs).
    """
    base = list(base_configs)
    if not languages:
        return base
    out = []
    for cfg in base:
        sub = _vendored_subdirs(cfg, languages)
        out.extend(sub if sub else [cfg])
    return out


def select_rule_configs(base_configs, pack_specs, target_dir, scope=None):
    """Select the semgrep ``--config`` list for a scan.

    base_configs: registry names / rule files / vendored rule dirs.
    pack_specs: iterable of (name, path, languages) for BraimSec's custom
    packs; a pack is kept when any of its languages was detected.
    Returns (base_configs, [(pack_name, pack_path)]).

    Never narrows to zero rules: the full set is used (and logged) when
    scoping is bypassed/disabled or detection finds nothing recognizable.
    """
    live_packs = [(n, p, langs) for n, p, langs in pack_specs
                  if p and os.path.isfile(p)]
    if not scoping_active():
        if os.environ.get(FULL_RULES_ENV) == "1":
            log.info("rule scoping bypassed via %s=1: full rule set "
                     "(%d base configs, %d packs)",
                     FULL_RULES_ENV, len(base_configs), len(live_packs))
        return list(base_configs), [(n, p) for n, p, _l in live_packs]
    languages = detect_languages(target_dir, scope)
    if not languages:
        log.warning("rule scoping: no recognizable languages in %s; "
                    "using full rule set", target_dir)
        return list(base_configs), [(n, p) for n, p, _l in live_packs]
    base = scoped_base_configs(base_configs, languages)
    packs = [(n, p) for n, p, langs in live_packs if langs & languages]
    log.info("rule scoping: target=%s languages=%s base=%s packs=%s",
             target_dir, sorted(languages),
             [os.path.basename(c) for c in base],
             [n for n, _p in packs])
    return base, packs
