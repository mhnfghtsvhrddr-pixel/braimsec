"""Diff-aware SCA for the PR Review Bot.

The full-scan ``sca.run_sca`` reports every vulnerable pin in the repo.
On a PR diff that would spam comments about historical vulnerabilities
the PR did not introduce. This module answers a narrower question:

    which dependency pins are NEW or version-CHANGED in ``base...head``,
    and which of those have known CVEs?

Only those pins are queried against OSV, and one aggregated finding is
produced per pin occurrence (all its CVE IDs in a single inline
comment). A finding is emitted only when its line is an *added* line in
the diff, so every comment can be positioned inline on the PR.

Design notes / honest limits:

- Base pins come from ``git show base:path``. For ``requirements.txt``
  ``-r``/``-c`` includes, the base parse runs in an empty temp dir, so
  included files do not resolve on the base side (best-effort). The
  added-line guard below makes a false "new pin" harmless: a pin whose
  line was not added by this diff can never comment.
- Findings pass the PR bot gates *deterministically* (like gitleaks):
  an exact (ecosystem, name, version) match in the OSV database is
  high-confidence by construction — no AI verdict needed.
- Fail-soft throughout: OSV/network failure, unparsable manifests, or
  ``SCA_OFFLINE=1`` yield zero findings, never a broken bot run.
- The working tree is assumed to be at ``head`` (same contract as
  ``prbot.run_bot``): head pins are parsed from the files on disk.
"""

import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sca  # noqa: E402

GIT_TIMEOUT = 60

_SEVERITY_RANK = {"note": 0, "warning": 1, "error": 2}


# ---------------------------------------------------------------------------
# Manifest delta: base...head
# ---------------------------------------------------------------------------

def changed_manifests(added):
    """Repo-relative paths in ``added`` that are dependency manifests."""
    return sorted(p for p in added
                  if os.path.basename(p) in sca.ECOSYSTEMS)


def _base_pins(repo, base, rel, parser):
    """Parse the manifest as it was at ``base``. [] if new/unreadable."""
    p = subprocess.run(["git", "-C", repo, "show", f"{base}:{rel}"],
                       capture_output=True, text=True, timeout=GIT_TIMEOUT)
    if p.returncode != 0:
        return []  # new file (or unreadable): every head pin is new
    with tempfile.TemporaryDirectory(prefix="braimsec-scabase-") as tmp:
        tmp_file = os.path.join(tmp, os.path.basename(rel) or "manifest")
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(p.stdout)
        try:
            # NOTE: -r/-c includes resolve against the temp dir here, so
            # base pins reachable only via includes are missed (best-effort;
            # the added-line guard in run_sca_on_diff keeps this harmless).
            return parser(tmp_file, rel)
        except Exception:  # noqa: BLE001 - corrupt manifest: treat as empty
            return []


def new_pins(repo, base, rel):
    """Head pins (Package, head file+line) that are new or version-changed.

    A pin is "new" when (ecosystem, name) is absent from the base manifest
    or its pinned version differs (upgrade AND downgrade both count: the
    CVE set of the new version is what matters).
    """
    basename = os.path.basename(rel)
    ecosystem = sca.ECOSYSTEMS[basename]
    parser = sca._PARSERS[ecosystem]
    abs_path = os.path.join(repo, rel)
    try:
        head_pkgs = parser(abs_path, rel)
    except Exception:  # noqa: BLE001 - corrupt manifest: no SCA for it
        return []
    base_pkgs = _base_pins(repo, base, rel, parser)
    base_ver = {(p.ecosystem, p.name): p.version for p in base_pkgs}
    return [p for p in head_pkgs
            if base_ver.get((p.ecosystem, p.name)) != p.version]


# ---------------------------------------------------------------------------
# Finding aggregation: one comment per pin, all its CVEs inside
# ---------------------------------------------------------------------------

def _pin_finding(package, vulns):
    """One aggregated finding for a vulnerable pin occurrence."""
    ordered = sorted(
        vulns,
        key=lambda v: _SEVERITY_RANK.get(sca._severity(v), 1),
        reverse=True)
    worst = sca._severity(ordered[0])
    ids = [v.get("id", "?") for v in ordered]
    cves = []
    for v in ordered:
        c = sca._cve_alias(v)
        if c and c not in cves:
            cves.append(c)
    fixes = []
    for v in ordered:
        fx = sca._fixed_version(v, package)
        if fx and fx not in fixes:
            fixes.append(fx)
    n = len(ordered)
    shown = ", ".join(ids[:6]) + ("…" if n > 6 else "")
    msg = (f"{package.name} {package.version} ({package.ecosystem}): "
           f"{n} known vulnerabilit{'y' if n == 1 else 'ies'} [{shown}].")
    if cves:
        msg += (" " + ", ".join(cves[:4])
                + ("…" if len(cves) > 4 else "") + ".")
    msg += f" Highest severity: {worst.upper()}."
    if fixes:
        msg += f" Fixed in: {', '.join(fixes[:3])}."
    else:
        msg += " Fix: upgrade to a patched release."
    return {
        "tool": "osv",
        "rule_id": ordered[0].get("id", "unknown"),
        "severity": worst,
        "message": msg,
        "file": package.file,
        "line": package.line,
        "col": 1,
        "sca_vuln_ids": ids,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_sca_on_diff(repo, base, added):
    """SCA findings for new/changed pins only. Never raises.

    ``added`` is prbot.added_lines(diff): {rel path: {added line nos}}.
    Every returned finding sits on an added line, so the bot can always
    position it inline. Returns [] when no manifest changed, when OSV is
    unreachable, or when SCA_OFFLINE=1.
    """
    if sca.SCA_OFFLINE:
        return []
    rels = changed_manifests(added)
    if not rels:
        return []
    occurrences = []
    for rel in rels:
        occurrences.extend(new_pins(repo, base, rel))
    # Guard: only pins on added lines can comment (positions the inline
    # comment; also neutralizes base-parse blind spots such as
    # unresolvable -r includes).
    occurrences = [p for p in occurrences
                   if p.line in added.get(p.file, ())]
    if not occurrences:
        return []
    # De-duplicate identical (ecosystem, name, version) pins for the OSV
    # query, but keep every occurrence for per-location comments.
    unique, seen = [], {}
    for p in occurrences:
        key = (p.ecosystem, sca._pep503_like(p.name), p.version)
        if key not in seen:
            seen[key] = p
            unique.append(p)
    deadline = time.monotonic() + sca.SCA_TIMEOUT
    vuln_ids_by_pkg = sca.query_osv(unique, deadline)
    all_ids = list(dict.fromkeys(
        vid for ids in vuln_ids_by_pkg.values() for vid in ids))
    details = sca.fetch_vuln_details(all_ids, deadline) if all_ids else {}
    vulns_by_key = {}
    for p in unique:
        key = (p.ecosystem, sca._pep503_like(p.name), p.version)
        vulns = [details[vid] for vid in vuln_ids_by_pkg.get(id(p), [])
                 if vid in details]
        if vulns:
            vulns_by_key[key] = vulns
    findings = []
    for p in occurrences:
        key = (p.ecosystem, sca._pep503_like(p.name), p.version)
        vulns = vulns_by_key.get(key)
        if vulns:
            f = _pin_finding(p, vulns)
            # prbot works with absolute paths (cf. run_semgrep findings);
            # _rel()/dedupe()/build_comment all assume it.
            f["file"] = os.path.join(repo, p.file)
            findings.append(f)
    return findings
