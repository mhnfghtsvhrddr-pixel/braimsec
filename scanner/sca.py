#!/usr/bin/env python3
"""
BraimSec SCA (prototype v0.1.0)
--------------------------------
Software Composition Analysis via the Google OSV database
(https://api.osv.dev). No local vulnerability database needed.

Discovers dependency manifests in the target directory, extracts pinned
package versions, and queries OSV in batches.

Supported manifests:
    requirements.txt   -> PyPI
    package-lock.json  -> npm
    go.mod             -> Go
    Cargo.lock         -> crates.io
    Gemfile.lock       -> RubyGems

Env overrides:
    OSV_API_URL   base URL (default https://api.osv.dev)
    OSV_TIMEOUT   per-request seconds (default 20)
    SCA_TIMEOUT   total phase budget seconds (default 180)
    SCA_OFFLINE   =1 -> skip network entirely (dev/CI without net)

Fail-soft by design: any network/API failure logs a warning and returns [].
A scan without SCA coverage is better than a failed scan. Only exact pins
(name==version) are queried -- ranges cannot be resolved to an installed
version, so they are skipped rather than guessed.
"""

import json
import os
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

OSV_API_URL = os.environ.get("OSV_API_URL", "https://api.osv.dev").rstrip("/")
OSV_TIMEOUT = float(os.environ.get("OSV_TIMEOUT", "20"))
SCA_TIMEOUT = float(os.environ.get("SCA_TIMEOUT", "180"))
SCA_OFFLINE = os.environ.get("SCA_OFFLINE", "") == "1"

BATCH_SIZE = 100
MAX_RETRIES = 3

# Directories never worth walking for manifests.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             ".tox", "vendor", "dist", "build", ".hg", ".svn"}

ECOSYSTEMS = {
    "requirements.txt": "PyPI",
    "package-lock.json": "npm",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
    "Gemfile.lock": "RubyGems",
}

_SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MODERATE": "warning",
    "MEDIUM": "warning",
    "LOW": "note",
}


class Package:
    __slots__ = ("name", "version", "ecosystem", "file", "line")

    def __init__(self, name, version, ecosystem, file, line):
        self.name = name
        self.version = version
        self.ecosystem = ecosystem
        self.file = file          # path relative to scan target
        self.line = line          # 1-based line in the manifest


# ---------------------------------------------------------------- discovery

def discover_manifests(target):
    """Walk target, return [(abs_path, ecosystem)] for known manifests."""
    found = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name, ecosystem in ECOSYSTEMS.items():
            if name in files:
                found.append((os.path.join(root, name), ecosystem))
    return sorted(found)


# ---------------------------------------------------------------- parsers

def _pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*"
    r"(===|==|~=|>=|<=|>|<|!=)?\s*([^\s;#]+)?"
)


def parse_requirements(path, rel, _depth=0):
    """Parse requirements.txt; follow -r/-c includes (depth-limited)."""
    packages = []
    if _depth > 5:
        return packages
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
    except OSError:
        return packages

    # join backslash continuations
    lines, buf, start = [], "", 0
    for i, raw in enumerate(raw_lines, 1):
        stripped = raw.rstrip("\n")
        if stripped.rstrip().endswith("\\"):
            if not buf:
                start = i
            buf += stripped.rstrip()[:-1]
            continue
        if buf:
            lines.append((start, buf + stripped))
            buf = ""
        else:
            lines.append((i, stripped))

    base = os.path.dirname(path)
    for lineno, line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            inc = line.split(None, 1)[1].strip().split()[0]
            inc_path = os.path.join(base, inc)
            # rel path of the included file, anchored at the scan target root
            packages.extend(parse_requirements(
                inc_path,
                os.path.join(os.path.dirname(rel), os.path.basename(inc_path)),
                _depth + 1))
            continue
        if line.startswith("-") or line.startswith("--"):
            continue  # other pip options / URLs: not queryable
        # strip environment markers
        line = line.split(";", 1)[0].strip()
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name, _extras, op, version = m.groups()
        if op in ("==", "===") and version:
            # drop trailing comma fragments: "==1.2.*" -> keep as-is
            # (OSV handles exact versions; wildcards simply won't match)
            packages.append(Package(_pep503(name), version.strip(),
                                    "PyPI", rel, lineno))
        # ranges (!=, >=, ~= ...) are skipped: no exact version to query
    return packages


_PKG_KEY = re.compile(r'^\s*"node_modules/(.+?)"\s*:\s*\{\s*$')
_PKG_VER = re.compile(r'^\s*"version"\s*:\s*"([^"]+)"')


def _npm_name(mod_path):
    """node_modules/a/node_modules/@s/n -> @s/n ; .../b -> b."""
    parts = mod_path.split("/node_modules/")
    last = parts[-1]
    segs = last.split("/")
    if segs[0].startswith("@") and len(segs) >= 2:
        return "/".join(segs[:2])
    return segs[0]


def parse_package_lock(path, rel):
    packages = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError:
        return packages
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return packages

    if isinstance(data.get("packages"), dict):
        # lockfileVersion 2/3: line-anchored scan for accurate locations
        current, current_line = None, 0
        for i, line in enumerate(raw.splitlines(), 1):
            m = _PKG_KEY.match(line)
            if m:
                current, current_line = m.group(1), i
                continue
            if current:
                mv = _PKG_VER.match(line)
                if mv:
                    packages.append(Package(
                        _npm_name(current), mv.group(1), "npm", rel, i))
                    current = None
        return packages

    # lockfileVersion 1: structural walk of "dependencies"
    def walk(deps):
        for name, info in (deps or {}).items():
            if isinstance(info, dict):
                ver = info.get("version")
                if ver:
                    packages.append(Package(name, str(ver), "npm", rel, 1))
                walk(info.get("dependencies"))
    walk(data.get("dependencies"))
    return packages


_GO_REQUIRE = re.compile(r"^\s*([^\s]+)\s+(v[^\s]+)")
_GO_SINGLE = re.compile(r"^\s*require\s+([^\s]+)\s+(v[^\s]+)")


def parse_go_mod(path, rel):
    packages = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return packages
    replaced = set()
    for line in lines:
        line = line.strip()
        if line.startswith("replace"):
            # replace example.com/mod => ../local  (or => other v1.2.3):
            # replaced modules aren't fetched from the registry -> skip
            m = re.match(r"replace\s+([^\s]+)\s*=>", line)
            if m:
                replaced.add(m.group(1))
    in_require = False
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        m = _GO_SINGLE.match(line) if not in_require else _GO_REQUIRE.match(line)
        if m and not line.startswith("//"):
            mod, ver = m.group(1), m.group(2)
            if mod not in replaced:
                packages.append(Package(mod, ver, "Go", rel, i))
    return packages


def parse_cargo_lock(path, rel):
    packages = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return packages
    name, version, start = None, None, 0
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if line == "[[package]]":
            if name and version:
                packages.append(Package(name, version, "crates.io", rel, start))
            name, version, start = None, None, i
        elif line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and name and not version:
            version = line.split("=", 1)[1].strip().strip('"')
    if name and version:
        packages.append(Package(name, version, "crates.io", rel, start))
    return packages


_GEM_SPEC = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)")


def parse_gemfile_lock(path, rel):
    packages = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return packages
    in_specs = False
    for i, raw in enumerate(lines, 1):
        if re.match(r"^  specs:$", raw.rstrip("\n")):
            in_specs = True
            continue
        if in_specs and re.match(r"^\S", raw):
            in_specs = False  # next top-level section
        if in_specs:
            m = _GEM_SPEC.match(raw.rstrip("\n"))
            if m:
                packages.append(Package(m.group(1), m.group(2),
                                        "RubyGems", rel, i))
    return packages


_PARSERS = {
    "PyPI": parse_requirements,
    "npm": parse_package_lock,
    "Go": parse_go_mod,
    "crates.io": parse_cargo_lock,
    "RubyGems": parse_gemfile_lock,
}


# ---------------------------------------------------------------- OSV client

def _http_json(url, payload, timeout):
    """GET (payload=None) or POST JSON with retries. Raises on failure."""
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"User-Agent": "BraimSec-SCA/0.1.0"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    last = None
    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001 - network is flaky; retry all
            last = e
            time.sleep(1.0 * (attempt + 1))
    raise last


def _post_json(url, payload, timeout):
    return _http_json(url, payload, timeout)


def query_osv(packages, deadline):
    """Batch-query OSV. Returns {id(pkg): [vuln_id, ...]}. Never raises.

    NOTE: /v1/querybatch returns trimmed entries (id + modified only).
    Full details are fetched separately via fetch_vuln_details().
    """
    results = {}
    for i in range(0, len(packages), BATCH_SIZE):
        if time.monotonic() > deadline:
            print("[sca] WARN: SCA time budget exhausted, "
                  f"skipping {len(packages) - i} packages", file=sys.stderr)
            break
        chunk = packages[i:i + BATCH_SIZE]
        payload = {"queries": [
            {"package": {"name": p.name, "ecosystem": p.ecosystem},
             "version": p.version} for p in chunk]}
        try:
            resp = _post_json(f"{OSV_API_URL}/v1/querybatch", payload,
                              OSV_TIMEOUT)
        except Exception as e:  # noqa: BLE001 - fail-soft by design
            print(f"[sca] WARN: OSV batch failed ({e}); "
                  "continuing without SCA for this chunk", file=sys.stderr)
            continue
        for pkg, entry in zip(chunk, resp.get("results", [])):
            ids = [v.get("id") for v in (entry or {}).get("vulns", [])
                   if v.get("id")]
            if ids:
                results[id(pkg)] = ids
    return results


def fetch_vuln_details(vuln_ids, deadline, max_workers=10):
    """Fetch full vuln records from /v1/vulns/{id} in parallel.

    Returns {vuln_id: full_vuln_dict}. Entries that fail to fetch are
    omitted (fail-soft); callers must skip them, not invent details.
    """
    out = {}

    def one(vid):
        try:
            return vid, _http_json(f"{OSV_API_URL}/v1/vulns/{vid}",
                                   None, OSV_TIMEOUT)
        except Exception as e:  # noqa: BLE001 - fail-soft by design
            print(f"[sca] WARN: could not fetch {vid}: {e}",
                  file=sys.stderr)
            return vid, None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {}
        for vid in vuln_ids:
            if time.monotonic() > deadline:
                print("[sca] WARN: SCA time budget exhausted during "
                      "detail fetch", file=sys.stderr)
                break
            futs[ex.submit(one, vid)] = vid
        remaining = max(1.0, deadline - time.monotonic())
        try:
            for fut in as_completed(futs, timeout=remaining):
                vid, detail = fut.result()
                if detail:
                    out[vid] = detail
        except TimeoutError:
            print("[sca] WARN: detail fetch timed out; "
                  "reporting with available details", file=sys.stderr)
    return out


# ---------------------------------------------------------------- normalize

def _fixed_version(vuln, package):
    """Best-effort 'fixed in' version for the queried package version."""
    best, best_len = None, -1
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != package.ecosystem:
            continue
        if _pep503_like(pkg.get("name", "")) != _pep503_like(package.name):
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            introduced, fixed = None, None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
            if fixed:
                # prefer the range whose introduced is the longest
                # prefix of our version (e.g. 3.2.x branch for 3.2.0)
                key = introduced or ""
                if package.version.startswith(key) and len(key) > best_len:
                    best, best_len = fixed, len(key)
    return best


def _pep503_like(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _severity(vuln):
    db = vuln.get("database_specific") or {}
    sev = str(db.get("severity", "")).upper()
    return _SEVERITY_MAP.get(sev, "warning")


def _cve_alias(vuln):
    for a in vuln.get("aliases", []) or []:
        if a.startswith("CVE-"):
            return a
    return None


def vuln_to_finding(vuln, package):
    vid = vuln.get("id", "unknown")
    summary = (vuln.get("summary") or "").strip()
    if not summary:
        details = (vuln.get("details") or "").strip()
        summary = details[:120] + ("…" if len(details) > 120 else "")
    if not summary:
        summary = "Known vulnerability"
    cve = _cve_alias(vuln)
    fixed = _fixed_version(vuln, package)
    fix_text = f"Fixed in: {fixed}" if fixed else "Fix: upgrade to a patched release"
    message = (f"{package.name} {package.version}: {summary} "
               f"[{vid}" + (f" / {cve}" if cve else "") + f"]. {fix_text}.")
    return {
        "tool": "osv",
        "rule_id": vid,
        "severity": _severity(vuln),
        "message": message,
        "file": package.file,
        "line": package.line,
        "col": 1,
    }


# ---------------------------------------------------------------- entry point

def run_sca(target):
    """Run SCA on target dir. Returns normalized findings (fail-soft)."""
    if SCA_OFFLINE:
        return []
    if not os.path.isdir(target):
        return []
    packages = []
    for abs_path, ecosystem in discover_manifests(target):
        rel = os.path.relpath(abs_path, target)
        parser = _PARSERS[ecosystem]
        try:
            packages.extend(parser(abs_path, rel))
        except Exception as e:  # noqa: BLE001 - one bad manifest must not kill SCA
            print(f"[sca] WARN: failed to parse {rel}: {e}", file=sys.stderr)
    # de-duplicate identical (ecosystem, name, version) pins
    seen, unique = set(), []
    for p in packages:
        key = (p.ecosystem, _pep503_like(p.name), p.version)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    if not unique:
        return []
    deadline = time.monotonic() + SCA_TIMEOUT
    vuln_ids_by_pkg = query_osv(unique, deadline)
    # unique vuln ids across all packages (same vuln often hits one
    # package, but dedup keeps the detail-fetch cheap)
    all_ids = list(dict.fromkeys(
        vid for ids in vuln_ids_by_pkg.values() for vid in ids))
    details = fetch_vuln_details(all_ids, deadline) if all_ids else {}
    findings, seen_vulns = [], set()
    for p in unique:
        for vid in vuln_ids_by_pkg.get(id(p), []):
            vuln = details.get(vid)
            if not vuln:
                continue  # detail fetch failed: skip, don't invent
            key = (p.ecosystem, _pep503_like(p.name), p.version, vid)
            if key in seen_vulns:
                continue
            seen_vulns.add(key)
            findings.append(vuln_to_finding(vuln, p))
    return findings


def main():
    if len(sys.argv) < 2:
        print("usage: sca.py <target-dir>", file=sys.stderr)
        sys.exit(2)
    findings = run_sca(sys.argv[1])
    print(json.dumps(findings, indent=2, ensure_ascii=False))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"\n[+] SCA: {len(findings)} findings {counts}", file=sys.stderr)


if __name__ == "__main__":
    main()
