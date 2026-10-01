#!/usr/bin/env python3
"""braimsec - command-line client for the BraimSec security scanner.

Designed as a CI/CD quality gate: zip a directory, upload it, wait for
the scan to finish, then fail the build when findings exceed a severity
threshold.

Standard library only - no third-party dependencies.

Exit codes:
    0  success (scan done, quality gate passed)
    1  usage error, auth/network failure, or scan not found
    2  quality gate failed (--fail-on threshold exceeded)
    3  the scan itself failed on the server

Configuration (priority: CLI flag > environment > config file):
    --server / BRAIMSEC_SERVER / config file "server"
    --api-key / BRAIMSEC_API_KEY / config file "api_key"
    Config file: ~/.braimsec/config (JSON object, or KEY=VALUE lines).
    Override the config path with BRAIMSEC_CONFIG (mainly for tests).

The API key is never printed - not in output, errors, or logs.
"""

from __future__ import annotations

__version__ = "1.0.0"

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

DEFAULT_SERVER = "https://api.braimsec.world"
CONFIG_ENV_VAR = "BRAIMSEC_CONFIG"
SERVER_ENV_VAR = "BRAIMSEC_SERVER"
API_KEY_ENV_VAR = "BRAIMSEC_API_KEY"
MAX_ZIP_BYTES = 50 * 1024 * 1024  # must match api/main.py MAX_ZIP_BYTES

# BraimSec severities -> numeric rank (higher = worse).
SEVERITY_RANK = {"error": 3, "warning": 2, "note": 1}
# --fail-on gate names -> minimum rank that fails the build.
GATE_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 1, "never": 99}
GATE_CHOICES = ("critical", "high", "medium", "low", "never")
FORMAT_CHOICES = ("table", "json", "sarif")

# Directories never zipped (vcs, deps, build outputs, caches).
EXCLUDE_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__", ".venv", "venv", ".tox",
    "dist", "build", "out", "target", ".next", ".nuxt",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".idea", ".vscode",
}
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".pyd")
EXCLUDE_FILES = {".DS_Store"}


class BraimSecError(Exception):
    """API / transport failure. Never carries the API key."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _read_config_file(path: str) -> dict:
    """Read ~/.braimsec/config: JSON object, or KEY=VALUE lines. {} on any problem."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return {}
    text = text.strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}
    cfg: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        cfg[key.strip()] = value.strip()
    return cfg


def resolve_config(cli_server: str | None = None,
                   cli_api_key: str | None = None) -> tuple[str, str | None]:
    """Return (server, api_key). Priority: CLI > env > config file > default."""
    cfg_path = os.environ.get(CONFIG_ENV_VAR) or str(Path.home() / ".braimsec" / "config")
    file_cfg = _read_config_file(cfg_path)
    server = (
        cli_server
        or os.environ.get(SERVER_ENV_VAR)
        or file_cfg.get("server")
        or DEFAULT_SERVER
    )
    api_key = (
        cli_api_key
        or os.environ.get(API_KEY_ENV_VAR)
        or file_cfg.get("api_key")
        or file_cfg.get("api-key")
    )
    return server.rstrip("/"), api_key


# ---------------------------------------------------------------------------
# HTTP layer (stdlib only)
# ---------------------------------------------------------------------------

def _friendly_http_error(status: int, body: str) -> str:
    if status == 401:
        return "Authentication failed (HTTP 401). Check your BraimSec API key."
    if status == 402:
        return ("Quota exceeded (HTTP 402). Your BraimSec plan has no scans "
                "left this month.")
    if status == 403:
        return "Forbidden (HTTP 403). This API key may not perform this action."
    if status == 404:
        return "Not found (HTTP 404)."
    if status == 413:
        return "Upload too large (HTTP 413). The zip exceeds the 50 MB server limit."
    if status == 429:
        return "Rate limited (HTTP 429). Slow down and retry."
    if body:
        return f"Request failed: HTTP {status}. {body}"
    return f"Request failed: HTTP {status}."


def _http(method: str, url: str, api_key: str, data: bytes | None = None,
          content_type: str | None = None, timeout: int = 60) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method)
    # The key travels only in this header; it is never logged or echoed.
    req.add_header("X-API-Key", api_key)
    if content_type:
        req.add_header("Content-Type", content_type)
    req.add_header("User-Agent", f"braimsec-cli/{__version__}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")[:500]
        except Exception:  # noqa: BLE001 - best effort
            body = ""
        raise BraimSecError(_friendly_http_error(e.code, body), status=e.code) from None
    except urllib.error.URLError as e:
        raise BraimSecError(f"Cannot reach BraimSec server at {url}: {e.reason}") from None


def _get_json(server: str, api_key: str, path: str) -> object:
    status, raw = _http("GET", server + path, api_key)
    if status != 200:
        raise BraimSecError(f"Request failed: HTTP {status}.")
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise BraimSecError("Server returned invalid JSON.") from e


def _encode_multipart(fields: list[tuple[str, str]],
                      files: list[tuple[str, str, bytes, str]]) -> tuple[bytes, str]:
    boundary = "----BraimSec" + secrets.token_hex(16)
    body = bytearray()
    for name, value in fields:
        body += f"--{boundary}\r\n".encode("ascii")
        body += (f'Content-Disposition: form-data; name="{name}"\r\n\r\n').encode("ascii")
        body += str(value).encode("utf-8") + b"\r\n"
    for name, filename, content, ctype in files:
        body += f"--{boundary}\r\n".encode("ascii")
        body += (f'Content-Disposition: form-data; name="{name}"; '
                 f'filename="{filename}"\r\n').encode("ascii")
        body += f"Content-Type: {ctype}\r\n\r\n".encode("ascii")
        body += content + b"\r\n"
    body += f"--{boundary}--\r\n".encode("ascii")
    return bytes(body), boundary


# ---------------------------------------------------------------------------
# Scan API
# ---------------------------------------------------------------------------

def upload_scan(server: str, api_key: str, zip_bytes: bytes,
                filename: str, project_id: str | None = None) -> str:
    fields: list[tuple[str, str]] = []
    if project_id:
        fields.append(("project_id", project_id))
    # Sanitize like the server does: basename only, never a path.
    safe_name = os.path.basename(filename.strip()) or "upload.zip"
    if safe_name in (".", ".."):
        safe_name = "upload.zip"
    body, boundary = _encode_multipart(
        fields, [("file", safe_name, zip_bytes, "application/zip")])
    status, raw = _http("POST", server + "/api/scans", api_key, data=body,
                        content_type=f"multipart/form-data; boundary={boundary}",
                        timeout=300)
    if status not in (200, 201):
        raise BraimSecError(f"Scan upload failed: HTTP {status}.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise BraimSecError("Server returned invalid JSON for scan upload.") from e
    scan_id = data.get("scan_id") if isinstance(data, dict) else None
    if not scan_id:
        raise BraimSecError("Server did not return a scan_id.")
    return str(scan_id)


def get_scan(server: str, api_key: str, scan_id: str) -> dict:
    data = _get_json(server, api_key, f"/api/scans/{scan_id}")
    if not isinstance(data, dict):
        raise BraimSecError("Server returned an unexpected scan payload.")
    return data


def get_results(server: str, api_key: str, scan_id: str) -> list[dict]:
    data = _get_json(server, api_key, f"/api/scans/{scan_id}/results")
    return data if isinstance(data, list) else []


def wait_for_done(server: str, api_key: str, scan_id: str,
                  poll_interval: float = 3.0, timeout: float = 600.0,
                  on_tick=None) -> dict:
    """Poll until the scan is done/failed. Raises BraimSecError on timeout."""
    started = time.monotonic()
    while True:
        info = get_scan(server, api_key, scan_id)
        if on_tick:
            on_tick(info, time.monotonic() - started)
        if info.get("status") in ("done", "failed"):
            return info
        if time.monotonic() - started > timeout:
            raise BraimSecError(
                f"Timed out after {timeout:.0f}s waiting for scan {scan_id}.")
        time.sleep(poll_interval)


# ---------------------------------------------------------------------------
# Zipping
# ---------------------------------------------------------------------------

def zip_target(path: str) -> tuple[bytes, str]:
    """Zip a file or directory, excluding VCS/deps/build outputs. Returns (bytes, name)."""
    src = Path(path)
    if not src.exists():
        raise BraimSecError(f"Path does not exist: {path}")
    import io
    buf = io.BytesIO()
    count = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        if src.is_file():
            arc = src.name
            z.write(src, arc)
            count = 1
        else:
            for root, dirs, files in os.walk(src):
                # Prune excluded dirs in place so walk does not descend.
                dirs[:] = [d for d in dirs
                           if d not in EXCLUDE_DIRS and not d.startswith(".git")]
                # Never follow or store symlinks (avoids escaping the tree).
                dirs[:] = [d for d in dirs
                           if not os.path.islink(os.path.join(root, d))]
                for name in files:
                    if name in EXCLUDE_FILES or name.endswith(EXCLUDE_SUFFIXES):
                        continue
                    full = os.path.join(root, name)
                    if os.path.islink(full):
                        continue
                    arc = os.path.relpath(full, src)
                    z.write(full, arc)
                    count += 1
    if count == 0:
        raise BraimSecError(f"Nothing to scan under {path} (all files excluded?).")
    data = buf.getvalue()
    if len(data) > MAX_ZIP_BYTES:
        raise BraimSecError(
            f"Zipped size {len(data) // (1024 * 1024)} MB exceeds the 50 MB upload limit.")
    zip_name = (src.name or "scan") + ".zip"
    return data, zip_name


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"error": 0, "warning": 0, "note": 0}
    for f in findings:
        sev = str(f.get("severity") or "").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def max_rank(findings: list[dict]) -> int:
    rank = 0
    for f in findings:
        rank = max(rank, SEVERITY_RANK.get(str(f.get("severity") or "").lower(), 0))
    return rank


def format_table(findings: list[dict], scan_id: str, target: str) -> str:
    counts = severity_counts(findings)
    total = len(findings)
    lines = [
        f"BraimSec scan {scan_id} - done",
        f"Target: {target}",
        (f"Findings: {total} "
         f"(critical/error: {counts['error']}, high/warning: {counts['warning']}, "
         f"low/note: {counts['note']})"),
        "",
    ]
    if not findings:
        lines.append("No findings. Clean scan.")
        return "\n".join(lines)
    order = {"error": 0, "warning": 1, "note": 2}
    top = sorted(findings,
                 key=lambda f: (order.get(str(f.get("severity") or "").lower(), 3),
                                str(f.get("file") or "")))[:25]
    lines.append(f"Top {len(top)} findings:")
    for f in top:
        sev = str(f.get("severity") or "note").lower()
        label = {"error": "CRITICAL", "warning": "HIGH", "note": "LOW"}.get(sev, sev.upper())
        loc = str(f.get("file") or "?")
        if f.get("line"):
            loc += f":{f['line']}"
        msg = str(f.get("message") or f.get("rule_id") or "").replace("\n", " ")[:160]
        lines.append(f"  [{label:8}] {loc}  {f.get('rule_id', '')}  {msg}")
    if total > len(top):
        lines.append(f"  ... and {total - len(top)} more")
    return "\n".join(lines)


def format_json_doc(findings: list[dict], scan_id: str, target: str) -> str:
    doc = {
        "tool": "braimsec",
        "cli_version": __version__,
        "scan_id": scan_id,
        "target": target,
        "status": "done",
        "summary": severity_counts(findings),
        "total": len(findings),
        "findings": [
            {
                "tool": f.get("tool"),
                "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "message": f.get("message"),
                "file": f.get("file"),
                "line": f.get("line"),
                "col": f.get("col"),
            }
            for f in findings
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _finding_fingerprint(tool: str, rule_id: str, file: str, message: str) -> str:
    blob = f"{tool}|{rule_id}|{file}|{message}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:32]


def format_sarif_doc(findings: list[dict], scan_id: str, target: str) -> str:
    """Minimal deterministic SARIF 2.1.0 document (self-contained)."""
    rules: dict[str, int] = {}
    rule_defs: list[dict] = []
    results: list[dict] = []
    for f in findings:
        tool = str(f.get("tool") or "unknown")
        rule_id = str(f.get("rule_id") or "unknown")
        key = f"{tool}/{rule_id}"
        if key not in rules:
            rules[key] = len(rule_defs)
            rule_defs.append({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": str(f.get("message") or rule_id)[:200]},
            })
        sev = str(f.get("severity") or "").lower()
        level = sev if sev in ("error", "warning", "note") else "warning"
        try:
            line = int(f.get("line") or 1)
        except (TypeError, ValueError):
            line = 1
        try:
            col = int(f.get("col") or 1)
        except (TypeError, ValueError):
            col = 1
        line, col = max(line, 1), max(col, 1)
        file = str(f.get("file") or "?")
        message = str(f.get("message") or "")
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rules[key],
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {"startLine": line, "startColumn": col},
                }
            }],
            "fingerprints": {
                "braimsec/v1": _finding_fingerprint(tool, rule_id, file, message),
            },
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "BraimSec",
                "version": __version__,
                "informationUri": "https://braimsec.world",
                "rules": rule_defs,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def render(findings: list[dict], scan_id: str, target: str, fmt: str) -> str:
    if fmt == "json":
        return format_json_doc(findings, scan_id, target)
    if fmt == "sarif":
        return format_sarif_doc(findings, scan_id, target)
    return format_table(findings, scan_id, target)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _progress_to_stderr(info: dict, elapsed: float) -> None:
    status = info.get("status", "?")
    sys.stderr.write(f"\r  [{elapsed:5.0f}s] scan status: {status} ...")
    sys.stderr.flush()


def cmd_scan(args: argparse.Namespace) -> int:
    server, api_key = resolve_config(args.server, args.api_key)
    if not api_key:
        print("Error: API key is required. Pass --api-key, set BRAIMSEC_API_KEY, "
              "or add api_key to ~/.braimsec/config", file=sys.stderr)
        return 1
    try:
        print(f"Zipping {args.path} ...", file=sys.stderr)
        zip_bytes, zip_name = zip_target(args.path)
        print(f"Uploading {zip_name} ({len(zip_bytes) // 1024} KB) to {server} ...",
              file=sys.stderr)
        scan_id = upload_scan(server, api_key, zip_bytes, zip_name,
                              project_id=args.project)
        print(f"Scan started: {scan_id}", file=sys.stderr)
        if args.no_wait:
            print(scan_id)
            return 0
        info = wait_for_done(server, api_key, scan_id,
                             poll_interval=args.poll_interval,
                             timeout=args.timeout,
                             on_tick=_progress_to_stderr)
        sys.stderr.write("\n")
    except BraimSecError as e:
        sys.stderr.write("\n")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    if info.get("status") == "failed":
        print(f"Error: scan {scan_id} failed on the server: "
              f"{info.get('error') or 'unknown error'}", file=sys.stderr)
        return 3
    try:
        findings = get_results(server, api_key, scan_id)
    except BraimSecError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    target = info.get("target_name") or args.path
    report = render(findings, scan_id, target, args.format)
    if args.output:
        try:
            Path(args.output).write_text(report + "\n", encoding="utf-8")
        except OSError as e:
            print(f"Error: cannot write {args.output}: {e}", file=sys.stderr)
            return 1
        # Short human summary still goes to stdout for CI logs.
        print(format_table(findings, scan_id, target).splitlines()[2])
    else:
        print(report)
    gate = GATE_RANK[args.fail_on]
    worst = max_rank(findings)
    if worst >= gate:
        print(f"\nQuality gate FAILED (--fail-on {args.fail_on}): "
              f"findings at or above threshold.", file=sys.stderr)
        return 2
    if args.fail_on != "never":
        print(f"\nQuality gate passed (--fail-on {args.fail_on}).", file=sys.stderr)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    server, api_key = resolve_config(args.server, args.api_key)
    if not api_key:
        print("Error: API key is required. Pass --api-key, set BRAIMSEC_API_KEY, "
              "or add api_key to ~/.braimsec/config", file=sys.stderr)
        return 1
    try:
        info = get_scan(server, api_key, args.scan_id)
    except BraimSecError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    summary = info.get("severity_summary") or {}
    print(f"Scan:   {info.get('id')}")
    print(f"Target: {info.get('target_name', '?')}")
    print(f"Status: {info.get('status', '?')}")
    print(f"Findings: error={summary.get('error', 0)} "
          f"warning={summary.get('warning', 0)} note={summary.get('note', 0)}")
    if info.get("error"):
        print(f"Error:  {info['error']}")
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="braimsec",
        description="BraimSec security scanner CLI - scan code and gate CI builds.")
    p.add_argument("--version", action="version", version=f"braimsec {__version__}")
    p.add_argument("--server", default=None,
                   help="BraimSec server URL (default: BRAIMSEC_SERVER or "
                        "https://api.braimsec.world)")
    p.add_argument("--api-key", default=None,
                   help="API key (default: BRAIMSEC_API_KEY; never printed)")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="Zip a path, scan it, wait for results.")
    s.add_argument("path", help="File or directory to scan")
    s.add_argument("--project", default=None, help="Project ID to file the scan under")
    s.add_argument("--fail-on", default="never", choices=GATE_CHOICES,
                   help="Fail (exit 2) when findings reach this level "
                        "(critical=error, high=warning, low=any). Default: never.")
    s.add_argument("--format", default="table", choices=FORMAT_CHOICES,
                   help="Report format: table, json, or sarif. Default: table.")
    s.add_argument("--output", default=None,
                   help="Write the report to FILE (a short summary still prints).")
    s.add_argument("--timeout", type=float, default=600.0,
                   help="Max seconds to wait for the scan (default: 600).")
    s.add_argument("--poll-interval", type=float, default=3.0,
                   help="Seconds between status polls (default: 3).")
    s.add_argument("--no-wait", action="store_true",
                   help="Upload and print the scan id without waiting.")
    s.set_defaults(func=cmd_scan)

    t = sub.add_parser("status", help="Show a scan's status and severity summary.")
    t.add_argument("scan_id", help="Scan ID returned by `braimsec scan --no-wait`")
    t.set_defaults(func=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    try:
        return int(args.func(args))
    except BraimSecError as e:
        # Last-resort guard: command handlers already catch these, but the
        # key must never leak even on an unexpected path.
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
