"""Deterministic OpenAPI 3.1 documentation for the BraimSec API.

Design
------
The spec is *generated from the live FastAPI app*, but the per-endpoint
prose lives in an explicit registry (:data:`DOCS`) keyed by
``(method, path)``. :func:`build_openapi_spec` walks ``app.routes`` and
**refuses** (raises :class:`OpenAPIError`) when a route has no registry
entry — a new endpoint without documentation fails loudly instead of
silently shipping undocumented. Stale registry entries (documenting a
route that no longer exists) fail the same way.

Determinism: the same code always produces the same bytes — paths are
sorted, ``json.dumps(..., sort_keys=True)`` is used everywhere, and no
timestamps or random values enter the document.

Served at ``GET /api/openapi.json`` (public) with a human-readable page
at ``GET /docs`` (see :func:`docs_page_html`).
"""

from __future__ import annotations

import json

OPENAPI_VERSION = "3.1.0"
API_TITLE = "BraimSec API"
API_VERSION = "0.1.0"

DEFAULT_RATE_LIMIT = "600/minute"


class OpenAPIError(Exception):
    """Raised when the docs registry and the live routes disagree."""


# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------

def _resp(description: str, example=None, content_type: str = "application/json") -> dict:
    """Build one OpenAPI response object with an optional example payload."""
    r: dict = {"description": description}
    if example is not None:
        r["content"] = {content_type: {"example": example}}
    return r


def _err400(example: str = "days: >= 0 (0 = all time)") -> dict:
    return _resp("Bad request — invalid parameters or body.",
                 {"detail": example})


def _err401() -> dict:
    return _resp("Missing or invalid X-API-Key header.",
                 {"detail": "Invalid or missing X-API-Key header"})


def _err402(example: str = "Monthly scan quota exceeded (48/50 used). "
                           "Upgrade your plan to continue.") -> dict:
    return _resp("Monthly quota exhausted for this org.", {"detail": example})


def _err403(example: str = "Requires 'member' role or higher "
                            "(this key: 'viewer')") -> dict:
    return _resp("Forbidden — the key's role or scope is insufficient.",
                 {"detail": example})


def _err404(example: str = "Scan not found") -> dict:
    return _resp("Not found in this organization.", {"detail": example})


def _err409(example: str = "Address already registered") -> dict:
    return _resp("Conflict — the resource already exists or the state "
                 "does not allow the action.", {"detail": example})


def _err413() -> dict:
    return _resp("Payload too large.", {"detail": "ZIP exceeds 50 MB limit"})


def _err422() -> dict:
    return _resp("Request validation failed.",
                 {"detail": [{"loc": ["query", "days"],
                              "msg": "value is not a valid integer",
                              "type": "type_error.integer"}]})


def _err429() -> dict:
    return _resp("Rate limit exceeded — back off and retry.",
                 {"detail": "Rate limit exceeded: 30 per 1 minute"})


def _err500(example: str = "report refused: no completed scans") -> dict:
    return _resp("The server refused to build the artifact.",
                 {"detail": example})


def _err502(example: str = "Payment provider error: timeout") -> dict:
    return _resp("An upstream provider failed.", {"detail": example})


def _err503(example: str = "AI provider is not configured on this server") -> dict:
    return _resp("Service unavailable — try again shortly.",
                 {"detail": example})


def _param(name: str, where: str, ptype: str, description: str,
           required: bool = False, example=None, enum=None) -> dict:
    """Build one OpenAPI parameter object."""
    schema: dict = {"type": ptype}
    if enum:
        schema["enum"] = enum
    p: dict = {"name": name, "in": where, "required": required,
               "description": description, "schema": schema}
    if example is not None:
        p["example"] = example
    return p


def _body(description: str, example: dict,
          content_type: str = "application/json") -> dict:
    """Build a requestBody object from a concrete example payload."""
    return {"description": description,
            "required": True,
            "content": {content_type: {"example": example}}}


# ---------------------------------------------------------------------------
# Per-endpoint documentation registry.
#
# Key: (HTTP_METHOD, path) exactly as registered on the FastAPI app.
# Every entry: tag, summary, description, auth ("public" | "key"),
#   min_role (viewer|member|admin|owner — None for public),
#   org_scope (True when project-scoped keys are rejected),
#   rate_limit ("N/minute" as enforced by slowapi),
#   params (query/path), request_body, responses {status: {...}}.
# ---------------------------------------------------------------------------

DOCS: dict[tuple[str, str], dict] = {}

def _doc(method: str, path: str, **kw) -> None:
    DOCS[(method.upper(), path)] = kw


# ============================ Scans ========================================

_doc("POST", "/api/scans",
     tag="Scans",
     summary="Start a scan",
     description=("Queue a scan from a server-local path or an uploaded zip. "
                  "Quota is checked before any expensive work and consumed "
                  "only when the scan is actually created. An optional "
                  "webhook_url receives a signed JSON payload "
                  "(X-BraimSec-Signature: sha256=...) when the scan reaches "
                  "a terminal state; the signing secret is returned once. "
                  "baseline_scan_id runs an incremental diff-based rescan "
                  "(requires target_path — zip uploads are always full scans)."),
     auth="key", min_role="member", org_scope=False, rate_limit="60/minute",
     params=[],
     request_body=_body(
         "multipart/form-data: either target_path or an uploaded zip file.",
         {"target_path": "/srv/code/myapp", "webhook_url": "",
          "baseline_scan_id": "", "project_id": ""},
         content_type="multipart/form-data"),
     responses={
         "200": _resp("Scan queued.",
                      {"scan_id": "a1b2c3d4e5f6", "status": "queued",
                       "webhook_secret": "9f8e7d6c5b4a39281706f5e4d3c2b1a"}),
         "400": _err400("Provide target_path or upload a zip file"),
         "401": _err401(),
         "402": _err402(),
         "403": _err403("This key is scoped to its own project and cannot "
                        "file scans elsewhere"),
         "404": _err404("baseline scan not found"),
         "413": _err413(),
         "422": _err422(),
         "429": _err429(),
         "503": _err503("Scan queue unavailable, try again shortly."),
     })

_doc("GET", "/api/scans",
     tag="Scans",
     summary="List scans",
     description="Newest-first scan rows for the caller's org (and project "
                 "scope). Viewers may read.",
     auth="key", min_role="viewer", org_scope=False, rate_limit="600/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of scan rows.",
                      [{"id": "a1b2c3d4e5f6", "target_name": "myapp",
                        "status": "done", "total_findings": 7,
                        "created_at": "2026-10-01T12:00:00+00:00",
                        "finished_at": "2026-10-01T12:01:40+00:00"}]),
         "401": _err401(),
         "429": _err429(),
     })

_doc("GET", "/api/scans/{scan_id}",
     tag="Scans",
     summary="Scan status",
     description="One scan row plus a severity_summary "
                 "({error: n, warning: n, note: n}). Viewers may read.",
     auth="key", min_role="viewer", org_scope=False, rate_limit="600/minute",
     params=[_param("scan_id", "path", "string", "Scan id.", True,
                   example="a1b2c3d4e5f6")],
     request_body=None,
     responses={
         "200": _resp("Scan row with severity summary.",
                      {"id": "a1b2c3d4e5f6", "target_name": "myapp",
                       "status": "done", "total_findings": 7,
                       "severity_summary": {"error": 2, "warning": 3,
                                            "note": 2}}),
         "401": _err401(),
         "404": _err404(),
         "429": _err429(),
     })

_doc("GET", "/api/scans/{scan_id}/results",
     tag="Scans",
     summary="Scan findings",
     description=("Findings of one scan with triage state joined in. "
                  "Optional filters: severity (error|warning|note), "
                  "triage_status (open|in_progress|false_positive|fixed|"
                  "accepted_risk), assigned_to (API key id). Viewers may read."),
     auth="key", min_role="viewer", org_scope=False, rate_limit="600/minute",
     params=[
         _param("scan_id", "path", "string", "Scan id.", True,
                example="a1b2c3d4e5f6"),
         _param("severity", "query", "string",
                "Filter by severity.", False, example="error",
                enum=["error", "warning", "note"]),
         _param("triage_status", "query", "string",
                "Filter by triage status.", False, example="open",
                enum=["open", "in_progress", "false_positive", "fixed",
                      "accepted_risk"]),
         _param("assigned_to", "query", "string",
                "Filter by assignee (API key id).", False,
                example="k_9f2ac41d"),
     ],
     request_body=None,
     responses={
         "200": _resp("Array of finding rows.",
                      [{"id": 42, "tool": "semgrep",
                        "rule_id": "braimsec-python-sqli",
                        "severity": "error",
                        "message": "Possible SQL injection via string "
                                   "formatting",
                        "file": "app/db.py", "line": 87, "col": 12,
                        "ai_verdict": None, "has_fix": False,
                        "triage_status": "open", "triage_assignee": None,
                        "triage_note": ""}]),
         "400": _err400("triage_status: one of ('open', 'in_progress', "
                        "'false_positive', 'fixed', 'accepted_risk')"),
         "401": _err401(),
         "404": _err404(),
         "429": _err429(),
     })

_doc("GET", "/api/scans/{scan_id}/results.csv",
     tag="Scans",
     summary="Scan findings as CSV",
     description=("CSV export of one scan's findings — auditor-friendly. Same "
                  "visibility as GET /api/scans/{id}/results (org-scoped, "
                  "viewers may read). RFC 4180 quoting keeps messages with "
                  "commas/quotes/newlines intact. Downloads as "
                  "braimsec-<scan_id>-results.csv."),
     auth="key", min_role="viewer", org_scope=False, rate_limit="30/minute",
     params=[
         _param("scan_id", "path", "string", "Scan id.", True,
                example="a1b2c3d4e5f6"),
         _param("severity", "query", "string",
                "Filter by severity.", False, example="error",
                enum=["error", "warning", "note"]),
     ],
     request_body=None,
     responses={
         "200": _resp("CSV bytes.",
                      {"note": "binary text/csv; Content-Disposition: "
                               "attachment; filename="
                               "\"braimsec-<scan_id>-results.csv\""},
                      content_type="text/csv"),
         "401": _err401(),
         "404": _err404(),
         "429": _err429(),
     })

_doc("GET", "/api/trends",
     tag="Scans",
     summary="Vulnerability trends",
     description=("One point per completed scan, chronological: totals, "
                  "severity split, and new vs fixed findings computed against "
                  "the immediately previous scan (stable fingerprint "
                  "tool|rule_id|file|message). days=0 means all time. "
                  "Includes a summary trend: improving|worsening|stable|"
                  "insufficient. Viewers may read; project-scoped keys see "
                  "only their own project."),
     auth="key", min_role="viewer", org_scope=False, rate_limit="60/minute",
     params=[
         _param("days", "query", "integer",
                "Lookback window in days; 0 = all time.", False, example=90),
         _param("project_id", "query", "string",
                "Restrict to one project.", False, example="p_1234abcd"),
     ],
     request_body=None,
     responses={
         "200": _resp("Trend points plus summary.",
                      {"points": [{"scan_id": "a1b2c3d4e5f6",
                                   "target_name": "myapp",
                                   "created_at": "2026-10-01T12:00:00+00:00",
                                   "total": 7,
                                   "by_severity": {"error": 2, "warning": 3,
                                                   "note": 2},
                                   "new": 1, "fixed": 3}],
                       "summary": {"scans": 4, "period_days": 90,
                                   "latest_total": 7, "previous_total": 9,
                                   "delta": -2, "trend": "improving"}}),
         "400": _err400("days: >= 0 (0 = all time)"),
         "401": _err401(),
         "403": _err403("Project-scoped keys cannot query other projects"),
         "404": _err404("Project not found"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/scans/{scan_id}/diff",
     tag="Scans",
     summary="Diff two scans",
     description=("New / fixed / persisting findings between two completed "
                  "scans, matched by the stable fingerprint "
                  "(tool|rule_id|file|message — line/column insensitive). "
                  "scan_id is the newer scan, against the baseline. Both "
                  "must target the same project and codebase — a mismatch is "
                  "a 400, never a silent apples-to-oranges comparison. "
                  "Viewers may read."),
     auth="key", min_role="viewer", org_scope=False, rate_limit="60/minute",
     params=[
         _param("scan_id", "path", "string", "Newer scan id.", True,
                example="b2c3d4e5f6a7"),
         _param("against", "query", "string", "Baseline scan id.", True,
                example="a1b2c3d4e5f6"),
     ],
     request_body=None,
     responses={
         "200": _resp("Diff with summary counts and fix rate.",
                      {"scan": {"id": "b2c3d4e5f6a7", "total": 5},
                       "against": {"id": "a1b2c3d4e5f6", "total": 7},
                       "summary": {"new": 1, "fixed": 3, "persisting": 4,
                                   "fix_rate": 0.429},
                       "new": [], "fixed": [], "persisting": []}),
         "400": _err400("Scans target different codebases"),
         "401": _err401(),
         "404": _err404(),
         "429": _err429(),
     })

_doc("POST", "/api/scans/{scan_id}/ai-review",
     tag="Scans",
     summary="Request AI review",
     description=("Queue an AI review of a scan's pending findings. Consumes "
                  "ai_review quota (one unit per pending finding, plus a "
                  "capped sink-audit budget). 503 when the queue is "
                  "unreachable."),
     auth="key", min_role="member", org_scope=False, rate_limit="30/minute",
     params=[_param("scan_id", "path", "string", "Scan id.", True,
                   example="a1b2c3d4e5f6")],
     request_body=None,
     responses={
         "200": _resp("Review queued.",
                      {"scan_id": "a1b2c3d4e5f6", "ai_review": "queued",
                       "sink_audit": {"status": "queued", "budget": 3}}),
         "401": _err401(),
         "402": _err402("Monthly AI-review quota exceeded (100/100 used). "
                         "Upgrade your plan to continue."),
         "403": _err403(),
         "404": _err404(),
         "429": _err429(),
         "503": _err503("Review queue unavailable, try again shortly."),
     })

# ============================ Findings =====================================

_doc("POST", "/api/findings/{finding_id}/fix-suggestion",
     tag="Findings",
     summary="AI fix suggestion",
     description=("Generate an AI fix suggestion for one finding. First call "
                  "spends 2 units of ai_review quota and caches the result; "
                  "later calls return the cached suggestion for free. 503 "
                  "when no AI provider is configured on the server."),
     auth="key", min_role="member", org_scope=False, rate_limit="30/minute",
     params=[_param("finding_id", "path", "integer", "Finding id.", True,
                   example=42)],
     request_body=None,
     responses={
         "200": _resp("Suggestion (cached flag tells whether it was reused).",
                      {"finding_id": 42, "cached": False,
                       "suggestion": {"explanation": "Use parameterized "
                                                     "queries...",
                                      "diff": "@@ -87,7 +87,7 @@...",
                                      "confidence": "high",
                                      "caveats": "Verify the ORM call "
                                                 "still returns rows.",
                                      "checks": {"applies": True,
                                                 "syntax_ok": True},
                                      "generated_at":
                                      "2026-10-01T12:05:00+00:00"}}),
         "401": _err401(),
         "402": _err402("Monthly AI-review quota exceeded (100/100 used; "
                         "fix generation costs 2 units). Upgrade your plan "
                         "to continue."),
         "403": _err403(),
         "404": _err404("Finding not found"),
         "422": _err422(),
         "429": _err429(),
         "502": _err502("Fix generation failed: provider timeout"),
         "503": _err503("AI provider is not configured on this server"),
     })

_doc("POST", "/api/findings/{finding_id}/patch-verify",
     tag="Findings",
     summary="Verify a stored fix",
     description=("Closed-loop verification of a stored fix suggestion: "
                  "eligibility, fuzzy apply, semgrep re-scan. Deterministic "
                  "— no LLM, no quota consumed. A 'verified' patch is still "
                  "a suggestion requiring human review. 409 when the scan "
                  "sources are gone (zero-retention)."),
     auth="key", min_role="member", org_scope=False, rate_limit="30/minute",
     params=[_param("finding_id", "path", "integer", "Finding id.", True,
                   example=42)],
     request_body=None,
     responses={
         "200": _resp("Verification verdict stored on the finding.",
                      {"finding_id": 42,
                       "verification": {"verified": True,
                                        "detail": "finding no longer "
                                                  "reported after patch"}}),
         "400": _err400("No fix suggestion stored for this finding — call "
                        "POST /api/findings/{id}/fix-suggestion first"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Finding not found"),
         "409": _err409("Scan sources are no longer available (deleted "
                        "after scan — zero-retention); verification needs "
                        "the original file"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/findings/{finding_id}/taint-flow",
     tag="Findings",
     summary="Taint-flow trace",
     description=("Linear taint-flow trace for one finding: ordered steps "
                  "(source -> propagation -> sink) labeled with origin "
                  "(semgrep-trace | ast-slice), plus the tri-state "
                  "sanitization verdict (unsanitized | sanitized | "
                  "uncertain). Deterministic — no LLM, no quota. Viewers "
                  "may read. 200 with available:false when scan sources "
                  "are gone (zero-retention)."),
     auth="key", min_role="viewer", org_scope=False, rate_limit="30/minute",
     params=[_param("finding_id", "path", "integer", "Finding id.", True,
                   example=42)],
     request_body=None,
     responses={
         "200": _resp("Taint path steps.",
                      {"finding_id": 42,
                       "steps": [{"kind": "source", "origin": "semgrep-trace",
                                  "file": "app/views.py", "line": 31,
                                  "code": "name = request.GET['name']"},
                                 {"kind": "sink", "origin": "semgrep-trace",
                                  "file": "app/views.py", "line": 33,
                                  "code": "cursor.execute(q)"}],
                       "sanitization": "unsanitized"}),
         "401": _err401(),
         "404": _err404("Finding not found"),
         "422": _err422(),
         "429": _err429(),
     })

# ============================ Triage & team ================================

_doc("GET", "/api/team",
     tag="Triage",
     summary="List assignable team keys",
     description=("API keys of the org available for finding assignment "
                  "(id, name, prefix, role — never hashes). Project-scoped "
                  "keys see only their own project's keys."),
     auth="key", min_role="member", org_scope=False, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Team key rows.",
                      [{"id": "k_9f2ac41d", "name": "Sara",
                        "key_prefix": "bs_ab12cd34", "role": "member"}]),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("GET", "/api/findings/{finding_id}/triage",
     tag="Triage",
     summary="Triage state + history",
     description="Current triage state and append-only change history of one "
                 "finding. Viewers may read.",
     auth="key", min_role="viewer", org_scope=False, rate_limit="60/minute",
     params=[_param("finding_id", "path", "integer", "Finding id.", True,
                   example=42)],
     request_body=None,
     responses={
         "200": _resp("Triage state and history.",
                      {"finding_id": 42,
                       "triage": {"status": "in_progress",
                                  "assigned_to": "k_9f2ac41d",
                                  "note": "Checking with backend team"},
                       "history": [{"changed_by": "bs_ab12cd34",
                                    "changed_at": "2026-10-01T12:10:00+00:00",
                                    "from_status": "open",
                                    "to_status": "in_progress",
                                    "note": ""}]}),
         "401": _err401(),
         "404": _err404("Finding not found"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("PATCH", "/api/findings/{finding_id}/triage",
     tag="Triage",
     summary="Triage one finding",
     description=("Update status / assignee / note. Statuses: open, "
                  "in_progress, false_positive, fixed, accepted_risk. "
                  "Marking false_positive suppresses the finding's "
                  "fingerprint from future scheduled-scan alerts; leaving "
                  "false_positive lifts the suppression. assigned_to must be "
                  "a live API key id of the org."),
     auth="key", min_role="member", org_scope=False, rate_limit="60/minute",
     params=[_param("finding_id", "path", "integer", "Finding id.", True,
                   example=42)],
     request_body=_body(
         "Triage update (at least one of status, assigned_to, note).",
         {"status": "in_progress", "assigned_to": "k_9f2ac41d",
          "note": "Checking with backend team"}),
     responses={
         "200": _resp("New triage state.",
                      {"finding_id": 42, "status": "in_progress",
                       "assigned_to": "k_9f2ac41d",
                       "note": "Checking with backend team",
                       "updated_by": "bs_ab12cd34",
                       "updated_at": "2026-10-01T12:10:00+00:00"}),
         "400": _err400("status: one of ('open', 'in_progress', "
                        "'false_positive', 'fixed', 'accepted_risk')"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Finding not found"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("POST", "/api/findings/triage-bulk",
     tag="Triage",
     summary="Triage many findings",
     description=("Apply one triage update to up to 200 findings. Findings "
                  "not visible to the caller are skipped and reported."),
     auth="key", min_role="member", org_scope=False, rate_limit="30/minute",
     params=[],
     request_body=_body(
         "Bulk triage update.",
         {"finding_ids": [41, 42, 43], "status": "accepted_risk",
          "note": "Legacy module, scheduled for rewrite"}),
     responses={
         "200": _resp("Updated vs skipped ids.",
                      {"updated": [41, 42], "skipped": [43]}),
         "400": _err400("finding_ids: non-empty list required"),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

# ============================ Reports ======================================

_doc("GET", "/api/scans/{scan_id}/sarif",
     tag="Reports",
     summary="SARIF 2.1.0 export",
     description=("SARIF 2.1.0 document of a scan's findings as "
                  "application/sarif+json, downloading as "
                  "braimsec-<scan_id>.sarif. Import into GitHub code "
                  "scanning via github/codeql-action/upload-sarif (see "
                  "reports/SARIF.md). Deterministic pure function of stored "
                  "findings — no rescan, no LLM. Viewers may read."),
     auth="key", min_role="viewer", org_scope=False, rate_limit="30/minute",
     params=[_param("scan_id", "path", "string", "Scan id.", True,
                   example="a1b2c3d4e5f6")],
     request_body=None,
     responses={
         "200": _resp("SARIF document.",
                      {"version": "2.1.0",
                       "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "BraimSec"}},
                                 "results": []}]},
                      content_type="application/sarif+json"),
         "401": _err401(),
         "404": _err404(),
         "429": _err429(),
         "500": _err500("sarif build refused: no findings"),
     })

_doc("GET", "/api/scans/{scan_id}/badge.svg",
     tag="Reports",
     summary="Scan status badge (SVG)",
     description=("Public shields.io-style status badge for README embedding: "
                  "`<img src=\"https://<host>/api/scans/<id>/badge.svg\">`. "
                  "No authentication — exposes only aggregate severity counts "
                  "(never file names, messages, targets or org data). Unknown "
                  "scan -> 404, not a badge. Deterministic per scan state."),
     auth="public", min_role=None, org_scope=False, rate_limit="60/minute",
     params=[_param("scan_id", "path", "string", "Scan id.", True,
                   example="a1b2c3d4e5f6")],
     request_body=None,
     responses={
         "200": _resp("SVG badge bytes.",
                      {"note": "binary image/svg+xml; Cache-Control: no-store"},
                      content_type="image/svg+xml"),
         "404": _err404(),
         "429": _err429(),
     })

_doc("GET", "/api/scans/{scan_id}/report.pdf",
     tag="Reports",
     summary="Scan PDF report",
     description=("CISO-grade PDF report of one completed scan. Pure function "
                  "of stored data: no rescan, no LLM, no quota. "
                  "Deterministic per scan; ETag enables client caching "
                  "(If-None-Match -> 304). Viewers may read."),
     auth="key", min_role="viewer", org_scope=False, rate_limit="30/minute",
     params=[_param("scan_id", "path", "string", "Scan id.", True,
                   example="a1b2c3d4e5f6")],
     request_body=None,
     responses={
         "200": _resp("PDF bytes.",
                      {"note": "binary application/pdf; ETag header set; "
                               "Content-Disposition: attachment; filename="
                               "\"braimsec-<scan_id>-report.pdf\""},
                      content_type="application/pdf"),
         "304": {"description": "Not modified (ETag matched)."},
         "401": _err401(),
         "404": _err404(),
         "409": _err409("Scan not completed yet"),
         "429": _err429(),
         "500": _err500(),
     })

_doc("POST", "/api/reports/executive",
     tag="Reports",
     summary="Executive PDF report",
     description=("Manager-facing executive PDF (plain language): posture, "
                  "top-10 findings with practical recommendations, SOC 2 / "
                  "ISO 27001 coverage, recent scans. Pure function of stored "
                  "data: no rescan, no LLM, no quota. Optional body "
                  '{"project_id, days} (days default 90, 0 = all time). '
                  "Viewers may read."),
     auth="key", min_role="viewer", org_scope=False, rate_limit="30/minute",
     params=[],
     request_body=_body("Optional scope.",
                        {"project_id": "p_1234abcd", "days": 90}),
     responses={
         "200": _resp("PDF bytes.",
                      {"note": "binary application/pdf; Content-Disposition: "
                               "attachment; filename="
                               "\"braimsec-executive-report.pdf\""},
                      content_type="application/pdf"),
         "400": _err400("days: >= 0 (0 = all time)"),
         "401": _err401(),
         "403": _err403("Project-scoped keys cannot query other projects"),
         "404": _err404("No completed scans in scope"),
         "429": _err429(),
         "500": _err500(),
     })

_doc("POST", "/api/report-schedules",
     tag="Reports",
     summary="Create report schedule",
     description=("Schedule a recurring executive PDF emailed to the org's "
                  "alert-email recipients. frequency weekly|monthly; weekly "
                  "needs weekday (0=Monday), monthly needs day_of_month "
                  "(1..28). project_id scopes to one project (null = whole "
                  "org). Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[],
     request_body=_body(
         "Report schedule spec.",
         {"name": "Weekly exec summary", "frequency": "weekly",
          "run_time": "08:00", "weekday": 0, "timezone": "Asia/Beirut",
          "project_id": None, "days": 90, "enabled": True}),
     responses={
         "200": _resp("Created schedule.",
                      {"report_schedule_id": "rs_1a2b3c4d",
                       "next_run_at": "2026-10-05T08:00:00+03:00"}),
         "400": _err400("weekday: required for weekly report schedules"),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("GET", "/api/report-schedules",
     tag="Reports",
     summary="List report schedules",
     description="The org's report schedules, newest first. Viewer+, org scope.",
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of report schedule rows.",
                      [{"id": "rs_1a2b3c4d", "name": "Weekly exec summary",
                        "frequency": "weekly", "run_time": "08:00",
                        "weekday": 0, "timezone": "Asia/Beirut",
                        "enabled": 1,
                        "next_run_at": "2026-10-05T08:00:00+03:00"}]),
         "401": _err401(),
         "403": _err403("Project-scoped keys cannot access org-level "
                        "resources"),
         "429": _err429(),
     })

_doc("GET", "/api/report-schedules/{schedule_id}",
     tag="Reports",
     summary="Get report schedule",
     description="One report schedule. Viewer+, org scope.",
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[_param("schedule_id", "path", "string", "Report schedule id.",
                   True, example="rs_1a2b3c4d")],
     request_body=None,
     responses={
         "200": _resp("Report schedule row.",
                      {"id": "rs_1a2b3c4d", "name": "Weekly exec summary",
                       "frequency": "weekly"}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Report schedule not found"),
         "429": _err429(),
     })

_doc("PATCH", "/api/report-schedules/{schedule_id}",
     tag="Reports",
     summary="Update report schedule",
     description=("Partial update; changing cadence or timezone recomputes "
                  "the next run from now. Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("schedule_id", "path", "string", "Report schedule id.",
                   True, example="rs_1a2b3c4d")],
     request_body=_body("Fields to update.",
                        {"run_time": "09:00", "enabled": False}),
     responses={
         "200": _resp("Updated report schedule row.",
                      {"id": "rs_1a2b3c4d", "run_time": "09:00",
                       "enabled": 0}),
         "400": _err400("day_of_month: required for monthly report schedules"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Report schedule not found"),
         "429": _err429(),
     })

_doc("DELETE", "/api/report-schedules/{schedule_id}",
     tag="Reports",
     summary="Delete report schedule",
     description="Delete a report schedule and its delivery history. "
                 "Member+, org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("schedule_id", "path", "string", "Report schedule id.",
                   True, example="rs_1a2b3c4d")],
     request_body=None,
     responses={
         "200": _resp("Deletion receipt.",
                      {"report_schedule_id": "rs_1a2b3c4d",
                       "deleted": True}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Report schedule not found"),
         "429": _err429(),
     })

_doc("POST", "/api/report-schedules/{schedule_id}/run",
     tag="Reports",
     summary="Run report schedule now",
     description=("Trigger one immediate delivery of an enabled report "
                  "schedule. The regular cadence is untouched. Member+, "
                  "org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[_param("schedule_id", "path", "string", "Report schedule id.",
                   True, example="rs_1a2b3c4d")],
     request_body=None,
     responses={
         "200": _resp("Delivery outcome.",
                      {"report_schedule_id": "rs_1a2b3c4d",
                       "delivered": True, "recipients": 2}),
         "400": _err400("Report schedule is disabled"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Report schedule not found"),
         "429": _err429(),
     })

# ============================ Schedules ====================================

_doc("POST", "/api/schedules",
     tag="Schedules",
     summary="Create scan schedule",
     description=("Create a scheduled scan (member+, org scope). target_path "
                  "must resolve inside the scan sandbox. webhook_url is "
                  "optional — empty means email-only alerts. First baseline "
                  "run is silent; alerts fire only on new findings >= "
                  "alert_severity."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[],
     request_body=_body(
         "Schedule spec.",
         {"name": "Nightly scan", "target_path": "/srv/code/myapp",
          "frequency": "daily", "run_time": "02:00", "weekday": None,
          "timezone": "Asia/Beirut", "alert_severity": "warning",
          "webhook_url": "", "enabled": True}),
     responses={
         "200": _resp("Created schedule.",
                      {"schedule_id": "s_1a2b3c4d",
                       "next_run_at": "2026-10-02T02:00:00+03:00"}),
         "400": _err400("frequency: one of ('daily', 'weekly')"),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("GET", "/api/schedules",
     tag="Schedules",
     summary="List scan schedules",
     description="The org's schedules, newest first. Viewer+, org scope.",
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of schedule rows.",
                      [{"id": "s_1a2b3c4d", "name": "Nightly scan",
                        "frequency": "daily", "run_time": "02:00",
                        "timezone": "Asia/Beirut", "alert_severity": "warning",
                        "enabled": 1,
                        "next_run_at": "2026-10-02T02:00:00+03:00"}]),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("GET", "/api/schedules/{schedule_id}",
     tag="Schedules",
     summary="Get scan schedule",
     description="One schedule. Viewer+, org scope.",
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[_param("schedule_id", "path", "string", "Schedule id.", True,
                   example="s_1a2b3c4d")],
     request_body=None,
     responses={
         "200": _resp("Schedule row.",
                      {"id": "s_1a2b3c4d", "name": "Nightly scan",
                       "frequency": "daily"}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Schedule not found"),
         "429": _err429(),
     })

_doc("PATCH", "/api/schedules/{schedule_id}",
     tag="Schedules",
     summary="Update scan schedule",
     description=("Partial update; changing cadence or timezone recomputes "
                  "the next run from now. Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("schedule_id", "path", "string", "Schedule id.", True,
                   example="s_1a2b3c4d")],
     request_body=_body("Fields to update.",
                        {"run_time": "03:00", "enabled": False}),
     responses={
         "200": _resp("Updated schedule row.",
                      {"id": "s_1a2b3c4d", "run_time": "03:00",
                       "enabled": 0}),
         "400": _err400("weekday: required for weekly schedules"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Schedule not found"),
         "429": _err429(),
     })

_doc("DELETE", "/api/schedules/{schedule_id}",
     tag="Schedules",
     summary="Delete scan schedule",
     description="Delete a schedule and its notification history. Member+, "
                 "org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("schedule_id", "path", "string", "Schedule id.", True,
                   example="s_1a2b3c4d")],
     request_body=None,
     responses={
         "200": _resp("Deletion receipt.",
                      {"schedule_id": "s_1a2b3c4d", "deleted": True}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Schedule not found"),
         "429": _err429(),
     })

_doc("POST", "/api/schedules/{schedule_id}/run",
     tag="Schedules",
     summary="Run schedule now",
     description=("Trigger one immediate run of an enabled schedule. The "
                  "regular cadence is untouched. Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[_param("schedule_id", "path", "string", "Schedule id.", True,
                   example="s_1a2b3c4d")],
     request_body=None,
     responses={
         "200": _resp("Queued run.",
                      {"schedule_id": "s_1a2b3c4d",
                       "scan_id": "a1b2c3d4e5f6", "status": "queued"}),
         "400": _err400("Schedule is disabled"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Schedule not found"),
         "429": _err429(),
     })

# ============================ VCS ==========================================

_doc("POST", "/api/vcs/repos",
     tag="VCS",
     summary="Register repo for scan-on-push",
     description=("Register a GitHub/GitLab repo. Returns the repo plus a "
                  "one-time webhook_secret and the receiver_url to paste "
                  "into the provider's webhook settings. Secrets are shown "
                  "once and never stored in cleartext. 409 when the repo is "
                  "already registered for this org. Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[],
     request_body=_body(
         "Repo registration.",
         {"provider": "github", "repo_url": "https://github.com/acme/myapp",
          "full_name": "acme/myapp", "branch": "main",
          "alert_severity": "warning", "webhook_url": "",
          "project_id": None}),
     responses={
         "200": _resp("Registered repo with one-time secret.",
                      {"id": "v_1a2b3c4d", "provider": "github",
                       "repo_url": "https://github.com/acme/myapp",
                       "full_name": "acme/myapp", "branch": "main",
                       "webhook_secret": "whsec_9f8e7d6c5b4a",
                       "receiver_url": "https://api.braimsec.world/api/"
                                       "webhooks/github",
                       "warning": "Store this secret now — it will never be "
                                  "shown again."}),
         "400": _err400("Unknown provider 'bitbucket' (expected "
                        "github|gitlab)"),
         "401": _err401(),
         "403": _err403(),
         "409": _err409("This repo is already registered for this org"),
         "429": _err429(),
     })

_doc("GET", "/api/vcs/repos",
     tag="VCS",
     summary="List registered repos",
     description="The org's repos (never exposes secret material). Viewer+, "
                 "org scope; project-scoped keys see only their project.",
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of repo rows.",
                      [{"id": "v_1a2b3c4d", "provider": "github",
                        "repo_url": "https://github.com/acme/myapp",
                        "full_name": "acme/myapp", "branch": "main",
                        "alert_severity": "warning", "enabled": True,
                        "last_scan_id": "a1b2c3d4e5f6",
                        "last_scan_at": "2026-10-01T12:00:00+00:00"}]),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("GET", "/api/vcs/repos/{repo_id}",
     tag="VCS",
     summary="Repo detail",
     description="Repo row plus last_scan summary. Viewer+, org scope.",
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[_param("repo_id", "path", "string", "Repo id.", True,
                   example="v_1a2b3c4d")],
     request_body=None,
     responses={
         "200": _resp("Repo with last scan.",
                      {"id": "v_1a2b3c4d", "provider": "github",
                       "branch": "main",
                       "last_scan": {"id": "a1b2c3d4e5f6",
                                     "status": "done", "total_findings": 7}}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Repo not found"),
         "429": _err429(),
     })

_doc("PATCH", "/api/vcs/repos/{repo_id}",
     tag="VCS",
     summary="Update repo",
     description="Update branch / webhook_url / alert_severity / enabled. "
                 "Member+, org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("repo_id", "path", "string", "Repo id.", True,
                   example="v_1a2b3c4d")],
     request_body=_body("Fields to update.",
                        {"branch": "develop", "enabled": True}),
     responses={
         "200": _resp("Updated repo row.",
                      {"id": "v_1a2b3c4d", "branch": "develop",
                       "enabled": True}),
         "400": _err400("Nothing to update"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Repo not found"),
         "429": _err429(),
     })

_doc("DELETE", "/api/vcs/repos/{repo_id}",
     tag="VCS",
     summary="Delete repo",
     description=("Remove the repo link and its notification history. Scans "
                  "stay (org audit data). Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("repo_id", "path", "string", "Repo id.", True,
                   example="v_1a2b3c4d")],
     request_body=None,
     responses={
         "200": _resp("Deletion receipt.",
                      {"repo_id": "v_1a2b3c4d", "deleted": True}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Repo not found"),
         "429": _err429(),
     })

_doc("POST", "/api/vcs/repos/{repo_id}/rotate-secret",
     tag="VCS",
     summary="Rotate webhook secret",
     description=("Issue a new webhook secret (shown once — update the "
                  "provider). Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("repo_id", "path", "string", "Repo id.", True,
                   example="v_1a2b3c4d")],
     request_body=None,
     responses={
         "200": _resp("New one-time secret.",
                      {"repo_id": "v_1a2b3c4d",
                       "webhook_secret": "whsec_1a2b3c4d5e6f",
                       "receiver_url": "https://api.braimsec.world/api/"
                                       "webhooks/github",
                       "warning": "Store this secret now — it will never be "
                                  "shown again."}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Repo not found"),
         "429": _err429(),
     })

# ============================ Webhooks (public receivers) ==================

_doc("POST", "/api/webhooks/github",
     tag="Webhooks",
     summary="GitHub push receiver",
     description=("Public receiver for GitHub push webhooks. Verified with "
                  "HMAC-SHA256 (X-Hub-Signature-256) against the repo's "
                  "secret. Non-push events, unknown repos, disabled repos, "
                  "unwatched branches and already-scanned commits are "
                  "acknowledged without scanning. Pushes to a watched branch "
                  "queue a scan (202)."),
     auth="public", min_role=None, org_scope=False, rate_limit="60/minute",
     params=[],
     request_body=_body("Raw GitHub push event JSON.",
                        {"ref": "refs/heads/main",
                         "after": "9f8e7d6c5b4a39281706f5e4d3c2b1a3f4e",
                         "repository": {"clone_url": "https://github.com/"
                                                    "acme/myapp.git"}},
                        content_type="application/json"),
     responses={
         "200": _resp("Acknowledged without scanning.",
                      {"ok": True, "ignored": "not a push event"}),
         "202": _resp("Scan queued.",
                      {"ok": True, "queued": True,
                       "commit": "9f8e7d6c5b4a"}),
         "400": _resp("Bad signature or invalid JSON.",
                      {"ok": False, "error": "invalid signature"}),
         "429": _err429(),
     })

_doc("POST", "/api/webhooks/gitlab",
     tag="Webhooks",
     summary="GitLab push receiver",
     description=("Public receiver for GitLab push webhooks. Verified with "
                  "the repo's token (X-Gitlab-Token). Same "
                  "acknowledge-or-queue semantics as the GitHub receiver."),
     auth="public", min_role=None, org_scope=False, rate_limit="60/minute",
     params=[],
     request_body=_body("Raw GitLab push event JSON.",
                        {"ref": "refs/heads/main",
                         "checkout_sha": "9f8e7d6c5b4a39281706f5e4d3c2b1a3f4e",
                         "project": {"git_http_url": "https://gitlab.com/"
                                                     "acme/myapp.git"}},
                        content_type="application/json"),
     responses={
         "200": _resp("Acknowledged without scanning.",
                      {"ok": True, "ignored": "not a push event"}),
         "202": _resp("Scan queued.",
                      {"ok": True, "queued": True,
                       "commit": "9f8e7d6c5b4a"}),
         "400": _resp("Bad token or invalid JSON.",
                      {"ok": False, "error": "invalid signature"}),
         "429": _err429(),
     })

_doc("POST", "/api/webhooks/nowpayments",
     tag="Webhooks",
     summary="NOWPayments IPN receiver",
     description=("Public by necessity (called by NOWPayments). Secured by "
                  "the HMAC-SHA512 signature in x-nowpayments-sig. Returns "
                  "200 on a valid signature even for ignored events so "
                  "NOWPayments stops retrying; 400 only on a bad signature."),
     auth="public", min_role=None, org_scope=False, rate_limit="600/minute",
     params=[],
     request_body=_body("NOWPayments IPN payload.",
                        {"payment_id": "1234567890",
                         "payment_status": "finished",
                         "order_id": "bs_pro_monthly_a1b2c3d4_org9",
                         "price_amount": 40, "price_currency": "usd"},
                        content_type="application/json"),
     responses={
         "200": _resp("IPN processed.",
                      {"ok": True, "verdict": "fulfilled",
                       "detail": "fulfilled"}),
         "400": _resp("Bad signature or bad JSON.",
                      {"ok": False, "error": "bad signature"}),
         "429": _err429(),
     })

# ============================ Alerts =======================================

_doc("GET", "/api/notifications",
     tag="Alerts",
     summary="Alert delivery log",
     description=("Newest-first alert deliveries for the org. Optional "
                  "filters: schedule_id, vcs_repo_id, report_schedule_id, "
                  "channel (webhook|email|telegram|slack|teams), event "
                  "(schedule.alert|schedule.failed|vcs.alert|vcs.failed|"
                  "cert.expiry|uptime.down|uptime.recovered), "
                  "status (sent|failed|skipped). Unknown filter values -> "
                  "400. limit clamped to 1..200. Viewer+, org scope."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[
         _param("schedule_id", "query", "string",
                "Filter by scan schedule.", False, example="s_1a2b3c4d"),
         _param("vcs_repo_id", "query", "string", "Filter by repo.", False,
                example="v_1a2b3c4d"),
         _param("report_schedule_id", "query", "string",
                "Filter by report schedule.", False, example="rs_1a2b3c4d"),
         _param("channel", "query", "string",
                "Filter by channel: webhook|email|telegram|slack|teams.",
                False, example="telegram"),
         _param("event", "query", "string",
                "Filter by event: schedule.alert|schedule.failed|vcs.alert|"
                "vcs.failed|cert.expiry|uptime.down|uptime.recovered.", False, example="schedule.alert"),
         _param("status", "query", "string",
                "Filter by status: sent|failed|skipped.", False,
                example="failed"),
         _param("limit", "query", "integer", "Max rows (1..200).", False,
                example=50),
     ],
     request_body=None,
     responses={
         "200": _resp("Array of notification rows.",
                      [{"id": 7, "channel": "webhook", "recipient": "https://"
                        "hooks.example/x", "status": "delivered",
                        "created_at": "2026-10-01T12:00:00+00:00"}]),
         "400": _err400("Unknown channel/event/status filter value"),
         "401": _err401(),
         "403": _err403(),
         "422": _err422(),
         "429": _err429(),
     })

_doc("POST", "/api/notifications/{notif_id}/resend",
     tag="Alerts",
     summary="Resend a failed notification",
     description=("Retries one failed delivery from the alert log. Webhook "
                  "rows replay their stored payload exactly (re-signed with "
                  "the org's current HMAC secret); telegram/email rows "
                  "rebuild the message from the same scan's findings. "
                  "Slack/Teams rows cannot be resent (masked destination) -> "
                  "409. Already-sent or skipped rows -> 409. Member+, org "
                  "scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[
         _param("notif_id", "path", "integer",
                "Notification row id.", True, example=7),
     ],
     request_body=None,
     responses={
         "200": _resp("Updated row summary.",
                      {"id": 7, "channel": "webhook", "status": "sent",
                       "attempts": 2, "error": None}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Notification"),
         "409": _err409("Notification already sent / not resendable"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/cert-domains",
     tag="Alerts",
     summary="List monitored TLS domains",
     description=("Hostnames registered for TLS expiry monitoring, with "
                  "their last check state (ok|expiring|error|never), "
                  "expiry date and days left. Viewer+, org scope."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of domain rows.",
                      [{"id": 1, "hostname": "example.com", "port": 443,
                        "warn_days": 14, "enabled": 1, "last_status": "ok",
                        "last_days_left": 89,
                        "last_expires_at": "2026-12-30T12:00:00+00:00"}]),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/cert-domains",
     tag="Alerts",
     summary="Register a TLS domain",
     description=("Register a hostname for expiry monitoring. The domain is "
                  "probed immediately so the caller sees its live state "
                  "(_live: ok|expiring|error). The beat worker re-probes "
                  "enabled domains ~daily; when the cert expires within "
                  "warn_days an alert fans out to every channel the org "
                  "configured (webhook URL on the domain, telegram chats, "
                  "slack/teams webhooks, email recipients) and is logged as "
                  "event=cert.expiry. Non-public resolved IPs are refused "
                  "(SSRF guard). Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[],
     request_body={
         "application/json": {
             "example": {"hostname": "example.com", "port": 443,
                         "warn_days": 14,
                         "webhook_url": "https://hooks.example/cert"}}},
     responses={
         "200": _resp("Created domain row with live probe state.",
                      {"id": 1, "hostname": "example.com", "port": 443,
                       "_live": {"status": "ok", "days_left": 89}}),
         "400": _err400("Invalid hostname / port / duplicate domain"),
         "401": _err401(),
         "403": _err403(),
         "422": _err422(),
         "429": _err429(),
     })

_doc("PATCH", "/api/cert-domains/{domain_id}",
     tag="Alerts",
     summary="Update a TLS domain",
     description=("Update warn_days (1..90), webhook_url or enabled for a "
                  "monitored domain. Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("domain_id", "path", "integer",
                "Cert domain row id.", True, example=1),
     ],
     request_body={
         "application/json": {
             "example": {"warn_days": 30, "enabled": False}}},
     responses={
         "200": _resp("Updated domain row.", {"id": 1, "warn_days": 30}),
         "400": _err400("Nothing to update / invalid warn_days"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Domain"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("DELETE", "/api/cert-domains/{domain_id}",
     tag="Alerts",
     summary="Stop monitoring a TLS domain",
     description=("Delete a monitored domain. Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("domain_id", "path", "integer",
                "Cert domain row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Deletion confirmation.", {"deleted": 1}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Domain"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("POST", "/api/cert-domains/{domain_id}/check",
     tag="Alerts",
     summary="Probe a TLS domain now",
     description=("Probe the domain's certificate immediately (member+). "
                  "The outcome is persisted and an alert fires if the "
                  "anti-spam rules allow it. Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[
         _param("domain_id", "path", "integer",
                "Cert domain row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Domain row with live probe state.",
                      {"id": 1, "hostname": "example.com",
                       "_live": {"status": "expiring", "days_left": 5}}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Domain"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/uptime-targets",
     tag="Alerts",
     summary="List uptime targets",
     description=("URL targets registered for uptime monitoring, with "
                  "their last check state (up|down|error|never), HTTP "
                  "status, latency and consecutive failures. Viewer+, org "
                  "scope."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of target rows.",
                      [{"id": 1, "hostname": "example.com", "port": 443,
                        "path": "/health", "use_https": 1,
                        "last_status": "up", "last_http_code": 200,
                        "last_latency_ms": 87}]),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/uptime-targets",
     tag="Alerts",
     summary="Register an uptime target",
     description=("Register a URL for uptime monitoring. The target is "
                  "probed immediately so the caller sees its live state "
                  "(_live: up|down|error). The beat worker re-probes "
                  "enabled targets at most every check_interval_s; a "
                  "target counts as down on probe errors, HTTP >= 500, a "
                  "status mismatch vs expected_status, or a missing "
                  "keyword. The uptime.down alert fires after 2 consecutive "
                  "failures (anti-flap) and uptime.recovered on the first "
                  "success after a down alert; both fan out to every "
                  "channel the org configured. latency_warn_ms (100.."
                  "120000, optional) raises uptime.slow (warning) when a "
                  "successful probe is slower than the threshold and "
                  "uptime.fast (info) on the first probe back under it. "
                  "Non-public resolved IPs are refused (SSRF guard). "
                  "Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[],
     request_body={
         "application/json": {
             "example": {"hostname": "example.com", "port": 443,
                         "path": "/health", "use_https": True,
                         "expected_status": 200, "keyword": "ok",
                         "check_interval_s": 300,
                         "latency_warn_ms": 2000,
                         "webhook_url": "https://hooks.example/up"}}},
     responses={
         "200": _resp("Created target row with live probe state.",
                      {"id": 1, "hostname": "example.com",
                       "_live": {"status": "up", "http_status": 200}}),
         "400": _err400("Invalid hostname / port / duplicate target"),
         "401": _err401(),
         "403": _err403(),
         "422": _err422(),
         "429": _err429(),
     })

_doc("PATCH", "/api/uptime-targets/{target_id}",
     tag="Alerts",
     summary="Update an uptime target",
     description=("Update keyword, expected_status (100..599, null "
                  "clears), check_interval_s (60..3600), webhook_url, "
                  "latency_warn_ms (100..120000, null clears) or enabled. "
                  "Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("target_id", "path", "integer",
                "Uptime target row id.", True, example=1),
     ],
     request_body={
         "application/json": {
             "example": {"keyword": "ok", "check_interval_s": 600}}},
     responses={
         "200": _resp("Updated target row.", {"id": 1, "keyword": "ok"}),
         "400": _err400("Nothing to update / invalid value"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Target"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("DELETE", "/api/uptime-targets/{target_id}",
     tag="Alerts",
     summary="Stop monitoring an uptime target",
     description=("Delete a monitored target. Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("target_id", "path", "integer",
                "Uptime target row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Deletion confirmation.", {"deleted": 1}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Target"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("POST", "/api/uptime-targets/{target_id}/check",
     tag="Alerts",
     summary="Probe an uptime target now",
     description=("Probe the target immediately (member+). The outcome is "
                  "persisted and down/recovered alerts fire per the rules. "
                  "Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[
         _param("target_id", "path", "integer",
                "Uptime target row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Target row with live probe state.",
                      {"id": 1, "hostname": "example.com",
                       "_live": {"status": "up", "http_status": 200}}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Target"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/status-pages",
     tag="Alerts",
     summary="List status pages",
     description=("This org's public status pages (viewer+, org scope)."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of status page rows.",
                      [{"id": 1, "title": "Acme status",
                        "slug": "acme", "enabled": 1}]),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/status-pages",
     tag="Alerts",
     summary="Publish a status page",
     description=("Publish a public status page served at /status/<slug> "
                  "(member+). Slugs are 3..60 chars, lowercase letters, "
                  "digits and hyphens, globally unique. The page shows the "
                  "org's uptime targets with 90-day bars, active incidents "
                  "and recent history."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[],
     request_body={
         "application/json": {
             "example": {"title": "Acme status", "slug": "acme",
                         "headline": "All systems operational",
                         "enabled": True}}},
     responses={
         "200": _resp("Created status page row.",
                      {"id": 1, "slug": "acme", "enabled": 1}),
         "400": _err400("Invalid slug / duplicate slug / missing title"),
         "401": _err401(),
         "403": _err403(),
         "422": _err422(),
         "429": _err429(),
     })

_doc("PATCH", "/api/status-pages/{page_id}",
     tag="Alerts",
     summary="Update a status page",
     description=("Update title, slug, headline or enabled (member+, org "
                  "scope)."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("page_id", "path", "integer",
                "Status page row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Updated status page row.",
                      {"id": 1, "slug": "acme", "enabled": 1}),
         "400": _err400("Invalid slug / duplicate slug"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Page"),
         "429": _err429(),
     })

_doc("DELETE", "/api/status-pages/{page_id}",
     tag="Alerts",
     summary="Delete a status page",
     description=("Delete a status page (member+, org scope)."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("page_id", "path", "integer",
                "Status page row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Deletion confirmation.", {"deleted": 1}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Page"),
         "429": _err429(),
     })

_doc("GET", "/api/incidents",
     tag="Alerts",
     summary="List incidents",
     description=("Incident log, newest first (viewer+, org scope). "
                  "Filter with ?status=open|investigating|identified|"
                  "monitoring|resolved and ?target_id=N."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[
         _param("status", "query", "string",
                "Status filter (or 'open').", False, example="open"),
         _param("target_id", "query", "integer",
                "Uptime target row id.", False, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Array of incident rows.",
                      [{"id": 1, "title": " outage",
                        "status": "investigating", "impact": "critical"}]),
         "400": _err400("Bad status filter"),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/incidents",
     tag="Alerts",
     summary="Open an incident",
     description=("Open an incident manually (member+). uptime.down "
                  "alerts also open incidents automatically, one per "
                  "target; uptime.recovered auto-resolves them."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[],
     request_body={
         "application/json": {
             "example": {"title": "DB failover", "status": "identified",
                         "impact": "major", "target_id": 1,
                         "public_visible": True,
                         "message": "Primary DB unreachable"}}},
     responses={
         "200": _resp("Created incident with its timeline.",
                      {"id": 1, "status": "identified", "updates": []}),
         "400": _err400("Invalid title / status / impact / target"),
         "401": _err401(),
         "403": _err403(),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/incidents/{incident_id}",
     tag="Alerts",
     summary="Get an incident",
     description=("One incident with its update timeline (viewer+, org "
                  "scope)."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[
         _param("incident_id", "path", "integer",
                "Incident row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Incident row with updates.",
                      {"id": 1, "status": "investigating",
                       "updates": [{"status": "investigating",
                                    "message": "..."}]}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Incident"),
         "429": _err429(),
     })

_doc("PATCH", "/api/incidents/{incident_id}",
     tag="Alerts",
     summary="Update an incident",
     description=("Update title, impact, public_visible or status "
                  "(member+, org scope). Setting status=resolved stamps "
                  "resolved_at; reopening clears it."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("incident_id", "path", "integer",
                "Incident row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Updated incident with timeline.",
                      {"id": 1, "status": "monitoring"}),
         "400": _err400("Invalid status / impact"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Incident"),
         "429": _err429(),
     })

_doc("POST", "/api/incidents/{incident_id}/updates",
     tag="Alerts",
     summary="Add an incident update",
     description=("Append a timeline update, optionally changing the "
                  "incident status (member+, org scope)."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("incident_id", "path", "integer",
                "Incident row id.", True, example=1),
     ],
     request_body={
         "application/json": {
             "example": {"message": "Failover complete, watching metrics",
                         "status": "monitoring"}}},
     responses={
         "200": _resp("Incident with updated timeline.",
                      {"id": 1, "updates": []}),
         "400": _err400("message or status is required"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Incident"),
         "429": _err429(),
     })

_doc("POST", "/api/incidents/{incident_id}/resolve",
     tag="Alerts",
     summary="Resolve an incident",
     description=("Resolve an incident with an optional closing message "
                  "(member+, org scope). Idempotent."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("incident_id", "path", "integer",
                "Incident row id.", True, example=1),
     ],
     request_body={
         "application/json": {
             "example": {"message": "All green for 30 minutes"}}},
     responses={
         "200": _resp("Resolved incident.", {"id": 1,
                                             "status": "resolved"}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Incident"),
         "429": _err429(),
     })

_doc("DELETE", "/api/incidents/{incident_id}",
     tag="Alerts",
     summary="Delete an incident",
     description=("Delete an incident and its timeline (member+, org "
                  "scope)."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("incident_id", "path", "integer",
                "Incident row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Deletion confirmation.", {"deleted": 1}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Incident"),
         "429": _err429(),
     })

_doc("GET", "/api/maintenance",
     tag="Alerts",
     summary="List maintenance windows",
     description=("Scheduled maintenance windows, active/upcoming first "
                  "(viewer+, org scope). ?include_past=1 adds completed "
                  "and cancelled windows."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[
         _param("include_past", "query", "string",
                "Include completed/cancelled windows.", False,
                example="1"),
     ],
     request_body=None,
     responses={
         "200": _resp("Array of window rows with derived status.",
                      [{"id": 1, "title": "DB upgrade",
                        "status": "scheduled"}]),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/maintenance",
     tag="Alerts",
     summary="Schedule a maintenance window",
     description=("Schedule a maintenance window (member+). While active, "
                  "uptime.down alerts for covered targets are suppressed "
                  "(logged, not sent) and no incident auto-opens; probes "
                  "and daily aggregates keep running. Empty target_ids "
                  "covers all targets. Max 30 days long."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[],
     request_body={
         "application/json": {
             "example": {"title": "DB upgrade",
                         "description": "Primary DB failover test",
                         "starts_at": "2026-10-03T02:00:00+00:00",
                         "ends_at": "2026-10-03T04:00:00+00:00",
                         "target_ids": []}}},
     responses={
         "200": _resp("Created window row.",
                      {"id": 1, "status": "scheduled"}),
         "400": _err400("ends_at before starts_at / bad target / too long"),
         "401": _err401(),
         "403": _err403(),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/maintenance/{window_id}",
     tag="Alerts",
     summary="Get a maintenance window",
     description=("One maintenance window with its derived status "
                  "(viewer+, org scope)."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[
         _param("window_id", "path", "integer",
                "Window row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Window row.", {"id": 1, "status": "active"}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Window"),
         "429": _err429(),
     })

_doc("PATCH", "/api/maintenance/{window_id}",
     tag="Alerts",
     summary="Edit a maintenance window",
     description=("Edit title, description, times or target scope — only "
                  "while the window is still scheduled (member+, org "
                  "scope)."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("window_id", "path", "integer",
                "Window row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Updated window row.", {"id": 1}),
         "400": _err400("Window already started / invalid times"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Window"),
         "429": _err429(),
     })

_doc("POST", "/api/maintenance/{window_id}/cancel",
     tag="Alerts",
     summary="Cancel a maintenance window",
     description=("Cancel a scheduled or active window (member+, org "
                  "scope). Alert suppression stops immediately."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("window_id", "path", "integer",
                "Window row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Cancelled window.", {"id": 1,
                                            "status": "cancelled"}),
         "400": _err400("Window already completed"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Window"),
         "429": _err429(),
     })

_doc("DELETE", "/api/maintenance/{window_id}",
     tag="Alerts",
     summary="Delete a maintenance window",
     description=("Delete a maintenance window (member+, org scope)."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[
         _param("window_id", "path", "integer",
                "Window row id.", True, example=1),
     ],
     request_body=None,
     responses={
         "200": _resp("Deletion confirmation.", {"deleted": 1}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Window"),
         "429": _err429(),
     })

_doc("GET", "/api/status/{slug}",
     tag="Alerts",
     summary="Public status page (JSON)",
     description=("Read-only public summary of an enabled status page: "
                  "overall state (operational|degraded|outage), targets "
                  "with 90-day uptime bars, TLS certificate states, "
                  "active and recent public incidents with timelines, "
                  "and active/upcoming maintenance windows. An expired "
                  "certificate counts as an outage. No authentication. "
                  "404 for unknown or disabled pages."),
     auth="public", min_role=None, org_scope=False, rate_limit="30/minute",
     params=[
         _param("slug", "path", "string",
                "Public page slug.", True, example="acme"),
     ],
     request_body=None,
     responses={
         "200": _resp("Public status summary.",
                      {"title": "Acme status", "overall": "operational",
                       "targets": [], "incidents": [], "maintenance": [],
                       "certificates": []}),
         "404": _err404("Status page"),
         "429": _err429(),
     })

_doc("GET", "/status/{slug}",
     tag="Alerts",
     summary="Public status page (HTML)",
     description=("Human-readable public status page (Arabic RTL): the "
                  "same data as /api/status/{slug} rendered as HTML. No "
                  "authentication. 404 for unknown or disabled pages."),
     auth="public", min_role=None, org_scope=False, rate_limit="600/minute",
     params=[
         _param("slug", "path", "string",
                "Public page slug.", True, example="acme"),
     ],
     request_body=None,
     responses={
         "200": _resp("HTML status page.", "<html>..."),
         "404": _err404("Status page"),
         "429": _err429(),
     })

_doc("GET", "/api/alert-emails",
     tag="Alerts",
     summary="List email recipients",
     description=("The org's email alert recipients, plus whether the server "
                  "has SMTP configured (without it, alerts are recorded as "
                  "skipped and never sent). Viewer+, org scope."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("SMTP state and recipient rows.",
                      {"smtp_configured": True,
                       "emails": [{"id": 3, "email": "ops@acme.com",
                                   "enabled": 1,
                                   "created_at":
                                   "2026-10-01T12:00:00+00:00"}]}),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/alert-emails",
     tag="Alerts",
     summary="Add email recipient",
     description="Register one recipient address. 409 when already "
                 "registered. Member+, org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[],
     request_body=_body("Recipient.", {"email": "ops@acme.com"}),
     responses={
         "200": _resp("Created recipient row.",
                      {"id": 3, "email": "ops@acme.com", "enabled": 1,
                       "created_at": "2026-10-01T12:00:00+00:00"}),
         "400": _err400("Invalid email address"),
         "401": _err401(),
         "403": _err403(),
         "409": _err409(),
         "429": _err429(),
     })

_doc("PATCH", "/api/alert-emails/{email_id}",
     tag="Alerts",
     summary="Enable/disable recipient",
     description="Toggle one recipient. Member+, org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("email_id", "path", "integer", "Recipient row id.", True,
                   example=3)],
     request_body=_body("Toggle.", {"enabled": False}),
     responses={
         "200": _resp("New state.",
                      {"id": 3, "enabled": False}),
         "400": _err400("enabled: required (true|false)"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Address not found"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("DELETE", "/api/alert-emails/{email_id}",
     tag="Alerts",
     summary="Remove email recipient",
     description="Remove one recipient address. Member+, org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("email_id", "path", "integer", "Recipient row id.", True,
                   example=3)],
     request_body=None,
     responses={
         "200": _resp("Deletion receipt.",
                      {"id": 3, "deleted": True}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Address not found"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/telegram-chats",
     tag="Alerts",
     summary="List telegram chats",
     description=("The org's telegram alert chats, plus whether the server "
                  "has a bot token configured (without it, alerts are "
                  "recorded as skipped). Viewer+, org scope."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Bot state and chat rows.",
                      {"telegram_configured": True,
                       "chats": [{"id": 2, "chat_id": "-1001234567890",
                                  "label": "security",
                                  "created_at":
                                  "2026-10-01T12:00:00+00:00"}]}),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/telegram-chats",
     tag="Alerts",
     summary="Register telegram chat",
     description="Register one telegram chat id for alerts. 409 when already "
                 "registered. Member+, org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[],
     request_body=_body("Chat registration.",
                        {"chat_id": "-1001234567890", "label": "security"}),
     responses={
         "200": _resp("Created chat row.",
                      {"id": 2, "chat_id": "-1001234567890",
                       "label": "security",
                       "created_at": "2026-10-01T12:00:00+00:00"}),
         "400": _err400("Invalid chat id"),
         "401": _err401(),
         "403": _err403(),
         "409": _err409("Chat already registered"),
         "429": _err429(),
     })

_doc("DELETE", "/api/telegram-chats/{chat_row_id}",
     tag="Alerts",
     summary="Remove telegram chat",
     description="Remove one registered chat. Member+, org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("chat_row_id", "path", "integer", "Chat row id.", True,
                   example=2)],
     request_body=None,
     responses={
         "200": _resp("Deletion receipt.",
                      {"id": 2, "deleted": True}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Chat not found"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/slack-webhooks",
     tag="Alerts",
     summary="List Slack webhooks",
     description=("The org's Slack alert webhooks. URLs are never returned — "
                  "only a masked tail (the secret is Fernet-encrypted at "
                  "rest). Viewer+, org scope."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Webhook rows (masked).",
                      {"webhooks": [
                          {"id": 3, "label": "#security",
                           "webhook_url_masked":
                           "https://hooks.slack.com/services/…a1b2c3",
                           "created_at": "2026-10-01T12:00:00+00:00"}]}),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/slack-webhooks",
     tag="Alerts",
     summary="Register Slack webhook",
     description=("Register one Slack incoming-webhook URL for alerts. The "
                  "URL must be on hooks.slack.com and is Fernet-encrypted "
                  "at rest, never returned. 409 when already registered. "
                  "Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[],
     request_body=_body(
         "Webhook registration.",
         {"webhook_url": "https://hooks.slack.com/services/T000/B000/xxxx",
          "label": "#security"}),
     responses={
         "200": _resp("Created webhook row (masked).",
                      {"id": 3, "label": "#security",
                       "webhook_url_masked":
                       "https://hooks.slack.com/services/…a1b2c3",
                       "created_at": "2026-10-01T12:00:00+00:00"}),
         "400": _err400("Invalid Slack webhook URL"),
         "401": _err401(),
         "403": _err403(),
         "409": _err409("Webhook already registered"),
         "429": _err429(),
     })

_doc("DELETE", "/api/slack-webhooks/{webhook_row_id}",
     tag="Alerts",
     summary="Remove Slack webhook",
     description="Remove one registered Slack webhook. Member+, org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("webhook_row_id", "path", "integer", "Webhook row id.",
                   True, example=3)],
     request_body=None,
     responses={
         "200": _resp("Deletion receipt.",
                      {"id": 3, "deleted": True}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Webhook not found"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/teams-webhooks",
     tag="Alerts",
     summary="List Teams webhooks",
     description=("The org's Microsoft Teams alert webhooks. URLs are never "
                  "returned — only a masked form (the secret is "
                  "Fernet-encrypted at rest). Viewer+, org scope."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Webhook rows (masked).",
                      {"webhooks": [
                          {"id": 4, "label": "Security",
                           "webhook_url_masked":
                           "https://outlook.office.com/…a1b2c3",
                           "created_at": "2026-10-01T12:00:00+00:00"}]}),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/teams-webhooks",
     tag="Alerts",
     summary="Register Teams webhook",
     description=("Register one Teams incoming-webhook URL for alerts. Only "
                  "*.office.com and *.logic.azure.com URLs are accepted. "
                  "The URL is Fernet-encrypted at rest, never returned. "
                  "409 when already registered. Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[],
     request_body=_body(
         "Webhook registration.",
         {"webhook_url": "https://outlook.office.com/webhook/…",
          "label": "Security"}),
     responses={
         "200": _resp("Created webhook row (masked).",
                      {"id": 4, "label": "Security",
                       "webhook_url_masked":
                       "https://outlook.office.com/…a1b2c3",
                       "created_at": "2026-10-01T12:00:00+00:00"}),
         "400": _err400("Invalid Teams webhook URL"),
         "401": _err401(),
         "403": _err403(),
         "409": _err409("Webhook already registered"),
         "429": _err429(),
     })

_doc("DELETE", "/api/teams-webhooks/{webhook_row_id}",
     tag="Alerts",
     summary="Remove Teams webhook",
     description="Remove one registered Teams webhook. Member+, org scope.",
     auth="key", min_role="member", org_scope=True, rate_limit="30/minute",
     params=[_param("webhook_row_id", "path", "integer", "Webhook row id.",
                   True, example=4)],
     request_body=None,
     responses={
         "200": _resp("Deletion receipt.",
                      {"id": 4, "deleted": True}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Webhook not found"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/webhook-signing",
     tag="Alerts",
     summary="Webhook signing status",
     description=("Whether this org has an HMAC-SHA256 signing secret for "
                  "outgoing scheduled/VCS alert webhooks. The secret itself "
                  "is never returned. When configured, every alert POST "
                  "carries `X-BraimSec-Signature: t=<ts>,v1=<hex>` (HMAC of "
                  "`\"<ts>.<raw_body>\"`) and `X-BraimSec-Timestamp`; "
                  "receivers should reject timestamps older than 5 minutes. "
                  "Viewer+, org scope."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Signing status.",
                      {"configured": True,
                       "created_at": "2026-10-02T12:00:00+00:00",
                       "scheme": "HMAC-SHA256",
                       "signature_header": "X-BraimSec-Signature",
                       "timestamp_header": "X-BraimSec-Timestamp",
                       "replay_tolerance_seconds": 300}),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/webhook-signing/rotate",
     tag="Alerts",
     summary="Rotate webhook signing secret",
     description=("Generate a new HMAC-SHA256 signing secret for the org's "
                  "outgoing alert webhooks. The secret is returned exactly "
                  "once — store it at the receiver; it is never retrievable "
                  "again. The previous secret stops working immediately. "
                  "Member+, org scope."),
     auth="key", min_role="member", org_scope=True, rate_limit="10/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("New secret (shown once).",
                      {"signing_secret": "whsec_…",
                       "warning": "Shown once — it will never be displayed "
                                  "again."}),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

# ============================ Keys =========================================

_doc("POST", "/api/keys",
     tag="Keys",
     summary="Create API key",
     description=("Provision a key for the org. Roles: viewer|member|admin|"
                  "owner; only an owner key may grant admin/owner. "
                  "project_id optionally scopes the key. The raw key is "
                  "returned ONCE and never stored. Admin+."),
     auth="key", min_role="admin", org_scope=False, rate_limit="30/minute",
     params=[],
     request_body=_body("Key spec.",
                        {"name": "CI runner", "role": "member",
                         "project_id": None}),
     responses={
         "200": _resp("One-time raw key.",
                      {"key": "bs_9f8e7d6c5b4a39281706f5e4d3c2b1a3f4e5d6c7b",
                       "key_prefix": "bs_9f8e7d",
                       "name": "CI runner", "role": "member",
                       "project_id": None,
                       "warning": "Store this key now — it will never be "
                                  "shown again."}),
         "400": _err400("Unknown role 'root' (expected one of "
                        "('viewer', 'member', 'admin', 'owner'))"),
         "401": _err401(),
         "403": _err403("Only an 'owner' key can grant 'admin'/'owner' roles"),
         "429": _err429(),
     })

_doc("GET", "/api/keys",
     tag="Keys",
     summary="List API keys",
     description=("The org's keys (prefixes, never hashes). Project-scoped "
                  "keys see only their own project's keys. Admin+."),
     auth="key", min_role="admin", org_scope=False, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of key rows.",
                      [{"id": "k_9f2ac41d", "key_prefix": "bs_9f8e7d",
                        "name": "CI runner", "role": "member",
                        "project_id": None,
                        "created_at": "2026-10-01T12:00:00+00:00",
                        "last_used_at": "2026-10-01T13:00:00+00:00",
                        "revoked": 0}]),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("DELETE", "/api/keys/{key_id}",
     tag="Keys",
     summary="Revoke API key",
     description=("Revoke a key. Cannot revoke the key in use. "
                  "Project-scoped keys stay inside their project. Admin+."),
     auth="key", min_role="admin", org_scope=False, rate_limit="30/minute",
     params=[_param("key_id", "path", "string", "Key id.", True,
                   example="k_9f2ac41d")],
     request_body=None,
     responses={
         "200": _resp("Revocation receipt.",
                      {"key_id": "k_9f2ac41d", "revoked": True}),
         "400": _err400("Cannot revoke the key you are calling with"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Key not found"),
         "429": _err429(),
     })

_doc("POST", "/api/keys/{key_id}/rotate",
     tag="Keys",
     summary="Rotate API key",
     description=("Atomically issue a replacement and revoke the old one — "
                  "no window with zero or two valid keys. A key may always "
                  "rotate itself; rotating another key needs admin+. The "
                  "raw replacement is returned ONCE. The env-configured "
                  "master key cannot be rotated here."),
     auth="key", min_role="viewer", org_scope=False, rate_limit="30/minute",
     params=[_param("key_id", "path", "string", "Key id.", True,
                   example="k_9f2ac41d")],
     request_body=None,
     responses={
         "200": _resp("One-time replacement key.",
                      {"key": "bs_1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b",
                       "key_id": "k_1a2b3c4d", "key_prefix": "bs_1a2b3c",
                       "rotated_from": "k_9f2ac41d",
                       "warning": "Store this key now — it will never be "
                                  "shown again."}),
         "400": _err400("Key is already revoked"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Key not found"),
         "429": _err429(),
     })

# ============================ Projects =====================================

_doc("POST", "/api/projects",
     tag="Projects",
     summary="Create project",
     description="Create a project inside the org. Project-scoped keys "
                 "cannot create projects. Admin+, org scope.",
     auth="key", min_role="admin", org_scope=True, rate_limit="30/minute",
     params=[],
     request_body=_body("Project spec.", {"name": "payments-api"}),
     responses={
         "200": _resp("Created project.",
                      {"project_id": "p_1234abcd", "name": "payments-api"}),
         "400": _err400("Project name must be 1-80 characters"),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("GET", "/api/projects",
     tag="Projects",
     summary="List projects",
     description="The caller's projects. A project-scoped key sees only its "
                 "own. Viewers may read.",
     auth="key", min_role="viewer", org_scope=False, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of project rows.",
                      [{"id": "p_1234abcd", "name": "payments-api",
                        "created_at": "2026-10-01T12:00:00+00:00"}]),
         "401": _err401(),
         "429": _err429(),
     })

_doc("DELETE", "/api/projects/{project_id}",
     tag="Projects",
     summary="Delete project",
     description=("Delete an empty project. Refuses while scans or active "
                  "keys still reference it — nothing is orphaned implicitly. "
                  "Admin+, org scope."),
     auth="key", min_role="admin", org_scope=True, rate_limit="30/minute",
     params=[_param("project_id", "path", "string", "Project id.", True,
                   example="p_1234abcd")],
     request_body=None,
     responses={
         "200": _resp("Deletion receipt.",
                      {"project_id": "p_1234abcd", "deleted": True}),
         "400": _err400("Project still has scans or active keys"),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Project not found"),
         "429": _err429(),
     })

# ============================ Audit ========================================

_doc("GET", "/api/audit-log",
     tag="Audit",
     summary="Audit trail",
     description=("Newest-first audit records for the org. Optional action "
                  "filter (e.g. scan.created). Project-scoped keys are "
                  "rejected — the trail covers the whole org."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="600/minute",
     params=[
         _param("limit", "query", "integer", "Max rows (1..200).", False,
                example=50),
         _param("offset", "query", "integer", "Skip rows.", False, example=0),
         _param("action", "query", "string", "Filter by action name.", False,
                example="scan.created"),
     ],
     request_body=None,
     responses={
         "200": _resp("Array of audit records.",
                      [{"id": 101, "action": "scan.created",
                        "resource_type": "scan",
                        "resource_id": "a1b2c3d4e5f6",
                        "actor": "bs_ab12cd34",
                        "detail": {"target": "myapp", "via": "upload"},
                        "created_at": "2026-10-01T12:00:00+00:00"}]),
         "401": _err401(),
         "403": _err403("Project-scoped keys cannot access org-level "
                        "resources"),
         "422": _err422(),
         "429": _err429(),
     })

_doc("GET", "/api/audit-log/export.csv",
     tag="Audit",
     summary="Audit trail as CSV",
     description=("CSV export of the org's audit trail for compliance "
                  "handoffs. Newest-first, up to 5,000 rows per export "
                  "(use archives for deeper history). Same visibility as "
                  "GET /api/audit-log: org-scoped, viewers may read; "
                  "project-scoped keys are rejected. `detail` is embedded "
                  "as a JSON string (RFC 4180 quoting). Downloads as "
                  "braimsec-audit-<org_id>.csv."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="10/minute",
     params=[
         _param("action", "query", "string", "Filter by action name.", False,
                example="scan.created"),
     ],
     request_body=None,
     responses={
         "200": _resp("CSV bytes.",
                      {"note": "binary text/csv; Content-Disposition: "
                               "attachment; filename="
                               "\"braimsec-audit-<org_id>.csv\""},
                      content_type="text/csv"),
         "401": _err401(),
         "403": _err403("Project-scoped keys cannot access org-level "
                        "resources"),
         "429": _err429(),
     })

_doc("POST", "/api/audit-log/archive",
     tag="Audit",
     summary="Archive audit log",
     description=("Move audit events older than N days into a gzipped, "
                  "sha256-manifested archive file. Owner-only: archiving "
                  "deletes audit history. Project-scoped keys are rejected. "
                  "409 when an archive run is already in progress."),
     auth="key", min_role="owner", org_scope=True, rate_limit="10/minute",
     params=[],
     request_body=_body("Archive options (all optional).",
                        {"older_than_days": 90}),
     responses={
         "200": _resp("Archive manifest.",
                      {"archive_id": "arc_20261001_120000",
                       "events": 1240,
                       "sha256": "9f8e7d6c5b4a39281706f5e4d3c2b1a3f4e5d6c"
                                 "7b8a9900112233445566778899001122"}),
         "400": _err400("older_than_days must be an integer"),
         "401": _err401(),
         "403": _err403(),
         "409": _err409("An archive run is already in progress"),
         "429": _err429(),
     })

_doc("GET", "/api/audit-log/archives",
     tag="Audit",
     summary="List audit archives",
     description="The org's audit archive manifests. Admin+, org scope.",
     auth="key", min_role="admin", org_scope=True, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of archive manifests.",
                      [{"archive_id": "arc_20261001_120000",
                        "events": 1240,
                        "sha256": "9f8e7d6c5b4a39...",
                        "created_at": "2026-10-01T12:00:00+00:00"}]),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("GET", "/api/audit-log/archives/{archive_id}/verify",
     tag="Audit",
     summary="Verify audit archive",
     description=("Re-hash an archive file against its manifest. A missing "
                  "file is reported as match:false with a reason, not an "
                  "exception. Admin+, org scope."),
     auth="key", min_role="admin", org_scope=True, rate_limit="60/minute",
     params=[_param("archive_id", "path", "string", "Archive id.", True,
                   example="arc_20261001_120000")],
     request_body=None,
     responses={
         "200": _resp("Verification outcome.",
                      {"archive_id": "arc_20261001_120000",
                       "match": True,
                       "sha256": "9f8e7d6c5b4a39..."}),
         "401": _err401(),
         "403": _err403(),
         "404": _err404("Archive not found"),
         "429": _err429(),
     })

# ============================ Billing & checkout ===========================

_doc("GET", "/api/plans",
     tag="Billing",
     summary="Plan catalog",
     description="Public plan catalog with quotas and prices for the "
                 "marketing/pricing page. No auth.",
     auth="public", min_role=None, org_scope=False, rate_limit="600/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Array of plans.",
                      [{"plan_id": "pro", "plan_name": "Pro",
                        "monthly_price_cents": 4000,
                        "price_display": "$40/mo",
                        "scan_quota": 200, "ai_review_quota": 500,
                        "max_projects": 10, "max_seats": 5,
                        "features": ["sso", "sla"]}]),
         "429": _err429(),
     })

_doc("GET", "/api/health",
     tag="Billing",
     summary="Health probe",
     description=("Public liveness/readiness probe for load balancers. No "
                  "auth by design; reveals only component statuses, never "
                  "secrets. 200 = healthy, 503 = degraded."),
     auth="public", min_role=None, org_scope=False, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Component statuses.",
                      {"status": "ok",
                       "checks": {"database": "ok",
                                  "broker": "inline-mode"}}),
         "429": _err429(),
         "503": _resp("Degraded.",
                      {"status": "degraded",
                       "checks": {"database": "error: OperationalError",
                                  "broker": "inline-mode"}}),
     })

_doc("GET", "/api/subscription",
     tag="Billing",
     summary="Current subscription",
     description=("The org's subscription: plan, status, billing period, "
                  "and quotas in force. Org scope (project-scoped keys "
                  "rejected)."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="600/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Subscription detail.",
                      {"plan_id": "pro", "plan_name": "Pro",
                       "status": "active",
                       "current_period_start": "2026-10-01T00:00:00+00:00",
                       "current_period_end": "2026-11-01T00:00:00+00:00",
                       "trial_ends_at": None,
                       "quotas": {"scans": 200, "ai_reviews": 500},
                       "limits": {"max_projects": 10, "max_seats": 5},
                       "features": ["sso"]}),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("GET", "/api/usage",
     tag="Billing",
     summary="Usage vs quota",
     description=("Current month's consumption vs quota (scan, ai_review). "
                  "Quotas never roll over. Org scope."),
     auth="key", min_role="viewer", org_scope=True, rate_limit="600/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("Usage rows.",
                      {"scans": {"used": 12, "quota": 200,
                                 "remaining": 188, "unlimited": False},
                       "ai_reviews": {"used": 30, "quota": 500,
                                      "remaining": 470,
                                      "unlimited": False}}),
         "401": _err401(),
         "403": _err403(),
         "429": _err429(),
     })

_doc("POST", "/api/checkout/crypto",
     tag="Billing",
     summary="Crypto checkout",
     description=("Create a hosted NOWPayments invoice (USDT). Public — new "
                  "customers have no API key yet. A fresh API key is "
                  "provisioned for NEW orgs and returned once (shown before "
                  "payment; it works on the free tier until the IPN upgrades "
                  "the plan). Renewals (same email) get api_key:null. 503 "
                  "when crypto checkout is not configured on the server."),
     auth="public", min_role=None, org_scope=False, rate_limit="10/minute",
     params=[],
     request_body=_body("Checkout request.",
                        {"tier": "pro", "cycle": "monthly",
                         "email": "buyer@acme.com"}),
     responses={
         "200": _resp("Invoice + one-time key for new orgs.",
                      {"invoice_url": "https://nowpayments.io/payment/"
                                      "?iid=1234567890",
                       "invoice_id": "1234567890",
                       "order_id": "bs_pro_monthly_a1b2c3d4_org9",
                       "amount_usd": 40, "pay_currency": "usdtbsc",
                       "api_key": "bs_9f8e7d6c5b4a39281706f5e4d3c2b1a3f4e"
                                  "5d6c7b",
                       "key_note": "Save this API key now — it is shown "
                                   "only once."}),
         "400": _err400("Unknown tier/cycle"),
         "429": _err429(),
         "502": _err502(),
         "503": _err503("Crypto checkout is not configured yet"),
     })

_doc("GET", "/api/checkout/status",
     tag="Billing",
     summary="Order status",
     description=("Public order status for the success page. Keyed by the "
                  "unguessable order_id; reveals only that order's own state."),
     auth="public", min_role=None, org_scope=False, rate_limit="30/minute",
     params=[_param("order_id", "query", "string", "Order id from checkout.",
                   True, example="bs_pro_monthly_a1b2c3d4_org9")],
     request_body=None,
     responses={
         "200": _resp("Order + subscription state.",
                      {"order_id": "bs_pro_monthly_a1b2c3d4_org9",
                       "pay_status": "fulfilled", "tier": "pro",
                       "cycle": "monthly", "amount_usd": 40,
                       "plan": "pro", "subscription": "active",
                       "period_end": "2026-11-01T00:00:00+00:00"}),
         "404": _err404("Unknown order"),
         "429": _err429(),
     })

_doc("GET", "/checkout/success",
     tag="Billing",
     summary="Payment landing page",
     description=("Post-payment HTML landing page. NOWPayments redirects "
                  "here with ?order_id=...; the page polls "
                  "/api/checkout/status and shows the activation state. "
                  "No auth."),
     auth="public", min_role=None, org_scope=False, rate_limit="600/minute",
     params=[_param("order_id", "query", "string", "Order id.", False,
                   example="bs_pro_monthly_a1b2c3d4_org9")],
     request_body=None,
     responses={
         "200": _resp("HTML page.", {"note": "text/html landing page"},
                      content_type="text/html"),
         "429": _err429(),
     })

# ============================ API documentation itself =====================

_doc("GET", "/api/openapi.json",
     tag="Docs",
     summary="OpenAPI document",
     description=("This OpenAPI 3.1 document, generated deterministically "
                  "from the live application routes. Public — for "
                  "documentation and third-party integrations. The document "
                  "fails closed: any route missing from the docs registry "
                  "raises at build time instead of shipping undocumented."),
     auth="public", min_role=None, org_scope=False, rate_limit="60/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("The OpenAPI 3.1 document.",
                      {"openapi": "3.1.0",
                       "info": {"title": "BraimSec API",
                                "version": "0.1.0"},
                       "paths": {"/api/health": {}}},
                      content_type="application/json"),
         "429": _err429(),
         "500": _resp("Docs registry out of sync with routes.",
                      {"detail": "undocumented route: POST /api/new-thing"}),
     })

_doc("GET", "/docs",
     tag="Docs",
     summary="API documentation page",
     description=("Human-readable API reference: searchable endpoint list "
                  "grouped by tag, parameters, request/response examples, "
                  "auth and rate-limit notes, and copy-as-cURL snippets. "
                  "Self-contained — no external CDN, works offline. "
                  "No auth."),
     auth="public", min_role=None, org_scope=False, rate_limit="600/minute",
     params=[],
     request_body=None,
     responses={
         "200": _resp("HTML documentation page.",
                      {"note": "text/html reference page"},
                      content_type="text/html"),
         "429": _err429(),
     })

# ---------------------------------------------------------------------------
# Spec builder
# ---------------------------------------------------------------------------

def _live_routes(app) -> set[tuple[str, str]]:
    """(method, path) pairs actually registered on the app.

    Only concrete API routes; HEAD/OPTIONS are transport noise, not
    documented operations. The dashboard StaticFiles mount is not an
    APIRoute and is ignored.
    """
    from fastapi.routing import APIRoute  # local import: no fastapi at module import time in tests that stub it
    out: set[tuple[str, str]] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        methods = set(route.methods or ()) - {"HEAD", "OPTIONS"}
        for m in methods:
            out.add((m, route.path))
    return out


def _operation(entry: dict) -> dict:
    """Build one OpenAPI operation object from a registry entry."""
    op: dict = {
        "tags": [entry["tag"]],
        "summary": entry["summary"],
        "description": entry["description"],
    }
    if entry["auth"] == "key":
        op["security"] = [{"ApiKeyAuth": []}]
    else:
        op["security"] = []
    # Honest, machine-readable access metadata as extensions.
    op["x-auth"] = entry["auth"]
    if entry["min_role"]:
        op["x-min-role"] = entry["min_role"]
    op["x-org-scope"] = bool(entry["org_scope"])
    op["x-rate-limit"] = entry["rate_limit"]
    if entry["params"]:
        op["parameters"] = entry["params"]
    if entry.get("request_body"):
        op["requestBody"] = entry["request_body"]
    op["responses"] = {str(code): resp
                       for code, resp in entry["responses"].items()}
    return op


def build_openapi_spec(app) -> dict:
    """Build the OpenAPI 3.1 document from the live app routes.

    Fail-closed: every registered route must have a DOCS entry
    (undocumented endpoint -> OpenAPIError), and every DOCS entry must
    map to a registered route (stale entry -> OpenAPIError).
    """
    live = _live_routes(app)
    documented = set(DOCS)
    missing = sorted(live - documented)
    if missing:
        raise OpenAPIError(
            "undocumented routes: " +
            ", ".join(f"{m} {p}" for m, p in missing))
    stale = sorted(documented - live)
    if stale:
        raise OpenAPIError(
            "stale docs entries (no such route): " +
            ", ".join(f"{m} {p}" for m, p in stale))

    paths: dict = {}
    for method, path in sorted(live):
        paths.setdefault(path, {})[method.lower()] = _operation(
            DOCS[(method, path)])

    tags_seen: list[str] = []
    for (_m, _p), entry in sorted(DOCS.items()):
        if entry["tag"] not in tags_seen:
            tags_seen.append(entry["tag"])

    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": API_TITLE,
            "version": API_VERSION,
            "description": (
                "BraimSec — API security scanning as a service. "
                "All /api/* endpoints except the documented public ones "
                "require the X-API-Key header. Roles rank "
                "viewer < member < admin < owner; some endpoints additionally "
                "reject project-scoped keys (x-org-scope). Rate limits are "
                "per minute, keyed by API key prefix (or client IP for "
                "public endpoints)."
            ),
            "contact": {"name": "BraimSec support",
                        "email": "support@braimsec.world"},
        },
        "servers": [{"url": "https://api.braimsec.world",
                     "description": "Production"},
                    {"url": "http://127.0.0.1:8000",
                     "description": "Local development"}],
        "tags": [{"name": t} for t in tags_seen],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": ("Per-customer API key (shown once at "
                                    "creation) or the master key. Never in "
                                    "URLs."),
                }
            },
        },
    }


def spec_to_json(app=None, spec: dict | None = None) -> bytes:
    """Canonical JSON bytes of the spec (sorted keys — byte-deterministic)."""
    if spec is None:
        if app is None:
            raise OpenAPIError("spec_to_json needs app or spec")
        spec = build_openapi_spec(app)
    return json.dumps(spec, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Human-readable docs page (GET /docs).
#
# Self-contained single HTML file: no CDN, no external fonts, no build
# step — it fetches /api/openapi.json and renders it client-side. This
# keeps the docs usable offline / in air-gapped deployments, matching the
# project's no-CDN convention (the dashboard trends chart is CDN-free
# too). Swagger UI was considered and rejected for the same reason.
# ---------------------------------------------------------------------------

def docs_page_html() -> str:
    """Return the /docs HTML page."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BraimSec API — Documentation</title>
<style>
:root{--bg:#0b1020;--panel:#131a30;--line:#24304f;--txt:#e8ecf4;
--dim:#9aa6c2;--get:#22c55e;--post:#3b82f6;--patch:#f59e0b;--del:#ef4444}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
font-family:system-ui,-apple-system,"Segoe UI",sans-serif;font-size:14px}
header{padding:28px 32px;border-bottom:1px solid var(--line)}
header h1{margin:0 0 8px;font-size:24px}
header p{margin:6px 0;color:var(--dim);max-width:900px;line-height:1.6}
code{background:#0b1020;border:1px solid var(--line);border-radius:6px;
padding:1px 7px;font-size:12.5px}
.layout{display:flex;min-height:calc(100vh - 130px)}
nav{width:300px;flex-shrink:0;border-right:1px solid var(--line);
padding:16px;overflow-y:auto;position:sticky;top:0;max-height:calc(100vh - 130px)}
nav input{width:100%;padding:8px 10px;border-radius:8px;border:1px solid var(--line);
background:#0b1020;color:var(--txt);margin-bottom:12px}
nav h3{font-size:12px;color:var(--dim);text-transform:uppercase;
letter-spacing:.08em;margin:14px 0 6px}
nav a{display:flex;gap:8px;align-items:center;padding:6px 8px;border-radius:6px;
color:var(--txt);text-decoration:none;font-size:13px}
nav a:hover{background:#1a2340}
nav a .path{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
main{flex:1;padding:24px 32px;max-width:1000px}
.badge{font-size:11px;font-weight:700;border-radius:5px;padding:2px 8px;
color:#04121f;flex-shrink:0}
.badge.get{background:var(--get)}.badge.post{background:var(--post)}
.badge.patch{background:var(--patch)}.badge.delete{background:var(--del)}
section.ep{background:var(--panel);border:1px solid var(--line);
border-radius:12px;padding:20px 22px;margin-bottom:18px}
section.ep h2{margin:0 0 4px;font-size:16px;display:flex;gap:10px;align-items:center}
section.ep h2 .p{font-family:ui-monospace,monospace;font-size:14px}
.meta{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.meta span{font-size:12px;background:#0b1020;border:1px solid var(--line);
border-radius:20px;padding:3px 12px;color:var(--dim)}
.meta span b{color:var(--txt)}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px}
pre{background:#0b1020;border:1px solid var(--line);border-radius:8px;
padding:12px 14px;overflow-x:auto;font-size:12.5px;line-height:1.55;position:relative}
pre code{background:none;border:none;padding:0}
.curlbtn{position:absolute;top:8px;right:8px;background:#1a2340;color:var(--txt);
border:1px solid var(--line);border-radius:6px;padding:4px 10px;font-size:12px;
cursor:pointer}
.curlbtn:hover{background:#24304f}
h4{margin:18px 0 6px;font-size:13px;color:var(--dim)}
.respcode{font-family:ui-monospace,monospace;font-weight:700}
.r2xx{color:var(--get)}.r4xx{color:var(--patch)}.r5xx{color:var(--del)}
.hide{display:none}
footer{padding:20px 32px;color:var(--dim);font-size:12px;
border-top:1px solid var(--line)}
</style>
</head>
<body>
<header>
<h1>🛡️ BraimSec API</h1>
<p><b>Base URL:</b> <code>https://api.braimsec.world</code> &nbsp;·&nbsp;
<b>Auth:</b> every <code>/api/*</code> endpoint except the ones tagged
<b>public</b> needs the <code>X-API-Key</code> header.
Roles rank <code>viewer &lt; member &lt; admin &lt; owner</code>.
Rate limits are per minute, keyed by API key (or client IP for public
endpoints) — slow down when you see <code>429</code> and honor
<code>Retry-After</code>.</p>
<p style="font-size:12px">Machine-readable spec: <code>GET /api/openapi.json</code>
(OpenAPI 3.1). Found a mismatch between these docs and the API?
<a href="mailto:support@braimsec.world" style="color:#7db4ff">Tell us</a>.</p>
</header>
<div class="layout">
<nav id="sidenav"><input id="q" type="search" placeholder="Filter endpoints…">
<div id="navlist"></div></nav>
<main id="content"><p style="color:var(--dim)">Loading API reference…</p></main>
</div>
<footer>BraimSec API <span id="ver"></span> · generated from the live application —
it cannot go stale.</footer>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",
">":"&gt;",'"':"&quot;"}[c]));
const pretty=o=>esc(JSON.stringify(o,null,2));
function curlFor(method,path,op){
  let cmd=`curl -X ${method} "https://api.braimsec.world${path}"`;
  const needsKey=(op.security||[]).some(s=>s.ApiKeyAuth!==undefined);
  if(needsKey) cmd+=' -H "X-API-Key: YOUR_API_KEY"';
  const body=op.requestBody;
  if(body&&method!=="GET"){
    const ct=Object.keys(body.content||{})[0]||"application/json";
    const ex=(body.content[ct]||{}).example;
    cmd+=` -H "Content-Type: ${ct}"`;
    if(ex!==undefined) cmd+=` -d '${JSON.stringify(ex).replace(/'/g,"'\\''")}'`;
  }
  return cmd;
}
function paramTable(params){
  if(!params||!params.length) return "<p style='color:var(--dim)'>None.</p>";
  let h="<table><tr><th>Name</th><th>In</th><th>Type</th><th>Required</th>"
  +"<th>Description</th></tr>";
  for(const p of params){
    const t=(p.schema&&p.schema.type)||"";
    const en=(p.schema&&p.schema.enum)?"<br><code>"+p.schema.enum.join(" | ")
    +"</code>":"";
    h+=`<tr><td><code>${esc(p.name)}</code></td><td>${esc(p.in)}</td>`
    +`<td>${esc(t)}${en}</td><td>${p.required?"yes":"no"}</td>`
    +`<td>${esc(p.description||"")}${p.example!==undefined
    ?'<br>eg. <code>'+esc(JSON.stringify(p.example))+'</code>':""}</td></tr>`;
  }
  return h+"</table>";
}
function responses(op){
  let h="";
  const codes=Object.keys(op.responses||{}).sort();
  for(const c of codes){
    const r=op.responses[c];
    const cls=c.startsWith("2")?"r2xx":c.startsWith("4")?"r4xx":"r5xx";
    h+=`<h4><span class="respcode ${cls}">${esc(c)}</span> — ${esc(r.description||"")}</h4>`;
    const ct=Object.keys((r.content||{}))[0];
    if(ct){
      const ex=r.content[ct].example;
      if(ex!==undefined) h+=`<pre><code>${pretty(ex)}</code></pre>`;
      else h+=`<p style="color:var(--dim)">${esc(ct)}</p>`;
    }
  }
  return h;
}
function render(spec){
  $("#ver").textContent="v"+((spec.info||{}).version||"");
  const paths=spec.paths||{};
  const byTag={};
  for(const [path,item] of Object.entries(paths)){
    for(const [method,op] of Object.entries(item)){
      const t=(op.tags||["Other"])[0];
      (byTag[t]=byTag[t]||[]).push({path,method:method.toUpperCase(),op,
        id:method+":"+path});
    }
  }
  const tags=Object.keys(byTag).sort();
  let nav="";
  for(const t of tags){
    nav+=`<h3>${esc(t)}</h3>`;
    for(const e of byTag[t])
      nav+=`<a href="#${esc(e.id)}" data-id="${esc(e.id)}">`
      +`<span class="badge ${e.method.toLowerCase()}">${e.method}</span>`
      +`<span class="path">${esc(e.path)}</span></a>`;
  }
  $("#navlist").innerHTML=nav;
  let main="";
  for(const t of tags){
    main+=`<h3 style="font-size:12px;color:var(--dim);text-transform:uppercase;`
    +`letter-spacing:.08em;margin:26px 0 10px">${esc(t)}</h3>`;
    for(const e of byTag[t]){
      const op=e.op;
      const auth=(op["x-auth"]==="public")
        ?"<span>🌐 <b>public</b> — no key needed</span>"
        :`<span>🔑 <b>key</b>${op["x-min-role"]?" · role ≥ <b>"
          +esc(op["x-min-role"])+"</b>":""}${op["x-org-scope"]
          ?" · <b>org scope</b> (project keys rejected)":""}</span>`;
      main+=`<section class="ep" id="${esc(e.id)}" data-id="${esc(e.id)}">`
      +`<h2><span class="badge ${e.method.toLowerCase()}">${e.method}</span>`
      +`<span class="p">${esc(e.path)}</span></h2>`
      +`<p style="color:var(--dim)"><b style="color:var(--txt)">`
      +`${esc(op.summary||"")}</b><br>${esc(op.description||"")}</p>`
      +`<div class="meta">${auth}<span>⏱ <b>${esc(op["x-rate-limit"]
        ||"600/minute")}</b> / minute</span></div>`
      +`<h4>Parameters</h4>${paramTable(op.parameters)}`;
      const body=op.requestBody;
      if(body){
        const ct=Object.keys(body.content||{})[0];
        const ex=ct?body.content[ct].example:undefined;
        main+=`<h4>Request body <span style="font-weight:400">(${esc(ct||"")}
        </span></h4><p style="color:var(--dim)">${esc(body.description||"")}</p>`;
        if(ex!==undefined) main+=`<pre><code>${pretty(ex)}</code></pre>`;
      }
      main+=`<h4>Responses</h4>${responses(op)}`;
      main+=`<h4>cURL</h4><pre><button class="curlbtn" data-curl="${esc(
        btoa(unescape(encodeURIComponent(curlFor(e.method,e.path,op))))
        )}">copy</button><code>${esc(curlFor(e.method,e.path,op))}</code></pre>`;
      main+=`</section>`;
    }
  }
  $("#content").innerHTML=main;
  document.querySelectorAll(".curlbtn").forEach(b=>b.onclick=()=>{
    navigator.clipboard.writeText(decodeURIComponent(escape(atob(
      b.dataset.curl)))).then(()=>{b.textContent="copied ✓";
      setTimeout(()=>b.textContent="copy",1500);});
  });
  $("#q").oninput=ev=>{
    const q=ev.target.value.trim().toLowerCase();
    document.querySelectorAll("section.ep").forEach(s=>{
      s.classList.toggle("hide",
        q&&!s.dataset.id.toLowerCase().includes(q)
          &&!s.textContent.toLowerCase().includes(q));
    });
    document.querySelectorAll("#navlist a").forEach(a=>{
      const sec=document.querySelector(
        `section.ep[data-id="${CSS.escape(a.dataset.id)}"]`);
      a.style.display=(!q||!sec.classList.contains("hide"))?"":"none";
    });
  };
}
fetch("/api/openapi.json").then(r=>{if(!r.ok)throw new Error(r.status);
return r.json();}).then(render).catch(e=>{
  $("#content").innerHTML="<p style='color:#ef4444'>Could not load "
  +"/api/openapi.json ("+esc(e.message)+").</p>";});
</script>
</body>
</html>"""
