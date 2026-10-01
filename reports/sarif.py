"""SARIF 2.1.0 export for BraimSec scan results.

Deterministic builder: the same findings always produce the same document
bytes (rules/fingerprints are content-derived, no timestamps inside).
The output is accepted by GitHub code scanning (upload-sarif) and any
other SARIF 2.1.0 consumer.

Finding identity (fingerprints) intentionally matches the alerting path:
``tool|rule_id|file|message`` — line/column insensitive, so a result keeps
its identity when code shifts around it.
"""

import hashlib

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

#: Generator version of this exporter (bumped when the emitted shape changes).
SARIF_EXPORT_VERSION = "1.0.0"

#: SARIF `level` values we emit. Unknown engine severities fall back to
#: "warning" (conservative: visible, never silently dropped to "none").
VALID_LEVELS = ("none", "note", "warning", "error")

_INFORMATION_URI = "https://braimsec.world"


class SarifError(Exception):
    """Raised when a SARIF document fails structural validation."""


def _engine_version():
    try:
        from scan_engine import ENGINE_VERSION  # noqa: PLC0415
        return ENGINE_VERSION
    except Exception:
        return "0.1.0"


def _default_compliance_lookup(rule_id, tool):
    try:
        from builder import lookup_compliance  # noqa: PLC0415
        return lookup_compliance(rule_id, tool)
    except Exception:
        return None


def _cwe_help_uri(cwe_id):
    """'CWE-918' -> the canonical MITRE definition page (None if unusable)."""
    if not cwe_id:
        return None
    num = str(cwe_id).upper().replace("CWE-", "").strip()
    if not num.isdigit():
        return None
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def finding_fingerprint(tool, rule_id, file, message):
    """Stable 32-hex identity for a finding (line/column insensitive)."""
    blob = f"{tool}|{rule_id}|{file}|{message}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:32]


def _level(severity):
    sev = str(severity or "").lower()
    return sev if sev in VALID_LEVELS else "warning"


def _pos(value):
    """SARIF regions are 1-based; coerce missing/garbage to 1 (fail-safe)."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 1
    return v if v >= 1 else 1


def build_sarif(findings, scan_id=None, target_name=None, tool_version=None,
                compliance_lookup=None):
    """Build a SARIF 2.1.0 document from normalized BraimSec findings.

    ``findings``: list of dicts with ``tool``, ``rule_id``, ``severity``,
    ``message``, ``file``, ``line``, ``col``.
    """
    if tool_version is None:
        tool_version = _engine_version()
    if compliance_lookup is None:
        compliance_lookup = _default_compliance_lookup

    rules = {}
    rule_index = {}
    results = []

    for f in findings:
        tool = f.get("tool") or "unknown"
        rule_id = f.get("rule_id") or "unknown"
        key = f"{tool}/{rule_id}"
        if key not in rules:
            rule_index[key] = len(rules)
            short = str(f.get("message") or rule_id)[:200]
            rule = {
                "id": key,
                "name": str(rule_id),
                "shortDescription": {"text": short},
            }
            try:
                comp = compliance_lookup(rule_id, tool) or {}
                cwe = (comp.get("cwe") or {}).get("id")
                uri = _cwe_help_uri(cwe)
                if uri:
                    rule["helpUri"] = uri
            except Exception:
                pass  # compliance data is decorative; never break the export
            rules[key] = rule

        message = str(f.get("message") or "")
        file = str(f.get("file") or "")
        results.append({
            "ruleId": key,
            "ruleIndex": rule_index[key],
            "level": _level(f.get("severity")),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {
                        "startLine": _pos(f.get("line")),
                        "startColumn": _pos(f.get("col")),
                    },
                },
            }],
            "fingerprints": {
                "braimsec/v1": finding_fingerprint(tool, rule_id, file,
                                                   message),
            },
        })

    run = {
        "tool": {
            "driver": {
                "name": "BraimSec",
                "fullName": "BraimSec Scanner",
                "version": str(tool_version),
                "informationUri": _INFORMATION_URI,
                "rules": list(rules.values()),
            },
        },
        "results": results,
    }
    if scan_id:
        run["automationDetails"] = {"id": f"braimsec/{scan_id}"}
        if target_name:
            run["automationDetails"]["description"] = {
                "text": f"BraimSec scan of {target_name}"
            }

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def validate_sarif(doc):
    """Structural validation of a SARIF 2.1.0 document.

    Returns True; raises SarifError describing the first violation.
    This checks the shape GitHub's upload-sarif cares about — it is not a
    full JSON-Schema validation (no network dependency).
    """
    def bad(msg):
        raise SarifError(msg)

    if not isinstance(doc, dict):
        bad("document must be an object")
    if doc.get("$schema") != SARIF_SCHEMA:
        bad(f"$schema must be {SARIF_SCHEMA}")
    if doc.get("version") != SARIF_VERSION:
        bad('version must be "2.1.0"')

    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        bad("runs must be a non-empty array")
    for i, run in enumerate(runs):
        if not isinstance(run, dict):
            bad(f"runs[{i}] must be an object")
        driver = ((run.get("tool") or {}).get("driver") or {})
        if not driver.get("name"):
            bad(f"runs[{i}].tool.driver.name is required")
        rules = driver.get("rules", [])
        if not isinstance(rules, list):
            bad(f"runs[{i}].tool.driver.rules must be an array")
        for j, rule in enumerate(rules):
            if not isinstance(rule, dict) or not rule.get("id"):
                bad(f"runs[{i}].tool.driver.rules[{j}].id is required")
        results = run.get("results")
        if not isinstance(results, list):
            bad(f"runs[{i}].results must be an array")
        for j, res in enumerate(results):
            where = f"runs[{i}].results[{j}]"
            if not isinstance(res, dict):
                bad(f"{where} must be an object")
            if not res.get("ruleId"):
                bad(f"{where}.ruleId is required")
            if res.get("level") not in VALID_LEVELS:
                bad(f"{where}.level must be one of {VALID_LEVELS}")
            msg = res.get("message") or {}
            if not msg.get("text"):
                bad(f"{where}.message.text is required")
            locs = res.get("locations")
            if not isinstance(locs, list) or not locs:
                bad(f"{where}.locations must be a non-empty array")
            phys = (locs[0] or {}).get("physicalLocation") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri")
            if not uri:
                bad(f"{where}.locations[0].physicalLocation."
                    "artifactLocation.uri is required")
            region = phys.get("region") or {}
            line = region.get("startLine")
            if not isinstance(line, int) or line < 1:
                bad(f"{where}.locations[0].physicalLocation.region."
                    "startLine must be an integer >= 1")
    return True
