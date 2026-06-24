"""
tools/sarif.py — SARIF 2.1.0 output generation.

Pure function: findings_to_sarif(findings) -> dict

Converts the vulnscan-agent finding format into a valid SARIF 2.1.0 document
suitable for GitHub code scanning upload.

Severity → SARIF level mapping:
  CRITICAL / HIGH → "error"
  MEDIUM          → "warning"
  LOW             → "note"

This module has NO side effects and NO I/O. Callers are responsible for
writing the dict to disk (json.dump). All errors are signalled via ValueError
so callers can catch and log without crashing the scan.
"""
from __future__ import annotations

import re
from typing import Any

# SARIF 2.1.0 schema URI (informational; parsers may validate against it)
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

# Fallback level when severity is unrecognised
_DEFAULT_LEVEL = "note"


def _parse_start_line(lines: str) -> int:
    """
    Extract the first integer from a lines string such as "42", "42-45", "L42".

    Returns 1 if no integer can be parsed (SARIF requires line >= 1).
    """
    if not lines:
        return 1
    match = re.search(r"\d+", str(lines))
    return int(match.group()) if match else 1


def _build_rules(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Derive SARIF rules from the distinct CWE identifiers in findings.

    Each CWE becomes one rule entry with:
      id            — the CWE string (e.g. "CWE-89")
      name          — PascalCase slug derived from the CWE id
      shortDescription.text — human-readable label

    Findings without a CWE get a synthetic rule id of "NO_CWE".
    """
    seen: dict[str, dict[str, Any]] = {}
    for finding in findings:
        cwe = (finding.get("cwe") or "NO_CWE").strip() or "NO_CWE"
        if cwe in seen:
            continue
        # Derive a name: "CWE-89" → "Cwe89", "NO_CWE" → "NoCwe"
        name_slug = re.sub(r"[^A-Za-z0-9]", "", cwe.title())
        seen[cwe] = {
            "id": cwe,
            "name": name_slug,
            "shortDescription": {
                "text": f"Vulnerability identified under {cwe}",
            },
            "helpUri": (
                f"https://cwe.mitre.org/data/definitions/{cwe.lstrip('CWEcwe-').lstrip('0') or '0'}.html"
                if cwe.upper().startswith("CWE-")
                else "https://cwe.mitre.org/"
            ),
        }
    return list(seen.values())


def _build_result(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a single finding dict into a SARIF result object.

    Mandatory result fields produced:
      ruleId        — CWE id (or "NO_CWE")
      level         — mapped from severity
      message.text  — title + short description
      locations     — physicalLocation with artifactLocation + region.startLine
    """
    severity = (finding.get("severity") or "LOW").upper()
    level = _SEVERITY_TO_LEVEL.get(severity, _DEFAULT_LEVEL)
    cwe = (finding.get("cwe") or "NO_CWE").strip() or "NO_CWE"
    title = finding.get("title") or "Untitled finding"
    description = finding.get("description") or ""
    file_path = (finding.get("file_path") or "").strip()
    start_line = _parse_start_line(finding.get("lines", ""))

    # Use a generic placeholder URI when no file path is recorded
    artifact_uri = file_path if file_path else "unknown"

    return {
        "ruleId": cwe,
        "level": level,
        "message": {
            "text": f"{title}: {description}" if description else title,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": start_line,
                    },
                },
            }
        ],
    }


def findings_to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Convert a list of vulnscan-agent finding dicts into a SARIF 2.1.0 document.

    Args:
        findings: List of finding dicts as returned by list_findings().
                  Each dict is expected to have at minimum:
                    severity, title, description, file_path, lines, cwe.

    Returns:
        A SARIF 2.1.0 document as a plain Python dict (ready for json.dump).

    Raises:
        ValueError: If findings is not a list (caller bug guard).
    """
    if not isinstance(findings, list):
        raise ValueError(f"findings must be a list, got {type(findings).__name__!r}")

    rules = _build_rules(findings)
    results = [_build_result(f) for f in findings]

    return {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnscan-agent",
                        "informationUri": "https://gitea.infrawei.lt/infrawei/managed-infra",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
