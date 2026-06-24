"""
Findings workspace tools — CRUD on finding entities in scan/findings/.

Each finding is stored as a JSON file: scan/findings/<uuid>.json

suppress_finding(id, reason):
  - Deletes the finding JSON.
  - Appends a suppression entry to scan/context.md so future runs skip it.

complete_scan(summary):
  - Writes scan/report.md.
  - This is the explicit completion signal — no heuristic.

Workspace root is determined by env SCAN_WORKSPACE (default: ./scan).
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langchain_core.tools import tool  # type: ignore

# SARIF import is best-effort: if the module is missing we degrade gracefully.
try:
    from tools.sarif import findings_to_sarif as _findings_to_sarif  # type: ignore
except ImportError:  # pragma: no cover
    _findings_to_sarif = None  # type: ignore

logger = logging.getLogger(__name__)

VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})


def _workspace() -> Path:
    raw = os.environ.get("SCAN_WORKSPACE", "./scan")
    ws = Path(raw).resolve()
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "findings").mkdir(exist_ok=True)
    return ws


def _findings_dir() -> Path:
    return _workspace() / "findings"


def _context_md() -> Path:
    return _workspace() / "context.md"


def _report_md() -> Path:
    return _workspace() / "report.md"


def _load_finding(finding_id: str) -> dict[str, Any]:
    path = _findings_dir() / f"{finding_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Finding {finding_id!r} does not exist")
    return json.loads(path.read_text(encoding="utf-8"))


def _save_finding(finding: dict[str, Any]) -> None:
    fid = finding["id"]
    path = _findings_dir() / f"{fid}.json"
    path.write_text(json.dumps(finding, indent=2, ensure_ascii=False), encoding="utf-8")


@tool
def record_finding(
    title: str,
    severity: str,
    description: str,
    file_path: str = "",
    lines: str = "",
    cwe: str = "",
    fix: str = "",
) -> dict[str, Any]:
    """
    Record a new vulnerability finding in the scan workspace.

    Args:
        title:       Short title (e.g. "SQL Injection in search endpoint").
        severity:    CRITICAL | HIGH | MEDIUM | LOW
        description: Full description including evidence.
        file_path:   Affected file (optional).
        lines:       Affected line numbers or range (optional).
        cwe:         CWE identifier e.g. "CWE-89" (optional).
        fix:         Concise remediation advice (optional).

    Returns the created finding dict including its assigned id.
    """
    severity = severity.upper()
    if severity not in VALID_SEVERITIES:
        return {"error": f"Invalid severity {severity!r}. Use: {sorted(VALID_SEVERITIES)}"}

    finding: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "title": title,
        "severity": severity,
        "description": description,
        "file_path": file_path,
        "lines": lines,
        "cwe": cwe,
        "fix": fix,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "status": "open",
    }
    _save_finding(finding)
    logger.info("Recorded finding %s [%s]: %s", finding["id"], severity, title)
    return finding


@tool
def list_findings() -> list[dict[str, Any]]:
    """
    List all open findings in the scan workspace.

    Returns a list of finding dicts sorted by severity (CRITICAL first).
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings: list[dict[str, Any]] = []
    for path in _findings_dir().glob("*.json"):
        try:
            findings.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read finding %s: %s", path.name, exc)

    return sorted(findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 99))


@tool
def update_finding(
    finding_id: str,
    title: str = "",
    severity: str = "",
    description: str = "",
    file_path: str = "",
    lines: str = "",
    cwe: str = "",
    fix: str = "",
    status: str = "",
) -> dict[str, Any]:
    """
    Update one or more fields of an existing finding.

    Pass only the fields you want to change; empty strings are ignored.

    Args:
        finding_id:  The finding UUID.
        title:       New title (optional).
        severity:    New severity CRITICAL|HIGH|MEDIUM|LOW (optional).
        description: New description (optional).
        file_path:   New file path (optional).
        lines:       New line range (optional).
        cwe:         New CWE identifier (optional).
        fix:         New fix description (optional).
        status:      New status e.g. "acknowledged" (optional).

    Returns the updated finding dict.
    """
    try:
        finding = _load_finding(finding_id)
    except FileNotFoundError as exc:
        return {"error": str(exc)}

    # Build overlay dict of non-empty values only (immutable style)
    overrides: dict[str, Any] = {}
    if title:
        overrides["title"] = title
    if severity:
        sev = severity.upper()
        if sev not in VALID_SEVERITIES:
            return {"error": f"Invalid severity {sev!r}. Use: {sorted(VALID_SEVERITIES)}"}
        overrides["severity"] = sev
    if description:
        overrides["description"] = description
    if file_path:
        overrides["file_path"] = file_path
    if lines:
        overrides["lines"] = lines
    if cwe:
        overrides["cwe"] = cwe
    if fix:
        overrides["fix"] = fix
    if status:
        overrides["status"] = status

    updated = {**finding, **overrides, "updated_at": datetime.now(timezone.utc).isoformat()}
    _save_finding(updated)
    return updated


@tool
def delete_finding(finding_id: str) -> dict[str, Any]:
    """
    Delete a finding (hard delete — use suppress_finding to permanently exclude).

    Args:
        finding_id: The finding UUID to delete.

    Returns confirmation dict.
    """
    path = _findings_dir() / f"{finding_id}.json"
    if not path.exists():
        return {"error": f"Finding {finding_id!r} not found"}
    path.unlink()
    logger.info("Deleted finding %s", finding_id)
    return {"deleted": finding_id}


@tool
def suppress_finding(finding_id: str, reason: str) -> dict[str, Any]:
    """
    Permanently suppress a finding: delete it and record the suppression in
    scan/context.md so future scans honor the decision.

    Args:
        finding_id: The finding UUID to suppress.
        reason:     Human-readable justification (shown in context.md).

    Returns confirmation dict.
    """
    try:
        finding = _load_finding(finding_id)
    except FileNotFoundError as exc:
        return {"error": str(exc)}

    # Delete the finding
    ((_findings_dir() / f"{finding_id}.json")).unlink()

    # Append suppression to context.md
    ctx = _context_md()
    timestamp = datetime.now(timezone.utc).isoformat()
    entry = (
        f"\n## SUPPRESSED [{timestamp}]\n"
        f"- id: {finding_id}\n"
        f"- title: {finding.get('title', 'unknown')}\n"
        f"- severity: {finding.get('severity', 'unknown')}\n"
        f"- reason: {reason}\n"
        f"- file: {finding.get('file_path', '')}\n"
        f"- cwe: {finding.get('cwe', '')}\n"
        "<!-- SUPPRESS: do not re-flag this finding -->\n"
    )
    with ctx.open("a", encoding="utf-8") as fh:
        fh.write(entry)

    logger.info("Suppressed finding %s: %s", finding_id, reason)
    return {"suppressed": finding_id, "reason": reason}


@tool
def complete_scan(summary: str) -> dict[str, Any]:
    """
    Signal that the scan is complete and write the final report.

    Call this when you have finished exploring the repository, recorded all
    findings, and are confident no further analysis is needed.

    Args:
        summary: High-level summary of the scan (what was checked, key findings,
                 overall risk assessment).

    Returns confirmation with report path.
    """
    ws = _workspace()
    findings = list_findings.invoke({})  # type: ignore[attr-defined]

    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    timestamp = datetime.now(timezone.utc).isoformat()
    lines = [
        f"# Vulnerability Scan Report",
        f"",
        f"Generated: {timestamp}",
        f"",
        f"## Summary",
        f"",
        summary,
        f"",
        f"## Finding Counts",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {sev} | {severity_counts[sev]} |")

    lines += ["", "## Findings", ""]

    for finding in findings:
        lines += [
            f"### [{finding['severity']}] {finding['title']}",
            f"",
            f"- **File**: {finding.get('file_path', 'N/A')}",
            f"- **Lines**: {finding.get('lines', 'N/A')}",
            f"- **CWE**: {finding.get('cwe', 'N/A')}",
            f"- **Created**: {finding.get('created_at', 'N/A')}",
            f"",
            finding.get("description", ""),
            f"",
            f"**Fix**: {finding.get('fix', 'N/A')}",
            f"",
        ]

    report_path = _report_md()
    report_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Scan complete. Report written to %s", report_path)

    # Write SARIF 2.1.0 output alongside report.md — resilient, never crashes scan.
    sarif_path = ws / "results.sarif"
    try:
        if _findings_to_sarif is not None:
            sarif_doc = _findings_to_sarif(findings)
            sarif_path.write_text(
                json.dumps(sarif_doc, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("SARIF report written to %s", sarif_path)
        else:
            logger.warning("SARIF module unavailable — skipping results.sarif")
    except Exception as exc:  # noqa: BLE001
        logger.warning("SARIF write failed (non-fatal): %s", exc)

    return {
        "status": "complete",
        "report_path": str(report_path),
        "sarif_path": str(sarif_path) if sarif_path.exists() else None,
        "finding_counts": severity_counts,
        "total": sum(severity_counts.values()),
    }
