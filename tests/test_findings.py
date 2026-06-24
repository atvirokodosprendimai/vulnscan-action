"""
Tests for tools/findings.py — CRUD round-trip, suppression, and completion.

All tests use a temporary directory as SCAN_WORKSPACE so they are fully isolated.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path, monkeypatch):
    """Each test gets a fresh temporary scan workspace."""
    ws = tmp_path / "scan"
    ws.mkdir()
    (ws / "findings").mkdir()
    monkeypatch.setenv("SCAN_WORKSPACE", str(ws))
    # Re-import to pick up the patched env in cached _workspace() calls
    import importlib
    import tools.findings
    importlib.reload(tools.findings)
    yield ws


class TestRecordFinding:
    def test_creates_json_file(self, isolated_workspace):
        from tools.findings import record_finding

        result = record_finding.invoke({
            "title": "SQL Injection",
            "severity": "HIGH",
            "description": "User input concatenated into SQL",
            "file_path": "app/db.py",
            "lines": "42-45",
            "cwe": "CWE-89",
            "fix": "Use parameterized queries",
        })

        assert "id" in result
        assert result["severity"] == "HIGH"
        assert result["status"] == "open"

        # File should exist on disk
        finding_file = isolated_workspace / "findings" / f"{result['id']}.json"
        assert finding_file.exists()
        on_disk = json.loads(finding_file.read_text())
        assert on_disk["title"] == "SQL Injection"

    def test_rejects_invalid_severity(self):
        from tools.findings import record_finding

        result = record_finding.invoke({
            "title": "Test",
            "severity": "INVALID",
            "description": "desc",
        })
        assert "error" in result

    def test_severity_normalized_to_uppercase(self):
        from tools.findings import record_finding

        result = record_finding.invoke({
            "title": "Test",
            "severity": "critical",
            "description": "desc",
        })
        assert result["severity"] == "CRITICAL"


class TestListFindings:
    def test_returns_empty_list(self):
        from tools.findings import list_findings

        result = list_findings.invoke({})
        assert result == []

    def test_returns_sorted_by_severity(self):
        from tools.findings import record_finding, list_findings

        record_finding.invoke({"title": "Low one", "severity": "LOW", "description": "d"})
        record_finding.invoke({"title": "Critical one", "severity": "CRITICAL", "description": "d"})
        record_finding.invoke({"title": "High one", "severity": "HIGH", "description": "d"})

        findings = list_findings.invoke({})
        severities = [f["severity"] for f in findings]
        assert severities == ["CRITICAL", "HIGH", "LOW"]


class TestUpdateFinding:
    def test_update_title(self):
        from tools.findings import record_finding, update_finding

        created = record_finding.invoke({
            "title": "Original",
            "severity": "LOW",
            "description": "desc",
        })

        updated = update_finding.invoke({
            "finding_id": created["id"],
            "title": "Updated Title",
        })

        assert updated["title"] == "Updated Title"
        assert updated["severity"] == "LOW"  # unchanged

    def test_update_nonexistent(self):
        from tools.findings import update_finding

        result = update_finding.invoke({
            "finding_id": "00000000-0000-0000-0000-000000000000",
            "title": "x",
        })
        assert "error" in result


class TestDeleteFinding:
    def test_delete_removes_file(self, isolated_workspace):
        from tools.findings import record_finding, delete_finding

        created = record_finding.invoke({
            "title": "To delete",
            "severity": "LOW",
            "description": "d",
        })
        fid = created["id"]
        path = isolated_workspace / "findings" / f"{fid}.json"
        assert path.exists()

        result = delete_finding.invoke({"finding_id": fid})
        assert result["deleted"] == fid
        assert not path.exists()

    def test_delete_nonexistent(self):
        from tools.findings import delete_finding

        result = delete_finding.invoke({"finding_id": "does-not-exist"})
        assert "error" in result


class TestSuppressFinding:
    def test_suppress_deletes_finding_and_updates_context(self, isolated_workspace):
        from tools.findings import record_finding, suppress_finding

        created = record_finding.invoke({
            "title": "False positive",
            "severity": "MEDIUM",
            "description": "Not actually vulnerable",
            "cwe": "CWE-22",
        })
        fid = created["id"]

        result = suppress_finding.invoke({
            "finding_id": fid,
            "reason": "Reviewed by security team — internal path only",
        })

        assert result["suppressed"] == fid

        # Finding file should be gone
        path = isolated_workspace / "findings" / f"{fid}.json"
        assert not path.exists()

        # context.md should contain the suppression
        ctx = isolated_workspace / "context.md"
        assert ctx.exists()
        content = ctx.read_text()
        assert "SUPPRESS" in content
        assert "False positive" in content
        assert "Reviewed by security team" in content

    def test_suppress_nonexistent(self):
        from tools.findings import suppress_finding

        result = suppress_finding.invoke({
            "finding_id": "not-here",
            "reason": "test",
        })
        assert "error" in result


class TestCompleteScan:
    def test_writes_report_md(self, isolated_workspace):
        from tools.findings import record_finding, complete_scan

        record_finding.invoke({
            "title": "SQLi",
            "severity": "HIGH",
            "description": "SQL injection in login",
            "file_path": "app/auth.py",
            "cwe": "CWE-89",
        })

        result = complete_scan.invoke({"summary": "Found 1 HIGH issue in auth module."})

        assert result["status"] == "complete"
        assert result["finding_counts"]["HIGH"] == 1
        assert result["total"] == 1

        report = isolated_workspace / "report.md"
        assert report.exists()
        content = report.read_text()
        assert "SQLi" in content
        assert "CWE-89" in content
        assert "Found 1 HIGH issue" in content

    def test_complete_with_no_findings(self, isolated_workspace):
        from tools.findings import complete_scan

        result = complete_scan.invoke({"summary": "No issues found."})
        assert result["status"] == "complete"
        assert result["total"] == 0
