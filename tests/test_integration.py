"""
Integration tests — planted vulnerability fixture + graph wiring.

The specialist is mocked to return a canned report (SQLi + cmd injection).
No live network calls. No API keys required.

Tests requiring live keys are marked with skipif.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture()
def vuln_repo(tmp_path) -> Path:
    """
    Create a minimal repo with planted vulnerabilities:
    1. String-formatted SQL (SQLi)
    2. os.system with user input (command injection)
    """
    code = tmp_path / "app" / "auth.py"
    code.parent.mkdir(parents=True)
    code.write_text(
        '''"""Deliberately vulnerable authentication module (test fixture)."""
import os
import sqlite3


def login(username, password):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # CWE-89: SQL injection via string formatting
    query = "SELECT * FROM users WHERE username=\'%s\' AND password=\'%s\'" % (username, password)
    cursor.execute(query)
    return cursor.fetchone()


def ping_host(host):
    # CWE-78: OS command injection
    os.system("ping -c 1 " + host)
''',
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture()
def isolated_workspace(tmp_path, monkeypatch):
    ws = tmp_path / "scan"
    ws.mkdir()
    (ws / "findings").mkdir()
    monkeypatch.setenv("SCAN_WORKSPACE", str(ws))
    monkeypatch.setenv("REPO_ROOT", str(tmp_path))
    import tools.findings
    importlib.reload(tools.findings)
    yield ws


# Canned specialist response simulating SQLi + command injection findings
_CANNED_SPECIALIST = """severity: HIGH
CWE: CWE-89 (SQL Injection)
lines: 10-11
explanation: User input directly interpolated into SQL query via % formatting
fix: Use parameterized queries with cursor.execute(query, (username, password))

severity: CRITICAL
CWE: CWE-78 (OS Command Injection)
lines: 16
explanation: os.system called with user-controlled host argument
fix: Use subprocess with a validated argument list; reject non-hostname chars"""


class TestPlantedVulnerabilities:
    """Drive findings tools directly, asserting 2 findings recorded."""

    def test_record_two_findings_and_complete(self, isolated_workspace):
        from tools.findings import (
            record_finding,
            list_findings,
            complete_scan,
        )

        # Record the two findings the (mocked) specialist would surface
        sqli = record_finding.invoke({
            "title": "SQL Injection in login()",
            "severity": "HIGH",
            "description": "User input directly interpolated into SQL query",
            "file_path": "app/auth.py",
            "lines": "10-11",
            "cwe": "CWE-89",
            "fix": "Use parameterized queries",
        })
        cmdi = record_finding.invoke({
            "title": "OS Command Injection in ping_host()",
            "severity": "CRITICAL",
            "description": "os.system called with user-controlled argument",
            "file_path": "app/auth.py",
            "lines": "16",
            "cwe": "CWE-78",
            "fix": "Use subprocess with validated argv list",
        })

        findings = list_findings.invoke({})
        assert len(findings) == 2

        severities = {f["severity"] for f in findings}
        assert "HIGH" in severities
        assert "CRITICAL" in severities

        result = complete_scan.invoke({
            "summary": "Found 2 vulnerabilities in app/auth.py: SQL injection and command injection."
        })
        assert result["status"] == "complete"
        assert result["total"] == 2
        assert result["finding_counts"]["HIGH"] == 1
        assert result["finding_counts"]["CRITICAL"] == 1

    def test_specialist_mock_returns_canned_report(self, isolated_workspace):
        """
        Mock requests.post inside the specialist to return canned findings.

        We patch at the requests.post level (not _call_featherless) so the
        patch survives without module reload — the mock controls what HTTP
        returns and we verify the full tool output.
        """
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": _CANNED_SPECIALIST}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 200},
        }

        with patch("tools.specialist.requests.post", return_value=mock_response):
            with patch.dict(os.environ, {"FEATHERLESS_API_KEY": "fake-key"}):
                from tools.specialist import deep_vuln_analysis

                result = deep_vuln_analysis.invoke({
                    "code": "os.system('ping ' + host)",
                    "context": "app/auth.py",
                })

        assert "CWE-89" in result, f"Expected CWE-89 in: {result!r}"
        assert "CWE-78" in result, f"Expected CWE-78 in: {result!r}"
        assert "SQL Injection" in result
        assert "Command Injection" in result


class TestGraphWiring:
    """
    Test that the graph nodes are correctly connected.

    We mock heavy dependencies to avoid needing real API keys or a running LLM.
    """

    def test_graph_compiles(self, tmp_path, monkeypatch):
        """Graph should compile without errors even with no API keys."""
        ws = tmp_path / "scan"
        ws.mkdir()
        (ws / "findings").mkdir()
        monkeypatch.setenv("SCAN_WORKSPACE", str(ws))
        monkeypatch.setenv("REPO_ROOT", str(tmp_path))

        # Patch build_orchestrator to avoid needing ZAI_API_KEY
        mock_llm = MagicMock()
        mock_llm.bind_tools = MagicMock(return_value=mock_llm)

        # Patch create_react_agent to avoid LLM init
        mock_agent = MagicMock()

        # Remove cached graph module so it re-imports cleanly
        for mod_name in list(sys.modules.keys()):
            if mod_name in ("graph",):
                del sys.modules[mod_name]

        with patch("models.build_orchestrator", return_value=mock_llm):
            with patch("langgraph.prebuilt.create_react_agent", return_value=mock_agent):
                import graph as graph_module

                compiled, config = graph_module.build_graph(thread_id="test-thread")
                assert compiled is not None
                assert config["configurable"]["thread_id"] == "test-thread"

    def test_init_node_sets_env(self, tmp_path, monkeypatch):
        """init_node should set REPO_ROOT in the environment."""
        ws = tmp_path / "scan"
        ws.mkdir()
        (ws / "findings").mkdir()
        monkeypatch.setenv("SCAN_WORKSPACE", str(ws))

        # Remove cached module to get a fresh import
        for mod_name in list(sys.modules.keys()):
            if mod_name in ("graph",):
                del sys.modules[mod_name]

        import graph as graph_module

        state = {
            "messages": [],
            "repo_root": str(tmp_path),
            "context_md": "",
            "requires_approval": False,
            "scan_complete": False,
            "scan_id": "test-123",
        }
        result = graph_module.init_node(state)

        assert os.environ.get("REPO_ROOT") == str(tmp_path.resolve())
        # Should have injected SystemMessage + HumanMessage
        assert len(result["messages"]) == 2


class TestLiveKeysSkipped:
    """Tests that require live API keys — skipped when keys absent."""

    @pytest.mark.skipif(
        not os.environ.get("FEATHERLESS_API_KEY"),
        reason="FEATHERLESS_API_KEY not set — live specialist test skipped",
    )
    def test_live_specialist(self):
        from tools.specialist import deep_vuln_analysis

        result = deep_vuln_analysis.invoke({
            "code": "x = 1",
            "context": "trivial_test.py",
        })
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.skipif(
        not os.environ.get("ZAI_API_KEY"),
        reason="ZAI_API_KEY not set — live orchestrator test skipped",
    )
    def test_live_orchestrator_builds(self):
        from models import build_orchestrator

        llm = build_orchestrator()
        assert llm is not None
