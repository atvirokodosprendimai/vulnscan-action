"""
Tests for tools/exec.py — the run_command allowlist (security-critical). Offline.

The allowlist is the safety boundary: the agent may invoke only vetted scanners,
never arbitrary commands, and never through a shell.
"""
from __future__ import annotations

import tools.exec as exec_mod
from tools.exec import ALLOWED_BINARIES, _parse_and_validate, run_command

import pytest


class TestAllowlistMembership:
    def test_go_scanners_present(self):
        assert "gosec" in ALLOWED_BINARIES
        assert "govulncheck" in ALLOWED_BINARIES

    def test_core_scanners_present(self):
        for b in ("semgrep", "pip-audit", "ast-grep", "gitleaks", "trivy"):
            assert b in ALLOWED_BINARIES


class TestParseAndValidate:
    def test_allowed_binary_parses(self):
        binary, argv = _parse_and_validate("gosec ./...")
        assert binary == "gosec"
        assert argv[0] == "gosec"

    def test_disallowed_binary_rejected(self):
        with pytest.raises(ValueError, match="not on the allowlist"):
            _parse_and_validate("rm -rf /")

    def test_shell_metachars_do_not_smuggle(self):
        # shlex.split keeps the ';' attached → basename "semgrep;" not allowlisted.
        with pytest.raises(ValueError):
            _parse_and_validate("semgrep; rm -rf /")

    def test_empty_command_rejected(self):
        with pytest.raises(ValueError):
            _parse_and_validate("")


class TestRunCommand:
    def test_disallowed_returns_structured_error(self):
        result = run_command.invoke({"command": "curl http://evil"})
        assert result["error"]
        assert "allowlist" in result["error"]
        assert result["returncode"] is None

    def test_missing_binary_not_installed(self, monkeypatch):
        # Force shutil.which to report the allowed binary as absent.
        monkeypatch.setattr(exec_mod.shutil, "which", lambda _x: None)
        result = run_command.invoke({"command": "govulncheck ./..."})
        assert result["error"] == "not_installed"
        assert result["binary"] == "govulncheck"
