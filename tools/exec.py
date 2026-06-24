"""
run_command: Execute a strictly allowlisted security scanner.

Only the following binaries are permitted:
  semgrep, pip-audit, ast-grep, gitleaks, trivy

Invocation uses subprocess with a parsed argv list (no shell=True).
Missing binaries produce a structured "not installed" result — never an
exception that would crash the agent loop.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from typing import Any

from langchain_core.tools import tool  # type: ignore

# Canonical allowlist — lowercase names only.
# gosec + govulncheck added for Go coverage (VulnLLM-R-7B is out-of-distribution
# on Go; deterministic Go scanners carry detection there).
ALLOWED_BINARIES: frozenset[str] = frozenset(
    {"semgrep", "pip-audit", "ast-grep", "gitleaks", "trivy", "gosec", "govulncheck"}
)

TIMEOUT_SECONDS = 300  # 5 minutes max per scanner run


def _parse_and_validate(command: str) -> tuple[str, list[str]]:
    """
    Parse command string, extract binary name, validate against allowlist.

    Returns (binary_name, argv_list).
    Raises ValueError if the binary is not on the allowlist.
    """
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise ValueError(f"Cannot parse command: {exc}") from exc

    if not argv:
        raise ValueError("Empty command")

    binary = os.path.basename(argv[0]).lower()
    if binary not in ALLOWED_BINARIES:
        raise ValueError(
            f"Binary {binary!r} is not on the allowlist. "
            f"Allowed: {sorted(ALLOWED_BINARIES)}"
        )
    return binary, argv


@tool
def run_command(command: str) -> dict[str, Any]:
    """
    Run an allowlisted security scanner and return structured output.

    Allowed binaries: semgrep, pip-audit, ast-grep, gitleaks, trivy.
    The command is parsed as argv (no shell expansion) for safety.

    Args:
        command: Full command string, e.g. "semgrep --config auto src/".

    Returns a dict with keys: binary, command, returncode, stdout, stderr, error.
    If the binary is not installed, returns {"error": "not_installed", ...}.
    """
    try:
        binary, argv = _parse_and_validate(command)
    except ValueError as exc:
        return {
            "binary": None,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": str(exc),
        }

    # Check installation without crashing
    binary_path = shutil.which(argv[0]) or shutil.which(binary)
    if binary_path is None:
        return {
            "binary": binary,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "not_installed",
        }

    # Replace the user-supplied binary name with the resolved path
    argv[0] = binary_path

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            # Never use shell=True
            shell=False,
            # Inherit REPO_ROOT for scanners that need it
            env={**os.environ},
        )
        return {
            "binary": binary,
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout[:50_000],  # cap to protect context window
            "stderr": result.stderr[:10_000],
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "binary": binary,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": f"timeout after {TIMEOUT_SECONDS}s",
        }
    except OSError as exc:
        return {
            "binary": binary,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": f"execution error: {exc}",
        }
