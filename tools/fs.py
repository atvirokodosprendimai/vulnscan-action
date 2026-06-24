"""
Read-only filesystem tools sandboxed to REPO_ROOT.

All paths are resolved with realpath() before any I/O so directory traversal
attacks (../../etc/passwd) are rejected before the kernel sees them.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from langchain_core.tools import tool  # type: ignore


def _repo_root() -> Path:
    raw = os.environ.get("REPO_ROOT", ".")
    return Path(raw).resolve()


def _safe_path(user_path: str) -> Path:
    """
    Resolve path, then assert it sits inside REPO_ROOT.

    Raises ValueError on traversal attempts.
    """
    root = _repo_root()
    candidate = (root / user_path).resolve()
    # realpath check — must be under root
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ValueError(
            f"Path traversal rejected: {user_path!r} resolves outside REPO_ROOT"
        )
    return candidate


@tool
def read_file(path: str) -> str:
    """
    Read a file from the repository (sandboxed to REPO_ROOT).

    Returns the file contents as a string.
    Rejects paths that escape the repository root.
    """
    resolved = _safe_path(path)
    if not resolved.is_file():
        return f"ERROR: {path!r} is not a file (or does not exist)"
    try:
        return resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"ERROR reading {path!r}: {exc}"


@tool
def list_files(directory: str = ".", pattern: str = "*") -> str:
    """
    List files in a directory (recursive glob), sandboxed to REPO_ROOT.

    Args:
        directory: Relative path inside the repo (default: repo root).
        pattern:   Glob pattern, e.g. "**/*.py" (default: "*").

    Returns newline-separated list of relative paths.
    """
    resolved = _safe_path(directory)
    if not resolved.is_dir():
        return f"ERROR: {directory!r} is not a directory"
    root = _repo_root()
    matches = sorted(
        str(p.relative_to(root))
        for p in resolved.glob(pattern)
        if p.is_file()
        and str(p.resolve()).startswith(str(root))
    )
    if not matches:
        return f"No files matching {pattern!r} under {directory!r}"
    return "\n".join(matches)


@tool
def grep_files(pattern: str, directory: str = ".", include: str = "*.py") -> str:
    """
    Search for a regex pattern in files under a directory (sandboxed).

    Args:
        pattern:   Python regex to search for.
        directory: Directory to search (relative, default: repo root).
        include:   File glob filter, e.g. "*.py" (default).

    Returns matching lines as "filepath:lineno: line".
    """
    resolved_dir = _safe_path(directory)
    if not resolved_dir.is_dir():
        return f"ERROR: {directory!r} is not a directory"

    root = _repo_root()
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return f"ERROR: invalid regex {pattern!r}: {exc}"

    results: list[str] = []
    for filepath in sorted(resolved_dir.glob(f"**/{include}")):
        if not filepath.is_file():
            continue
        # Sandbox check
        try:
            filepath.resolve().relative_to(root)
        except ValueError:
            continue
        try:
            for lineno, line in enumerate(
                filepath.read_text(encoding="utf-8", errors="replace").splitlines(),
                start=1,
            ):
                if compiled.search(line):
                    rel = filepath.relative_to(root)
                    results.append(f"{rel}:{lineno}: {line.rstrip()}")
        except OSError:
            continue

    if not results:
        return f"No matches for {pattern!r} in {directory!r} ({include})"
    # Cap to avoid overwhelming the context window
    cap = 200
    if len(results) > cap:
        results = results[:cap] + [f"... (truncated at {cap} results)"]
    return "\n".join(results)
