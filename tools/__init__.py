"""
Export the full LangChain tool list for the react agent.

Import order matters for readability; tools are listed alphabetically within
their functional groups.
"""
from tools.exec import run_command
from tools.findings import (
    complete_scan,
    delete_finding,
    list_findings,
    record_finding,
    suppress_finding,
    update_finding,
)
from tools.fs import grep_files, list_files, read_file
from tools.second_opinion import second_opinion
from tools.specialist import deep_vuln_analysis

ALL_TOOLS = [
    # Read-only filesystem exploration
    read_file,
    list_files,
    grep_files,
    # Static analysis runners
    run_command,
    # LLM specialist tools
    deep_vuln_analysis,
    second_opinion,
    # Findings workspace (CRUD + completion)
    record_finding,
    list_findings,
    update_finding,
    delete_finding,
    suppress_finding,
    complete_scan,
]

__all__ = ["ALL_TOOLS"]
