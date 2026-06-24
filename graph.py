"""
LangGraph vulnerability scanner graph.

Graph shape:
  init -> react_agent_node -> approval_gate -> report

- init: Load scan/context.md and inject it into the agent's initial message.
- react_agent_node: LangGraph prebuilt create_react_agent — the agent drives
  its own tool-calling loop. This is NOT a fixed pipeline: the agent decides
  which tools to call and in what order.
- approval_gate: Uses LangGraph interrupt() for any external-write tool.
  In v1 no external-write tools exist, so the gate is a no-op pass-through.
  The interrupt mechanism is wired so it is ready when external-write tools
  are added (e.g. creating GitHub issues, pushing results to an API).
- report: Final node that extracts the scan completion result.

Checkpointing: SqliteSaver to scan/checkpoints.sqlite so a suspended CI
runner can resume mid-scan.

LangFuse v3 observability:
  - Each scan is wrapped in a root span (trace input = repo path).
  - The react_agent is invoked with run_name + session/user/tags metadata.
  - flush() is called in a finally block to ensure traces reach the server
    in short-lived / CI processes.
  - All observability is optional — no-op when env keys are absent.
"""
from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Annotated, Any, TypedDict

import sqlite3

from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore
from langgraph.checkpoint.sqlite import SqliteSaver  # type: ignore
from langgraph.graph import END, StateGraph  # type: ignore
from langgraph.graph.message import add_messages  # type: ignore
from langgraph.prebuilt import create_react_agent  # type: ignore
from langgraph.types import interrupt  # type: ignore

import observability
from tools import ALL_TOOLS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class ScanState(TypedDict):
    messages: Annotated[list[Any], add_messages]
    repo_root: str
    context_md: str
    requires_approval: bool
    scan_complete: bool
    scan_id: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_context_md(scan_workspace: str) -> str:
    ctx = Path(scan_workspace) / "context.md"
    if ctx.exists():
        return ctx.read_text(encoding="utf-8")
    return "# Scan Context\n\n(No previous context — first run.)\n"


def _load_system_prompt() -> str:
    prompt_path = Path(__file__).parent / "prompts" / "auditor.md"
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8")
    return "You are a security auditor. Scan the repository for vulnerabilities."


def _scan_workspace() -> str:
    return os.environ.get("SCAN_WORKSPACE", "./scan")


def _checkpoint_db() -> str:
    ws = Path(_scan_workspace()).resolve()
    ws.mkdir(parents=True, exist_ok=True)
    return str(ws / "checkpoints.sqlite")


# ---------------------------------------------------------------------------
# Node: init
# ---------------------------------------------------------------------------

def init_node(state: ScanState) -> dict[str, Any]:
    """
    Load context.md and inject it as the first user message.
    Sets REPO_ROOT in the environment for the sandboxed fs tools.
    """
    repo_root = state.get("repo_root", os.environ.get("REPO_ROOT", "."))
    os.environ["REPO_ROOT"] = str(Path(repo_root).resolve())

    context_md = _load_context_md(_scan_workspace())
    system_prompt = _load_system_prompt()

    initial_message = HumanMessage(
        content=(
            f"Target repository: {repo_root}\n\n"
            "Current scan context (suppressions, accepted risks):\n"
            "---\n"
            f"{context_md}\n"
            "---\n\n"
            "Please begin the security audit now. "
            "Read the context above and honor all suppressions. "
            "Explore the repository, run scanners, analyze suspicious code, "
            "record findings, and call complete_scan when done."
        )
    )

    return {
        "messages": [SystemMessage(content=system_prompt), initial_message],
        "repo_root": repo_root,
        "context_md": context_md,
        "requires_approval": False,
        "scan_complete": False,
    }


# ---------------------------------------------------------------------------
# Node: react_agent_node
# ---------------------------------------------------------------------------

def _build_react_agent():
    """
    Build the react agent using the prebuilt create_react_agent.

    The agent retains full reasoning authority — the graph does not encode
    the scan steps. LangFuse callbacks are attached per-invoke call, not here,
    so they can carry per-scan session/user metadata.
    """
    from models import build_orchestrator

    llm = build_orchestrator()
    return create_react_agent(model=llm, tools=ALL_TOOLS)


def react_agent_node(state: ScanState) -> dict[str, Any]:
    """
    Run the react agent loop.

    The agent will call tools until it decides to stop (or calls complete_scan).
    We detect completion by checking whether the complete_scan tool was invoked.
    """
    agent = _build_react_agent()
    repo_root = state.get("repo_root", ".")
    scan_id = state.get("scan_id", str(uuid.uuid4()))
    model = os.environ.get("ORCH_MODEL", "glm-5.2")
    run_env = "ci" if os.environ.get("CI") else "local"

    # Build invoke config with LangFuse v3 attribution metadata
    config: dict[str, Any] = {
        "callbacks": observability.get_callbacks(),
        "run_name": f"vulnscan:{os.path.basename(os.path.abspath(repo_root))}",
        "metadata": {
            "langfuse_session_id": scan_id,
            "langfuse_user_id": os.path.basename(os.path.abspath(repo_root)),
            "langfuse_tags": ["vulnscan", model, run_env],
        },
    }

    result = agent.invoke({"messages": state["messages"]}, config=config)

    # Check if the agent signalled completion via complete_scan
    scan_complete = False
    for msg in result.get("messages", []):
        content = getattr(msg, "content", "")
        if isinstance(content, str) and '"status": "complete"' in content:
            scan_complete = True
            break
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("status") == "complete":
                    scan_complete = True
                    break

    return {
        "messages": result.get("messages", []),
        "scan_complete": scan_complete,
        "requires_approval": False,  # No external-write tools in v1
    }


# ---------------------------------------------------------------------------
# Node: approval_gate
# ---------------------------------------------------------------------------

def approval_gate_node(state: ScanState) -> dict[str, Any]:
    """
    Approval gate for external-write operations.

    In v1 no external-write tools exist so this is a pass-through.
    The interrupt() call is wired here: when external-write tools are added,
    set state["requires_approval"] = True and this node will pause execution
    for human approval before proceeding.

    LangGraph interrupt() suspends the graph and resumes when the caller
    invokes graph.invoke() again with the same thread_id.
    """
    if state.get("requires_approval", False):
        # Pause for human approval — caller resumes by invoking with thread_id
        approval = interrupt(
            {
                "type": "approval_required",
                "message": (
                    "The agent wants to perform an external write operation. "
                    "Resume this invocation to approve, or discard the thread to reject."
                ),
            }
        )
        logger.info("Approval gate resumed with: %s", approval)

    return {}  # No state mutation needed in pass-through mode


# ---------------------------------------------------------------------------
# Node: report
# ---------------------------------------------------------------------------

def report_node(state: ScanState) -> dict[str, Any]:
    """
    Final node: log completion and return.

    The actual report file is written by complete_scan tool.
    This node just surfaces the final status.
    """
    ws = _scan_workspace()
    report_path = Path(ws) / "report.md"
    if report_path.exists():
        logger.info("Scan report available at: %s", report_path)
    else:
        logger.warning("complete_scan was not called — no report.md written")

    return {"scan_complete": True}


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------

def build_graph(thread_id: str = "default") -> tuple[Any, Any]:
    """
    Build and compile the vulnerability scanner graph.

    Returns (compiled_graph, config_dict) where config_dict contains the
    thread_id for checkpointing (allows resume after suspension).

    SqliteSaver is instantiated directly from a persistent sqlite3 connection
    (not via the context-manager form of from_conn_string) so the caller does
    not need to manage a with-block lifetime.
    """
    db_path = _checkpoint_db()
    conn = sqlite3.connect(db_path, check_same_thread=False)
    checkpointer = SqliteSaver(conn)

    builder: StateGraph = StateGraph(ScanState)

    builder.add_node("init", init_node)
    builder.add_node("react_agent", react_agent_node)
    builder.add_node("approval_gate", approval_gate_node)
    builder.add_node("report", report_node)

    builder.set_entry_point("init")
    builder.add_edge("init", "react_agent")
    builder.add_edge("react_agent", "approval_gate")
    builder.add_edge("approval_gate", "report")
    builder.add_edge("report", END)

    compiled = builder.compile(checkpointer=checkpointer)
    config = {"configurable": {"thread_id": thread_id}}

    return compiled, config


def run_scan(repo_root: str, thread_id: str = "default") -> dict[str, Any]:
    """
    Entry point: run a full vulnerability scan.

    Args:
        repo_root:  Absolute path to the repository to scan.
        thread_id:  Unique identifier for this scan run (used for checkpointing).
                    Pass the same id to resume a suspended scan.

    Returns the final graph state.
    """
    scan_id = thread_id
    graph, config = build_graph(thread_id=thread_id)

    initial_state: ScanState = {
        "messages": [],
        "repo_root": repo_root,
        "context_md": "",
        "requires_approval": False,
        "scan_complete": False,
        "scan_id": scan_id,
    }

    logger.info("Starting scan of %s (thread_id=%s)", repo_root, thread_id)

    repo_name = os.path.basename(os.path.abspath(repo_root))
    span_ctx = observability.start_scan_span(repo_root)

    try:
        with span_ctx as root_span:
            final_state = graph.invoke(initial_state, config=config)

            # Update root trace with final summary
            if root_span is not None:
                from tools.findings import list_findings  # type: ignore
                findings = list_findings.invoke({})
                max_sev = None
                sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                if findings:
                    max_sev = min(
                        findings,
                        key=lambda f: sev_order.get(f.get("severity", "LOW"), 99),
                    ).get("severity")
                try:
                    root_span.update_trace(
                        input={"repo": repo_root},
                        output={"findings": len(findings), "max_severity": max_sev},
                    )
                except Exception:
                    pass  # never let tracing break the scan

    finally:
        # Flush buffered traces — critical for CI/short-lived processes
        observability.flush()

    return final_state
