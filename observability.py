"""
LangFuse v3 observability setup.

Import path: langfuse.langchain.CallbackHandler (v3, NOT langfuse.callback).
Config comes from env vars — never from handler args.

Environment variables:
  LANGFUSE_PUBLIC_KEY   — LangFuse public key
  LANGFUSE_SECRET_KEY   — LangFuse secret key
  LANGFUSE_BASE_URL     — Self-hosted LangFuse base URL (alias for LANGFUSE_HOST)
  LANGFUSE_HOST         — Alternative host var (LANGFUSE_BASE_URL takes precedence)

If public+secret keys are absent the module is a no-op — safe for offline tests
and CI runs without a LangFuse server.

NOTE on cost tracking:
  glm-5.2, Virtue-AI-HUB/VulnLLM-R-7B, and deepseek-v4-flash are NOT in
  LangFuse's default model-price table. Tokens are captured but cost shows $0
  until custom prices are defined in the self-hosted LangFuse UI (Models section)
  or via langfuse-cli. This does not block traces.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Module-level state — populated on first successful init
_configured: bool = False


def _ensure_host_env() -> None:
    """
    Normalize LANGFUSE_BASE_URL / LANGFUSE_HOST.
    LangFuse v3 client reads LANGFUSE_HOST; if the caller only sets
    LANGFUSE_BASE_URL, mirror it so the client picks it up.
    """
    base_url = os.environ.get("LANGFUSE_BASE_URL", "")
    host = os.environ.get("LANGFUSE_HOST", "")
    if base_url and not host:
        os.environ["LANGFUSE_HOST"] = base_url
    elif host and not base_url:
        os.environ["LANGFUSE_BASE_URL"] = host


def _is_configured() -> bool:
    """Return True when both key env vars are present."""
    _ensure_host_env()
    return bool(
        os.environ.get("LANGFUSE_PUBLIC_KEY")
        and os.environ.get("LANGFUSE_SECRET_KEY")
    )


def get_callbacks() -> list[Any]:
    """
    Return [langfuse.langchain.CallbackHandler()] or [] when env vars absent.

    The handler reads keys/host from env automatically (v3 behaviour).
    Never crashes — returns [] on any import or config error.
    """
    if not _is_configured():
        logger.debug("LangFuse not configured — observability disabled")
        return []

    try:
        from langfuse.langchain import CallbackHandler  # type: ignore

        handler = CallbackHandler()
        logger.info(
            "LangFuse observability enabled (host=%s)",
            os.environ.get("LANGFUSE_HOST", "default"),
        )
        return [handler]
    except Exception as exc:  # pragma: no cover
        logger.warning("LangFuse init failed (%s) — continuing without tracing", exc)
        return []


def flush() -> None:
    """
    Flush pending traces to LangFuse.

    MUST be called at the end of short-lived processes (CI) to avoid losing
    traces that are buffered in memory.

    Safe to call when LangFuse is not configured — no-op.
    """
    if not _is_configured():
        return
    try:
        from langfuse import get_client  # type: ignore

        client = get_client()
        client.shutdown()
        logger.debug("LangFuse traces flushed")
    except Exception as exc:  # pragma: no cover
        logger.warning("LangFuse flush failed: %s", exc)


def build_run_config(
    repo_path: str,
    scan_id: str,
    orchestrator_model: str = "",
    run_env: str = "",
) -> dict[str, Any]:
    """
    Build a LangChain invoke config dict with LangFuse attribution metadata.

    session_id = scan_id groups the whole agent loop into one LangFuse session.
    user_id    = repo identifier enables per-repo cost attribution.
    tags       = ["vulnscan", model, "ci"|"local"] for filtering.
    """
    import os as _os
    repo_name = _os.path.basename(_os.path.abspath(repo_path))
    model = orchestrator_model or _os.environ.get("ORCH_MODEL", "glm-5.2")
    env = run_env or ("ci" if _os.environ.get("CI") else "local")

    return {
        "callbacks": get_callbacks(),
        "run_name": f"vulnscan:{repo_name}",
        "metadata": {
            "langfuse_session_id": scan_id,
            "langfuse_user_id": repo_name,
            "langfuse_tags": ["vulnscan", model, env],
        },
    }


def start_scan_span(repo_path: str):
    """
    Context manager: wrap the entire scan in a root LangFuse span.

    Yields a handle whose .update_trace() can be called with final summary.
    Returns a no-op context when LangFuse is not configured.
    """
    if not _is_configured():
        from contextlib import nullcontext
        return nullcontext()

    try:
        from langfuse import get_client  # type: ignore

        lf = get_client()
        return lf.start_as_current_observation(
            as_type="span",
            name=f"vulnscan:{os.path.basename(os.path.abspath(repo_path))}",
            input={"repo": repo_path},
        )
    except Exception as exc:
        logger.warning("Could not start LangFuse span: %s", exc)
        from contextlib import nullcontext
        return nullcontext()


def trace_featherless_call(code_preview: str, model: str = "Virtue-AI-HUB/VulnLLM-R-7B"):
    """
    Context manager: manually instrument a raw Featherless HTTP call as a
    LangFuse generation.

    Featherless calls bypass the LangChain callback handler (raw HTTP),
    so we wrap them manually to capture model + token usage.

    Usage:
        with trace_featherless_call(code[:200]) as gen:
            resp = _call_featherless(code, context, api_key)
            if gen:
                gen.update(output=resp, usage_details={...})

    Returns None when LangFuse is not configured.
    """
    if not _is_configured():
        from contextlib import nullcontext
        return nullcontext()

    try:
        from langfuse import get_client  # type: ignore

        lf = get_client()
        # langfuse v4: generations are observations with as_type="generation"
        # (there is no start_as_current_generation in 4.x).
        return lf.start_as_current_observation(
            as_type="generation",
            name="vulnllm-specialist",
            model=model,
            input=code_preview,
        )
    except Exception as exc:
        logger.warning("Could not start LangFuse generation: %s", exc)
        from contextlib import nullcontext
        return nullcontext()
