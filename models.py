"""
Model constructors.

All model IDs, base URLs, and API keys come from environment variables so
operators can swap providers (e.g. MiniMax-M3 or DeepSeek) without touching
source code.

Orchestrator defaults:
  ZAI_API_KEY          — auth token
  ANTHROPIC_BASE_URL   — override base URL (default z.ai Anthropic-compat)
  ORCH_MODEL           — model name (default glm-5.2)

Specialist (VulnLLM-R-7B via Featherless):
  FEATHERLESS_API_KEY

Second opinion (DeepSeek):
  DEEPSEEK_API_KEY
"""
from __future__ import annotations

import os
from typing import Any


def build_orchestrator() -> Any:
    """
    Build the orchestrator ChatAnthropic model from env.

    Uses langchain_anthropic with a custom base_url so any Anthropic-compatible
    provider can be swapped in via environment variables.
    """
    from langchain_anthropic import ChatAnthropic  # type: ignore

    api_key = os.environ.get("ORCH_API_KEY") or os.environ.get("ZAI_API_KEY", "")
    base_url = os.environ.get(
        "ANTHROPIC_BASE_URL", "https://api.z.ai/api/anthropic"
    )
    model = os.environ.get("ORCH_MODEL", "glm-5.2")

    if not api_key:
        raise RuntimeError(
            "Orchestrator API key missing. Set ZAI_API_KEY (or ORCH_API_KEY)."
        )

    # Anthropic-compat providers (z.ai/MiniMax) return transient 529/503
    # overloaded errors under load; without retries a single blip crashes the
    # whole scan (observed: z.ai 529 mid-run). Retry with backoff like the
    # specialist tool does. Override via ORCH_MAX_RETRIES.
    return ChatAnthropic(
        model=model,
        anthropic_api_key=api_key,
        base_url=base_url,
        temperature=0,
        max_tokens=4096,
        max_retries=int(os.environ.get("ORCH_MAX_RETRIES", "5")),
        timeout=120,
    )


def build_specialist_http_client() -> dict[str, Any]:
    """
    Return config dict for the Featherless VulnLLM-R-7B specialist.

    The actual HTTP call is made inside tools/specialist.py so it can
    apply retry logic, concurrency limiting, and response trimming.
    """
    api_key = os.environ.get("FEATHERLESS_API_KEY", "")
    if not api_key:
        raise RuntimeError("FEATHERLESS_API_KEY not set.")

    return {
        "base_url": "https://api.featherless.ai/v1",
        "api_key": api_key,
        "model": "Virtue-AI-HUB/VulnLLM-R-7B",
    }


def build_second_opinion_llm() -> Any:
    """
    Build the DeepSeek second-opinion model (OpenAI-compatible).
    """
    from langchain_openai import ChatOpenAI  # type: ignore

    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not set.")

    return ChatOpenAI(
        model="deepseek-v4-flash",
        base_url="https://api.deepseek.com",
        api_key=api_key,
        temperature=0,
        max_tokens=2048,
        max_retries=4,
        timeout=90,
    )
