"""
second_opinion: Ask DeepSeek deepseek-v4-flash to confirm or refute a finding.

Use on uncertain or HIGH/CRITICAL findings before recording them.
Returns "CONFIRMED", "REFUTED", or "UNCERTAIN" with a brief explanation.
"""
from __future__ import annotations

import logging
import os

from langchain_core.tools import tool  # type: ignore

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a senior security engineer performing a second-opinion review. "
    "A finding has been flagged by another model. "
    "Assess whether it is a genuine vulnerability or a false positive.\n\n"
    "Reply with exactly one of:\n"
    "  CONFIRMED: <one-line explanation why this is a real vulnerability>\n"
    "  REFUTED: <one-line explanation why this is a false positive>\n"
    "  UNCERTAIN: <one-line explanation of what additional context is needed>\n\n"
    "Be concise and definitive."
)


@tool
def second_opinion(finding: str) -> str:
    """
    Ask DeepSeek deepseek-v4-flash to confirm or refute a security finding.

    Use for HIGH/CRITICAL findings or when the specialist result is ambiguous.

    Args:
        finding: The finding text (severity, CWE, code snippet, explanation).

    Returns:
        "CONFIRMED: ...", "REFUTED: ...", or "UNCERTAIN: ...".
    """
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        return "ERROR: DEEPSEEK_API_KEY not set — second opinion unavailable"

    try:
        from langchain_openai import ChatOpenAI  # type: ignore
        from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore

        llm = ChatOpenAI(
            model="deepseek-v4-flash",
            base_url="https://api.deepseek.com",
            api_key=api_key,
            temperature=0,
            max_tokens=512,
        )
        messages = [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=f"Finding to review:\n\n{finding}"),
        ]
        response = llm.invoke(messages)
        return str(response.content).strip()

    except Exception as exc:
        logger.error("second_opinion failed: %s", exc)
        return f"ERROR: second_opinion failed: {exc}"
