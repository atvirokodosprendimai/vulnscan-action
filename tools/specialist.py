"""
deep_vuln_analysis: LangChain tool that calls VulnLLM-R-7B via Featherless.

Load-bearing gotchas (verified 2026-06-24, port exactly):

1. Cloudflare blocks default Python / urllib User-Agents with HTTP 403 code 1010.
   Fix: always send ``User-Agent: curl/8.4.0``.

2. VulnLLM-R-7B ("-R" reasoning variant) emits:
     <actual analysis>
     </think>
     <hallucinated user/assistant turns to pad to max_tokens>
   Fix: send stop sequences AND post-process to keep only content before
   </think> (and before any hallucinated user turn).

3. Featherless returns HTTP 429 with no server-side queue when concurrency
   exceeds the account limit. Fix: client-side asyncio.Semaphore sized by
   env var FEATHERLESS_CONCURRENCY (default 2) + exponential backoff on 429/5xx.

4. Three retry attempts with exponential backoff + jitter.

LangFuse tracing:
  Raw HTTP calls bypass the LangChain callback handler, so each Featherless
  call is manually wrapped as a LangFuse generation (token usage included).
  When LangFuse is not configured this is a complete no-op.
"""
from __future__ import annotations

import logging
import os
import random
import threading
import time
from typing import Any

import requests
from langchain_core.tools import tool  # type: ignore

logger = logging.getLogger(__name__)

# Concurrency gate — Featherless queues nothing (over-allotment → 429), so cap
# in-flight calls. deep_vuln_analysis is a SYNC tool that LangChain runs in a
# thread pool, so the gate must be a threading.Semaphore (an asyncio one would
# not gate threads) acquired around the actual HTTP call.
_CONCURRENCY = int(os.environ.get("FEATHERLESS_CONCURRENCY", "2"))
_semaphore: threading.Semaphore | None = None
_semaphore_lock = threading.Lock()


def _get_semaphore() -> threading.Semaphore:
    global _semaphore
    if _semaphore is None:
        with _semaphore_lock:
            if _semaphore is None:
                _semaphore = threading.Semaphore(_CONCURRENCY)
    return _semaphore


# Stop sequences prevent the model from hallucinating extra turns.
_STOP_SEQUENCES = [
    "\nuser\n",
    "\nUser:",
    "\nFile:",
    "<|im_end|>",
    "\nassistant\n",
]

_SYSTEM_PROMPT = (
    "You are a security auditor specializing in source code vulnerability analysis. "
    "Analyze the provided code for security vulnerabilities. "
    "For each finding report:\n"
    "  severity: CRITICAL | HIGH | MEDIUM | LOW\n"
    "  CWE: <cwe-id and name>\n"
    "  lines: <line numbers or range>\n"
    "  explanation: <one-line explanation>\n"
    "  fix: <concise fix description>\n\n"
    "If no issues exist, reply exactly: NO_ISSUES\n"
    "Do not include any text outside the structured findings."
)

_BASE_URL = "https://api.featherless.ai/v1"
_MODEL = "Virtue-AI-HUB/VulnLLM-R-7B"
_MAX_TOKENS = 4000
_TEMPERATURE = 0.1
_MAX_RETRIES = 3


def _trim_response(raw: str) -> str:
    """
    Keep only the reasoning section, discard hallucinated turns.

    The model sometimes emits:
      <analysis>\\n</think>\\nuser\\nGARBAGE...
    We keep only the content before </think> (or before hallucinated user lines).
    """
    # Split on </think> — keep the part before it
    content = raw.split("</think>")[0]
    # Also guard against hallucinated user turn without </think>
    content = content.split("\nuser\n")[0]
    content = content.split("\nUser:")[0]
    return content.strip()


def _call_featherless(code: str, context: str, api_key: str) -> str:
    """
    Synchronous HTTP call to Featherless with retry on 429/5xx.

    Wraps the call as a LangFuse generation when observability is configured.
    Returns the trimmed model response text.
    """
    url = f"{_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        # Gotcha #1: Cloudflare blocks default User-Agents.
        "User-Agent": "curl/8.4.0",
    }
    user_content = (
        f"Context: {context}\n\nCode to analyze:\n```\n{code}\n```"
        if context
        else f"Code to analyze:\n```\n{code}\n```"
    )
    payload: dict[str, Any] = {
        "model": _MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "temperature": _TEMPERATURE,
        "max_tokens": _MAX_TOKENS,
        # Gotcha #2: stop sequences prevent hallucinated turns.
        "stop": _STOP_SEQUENCES,
    }

    # LangFuse manual tracing for raw HTTP (bypasses LangChain callback handler)
    try:
        from observability import trace_featherless_call  # type: ignore
        _trace_ctx = trace_featherless_call(code[:300])
    except Exception:
        from contextlib import nullcontext
        _trace_ctx = nullcontext()

    last_error: Exception | None = None

    # Gotcha #3: hold a concurrency slot for the whole call (incl. retries) so
    # simultaneous in-flight requests never exceed the Featherless allotment.
    with _get_semaphore(), _trace_ctx as gen:
        for attempt in range(_MAX_RETRIES):
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=120)

                if response.status_code == 200:
                    data = response.json()
                    raw = data["choices"][0]["message"]["content"]
                    trimmed = _trim_response(raw)

                    # Feed token usage to LangFuse generation if available
                    if gen is not None:
                        usage = data.get("usage", {})
                        try:
                            gen.update(
                                output=trimmed,
                                usage_details={
                                    "input": usage.get("prompt_tokens", 0),
                                    "output": usage.get("completion_tokens", 0),
                                },
                            )
                        except Exception:
                            pass  # never let tracing break the scan

                    return trimmed

                if response.status_code in (429, 500, 502, 503, 504):
                    # Exponential backoff with jitter
                    wait = (2**attempt) + random.uniform(0, 1)
                    logger.warning(
                        "Featherless HTTP %d (attempt %d/%d) — retrying in %.1fs",
                        response.status_code,
                        attempt + 1,
                        _MAX_RETRIES,
                        wait,
                    )
                    time.sleep(wait)
                    last_error = RuntimeError(
                        f"HTTP {response.status_code}: {response.text[:200]}"
                    )
                    continue

                # Non-retryable error
                raise RuntimeError(
                    f"Featherless error HTTP {response.status_code}: {response.text[:500]}"
                )

            except requests.RequestException as exc:
                wait = (2**attempt) + random.uniform(0, 1)
                logger.warning(
                    "Featherless request failed (attempt %d/%d): %s — retrying in %.1fs",
                    attempt + 1,
                    _MAX_RETRIES,
                    exc,
                    wait,
                )
                time.sleep(wait)
                last_error = exc

    raise RuntimeError(
        f"Featherless call failed after {_MAX_RETRIES} attempts: {last_error}"
    )


@tool
def deep_vuln_analysis(code: str, context: str = "") -> str:
    """
    Deep vulnerability analysis using VulnLLM-R-7B (Featherless specialist model).

    Use this for suspicious or complex code snippets that need specialist review.
    The model is tuned for security vulnerability detection and will report
    severity (CRITICAL/HIGH/MEDIUM/LOW), CWE id, affected lines, explanation,
    and fix — or reply NO_ISSUES if clean.

    Args:
        code:    The source code snippet to analyze.
        context: Optional context (filename, module, what the code does).

    Returns:
        Structured vulnerability report or "NO_ISSUES".
    """
    api_key = os.environ.get("FEATHERLESS_API_KEY", "")
    if not api_key:
        return "ERROR: FEATHERLESS_API_KEY not set — specialist tool unavailable"

    try:
        return _call_featherless(code, context, api_key)
    except Exception as exc:
        logger.error("deep_vuln_analysis failed: %s", exc)
        return f"ERROR: deep_vuln_analysis failed: {exc}"
