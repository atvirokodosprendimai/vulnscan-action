"""
Tests for observability.py — all offline (no Langfuse server, no keys).

Regression guard: the langfuse v4 SDK exposes generations via
start_as_current_observation(as_type="generation"), NOT start_as_current_generation
(which existed only in v3). A prior build called the v3 method and the specialist
generation tracing silently no-op'd. These tests pin the correct v4 call.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import observability


class TestNoOpWhenUnconfigured:
    """With no Langfuse keys, every entry point is a safe no-op."""

    def test_get_callbacks_empty(self):
        with patch.dict(os.environ, {}, clear=False):
            for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"):
                os.environ.pop(k, None)
            assert observability.get_callbacks() == []

    def test_flush_noop(self):
        for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"):
            os.environ.pop(k, None)
        observability.flush()  # must not raise

    def test_trace_featherless_returns_context(self):
        for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"):
            os.environ.pop(k, None)
        with observability.trace_featherless_call("code") as gen:
            assert gen is None  # nullcontext yields None


class TestGenerationUsesV4API:
    """When configured, the specialist generation must use the v4 method."""

    def test_uses_start_as_current_observation_generation(self):
        fake_client = MagicMock()
        env = {
            "LANGFUSE_PUBLIC_KEY": "pk-lf-test",
            "LANGFUSE_SECRET_KEY": "sk-lf-test",
        }
        # get_client is imported lazily inside the function, so patch the source.
        with patch.dict(os.environ, env):
            with patch("langfuse.get_client", return_value=fake_client):
                observability.trace_featherless_call("snippet", model="m")

        # The v3 method must NOT be used; the v4 observation API must be.
        assert not fake_client.start_as_current_generation.called
        fake_client.start_as_current_observation.assert_called_once()
        kwargs = fake_client.start_as_current_observation.call_args.kwargs
        assert kwargs.get("as_type") == "generation"
        assert kwargs.get("model") == "m"
