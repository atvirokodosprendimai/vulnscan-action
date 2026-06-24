"""
Tests for tools/specialist.py — all offline, no real HTTP calls.

Assertions:
  (a) Request sends User-Agent: curl/8.4.0
  (b) Response trimming: "real analysis</think>\\nuser\\nGARBAGE" -> "real analysis"
  (c) 429-then-200 retries once and succeeds
  (d) Concurrency gate caps simultaneous in-flight calls
"""
from __future__ import annotations

import os
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, call


class TestSpecialistUserAgent:
    """(a) User-Agent header must be curl/8.4.0."""

    def test_user_agent_header(self):
        captured_headers = {}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured_headers.update(headers or {})
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": "NO_ISSUES"}}]
            }
            return mock_resp

        with patch("tools.specialist.requests.post", side_effect=fake_post):
            with patch.dict(os.environ, {"FEATHERLESS_API_KEY": "test-key"}):
                from tools.specialist import _call_featherless
                _call_featherless("x = 1", "", "test-key")

        assert captured_headers.get("User-Agent") == "curl/8.4.0", (
            f"Expected 'curl/8.4.0', got {captured_headers.get('User-Agent')!r}"
        )


class TestSpecialistResponseTrimming:
    """(b) Trim hallucinated turns after </think> and after \\nuser\\n."""

    def test_trim_after_think_tag(self):
        from tools.specialist import _trim_response

        raw = "real analysis</think>\nuser\nGARBAGE HALLUCINATED TURN"
        result = _trim_response(raw)
        assert result == "real analysis", f"Got: {result!r}"

    def test_trim_after_user_turn_without_think(self):
        from tools.specialist import _trim_response

        raw = "real analysis\nuser\nGARBAGE"
        result = _trim_response(raw)
        assert result == "real analysis", f"Got: {result!r}"

    def test_trim_preserves_clean_content(self):
        from tools.specialist import _trim_response

        raw = "severity: HIGH\ncwe: CWE-89\nlines: 42\nexplanation: SQLi"
        result = _trim_response(raw)
        assert result == raw.strip()

    def test_trim_after_user_colon(self):
        from tools.specialist import _trim_response

        raw = "finding here\nUser: some hallucinated prompt"
        result = _trim_response(raw)
        assert result == "finding here"


class TestSpecialistRetry:
    """(c) 429 -> retry -> 200 succeeds."""

    def test_retry_on_429(self):
        call_count = 0

        def fake_post(url, json=None, headers=None, timeout=None):
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            if call_count == 1:
                mock_resp.status_code = 429
                mock_resp.text = "rate limited"
            else:
                mock_resp.status_code = 200
                mock_resp.json.return_value = {
                    "choices": [{"message": {"content": "RESULT</think>\nuser\nGARBAGE"}}]
                }
            return mock_resp

        with patch("tools.specialist.requests.post", side_effect=fake_post):
            with patch("tools.specialist.time.sleep"):  # don't actually sleep
                from tools.specialist import _call_featherless
                result = _call_featherless("code", "", "test-key")

        assert call_count == 2, f"Expected 2 calls (1 retry), got {call_count}"
        assert result == "RESULT"

    def test_all_retries_exhausted(self):
        """After MAX_RETRIES all fail, raises RuntimeError."""

        def always_429(url, json=None, headers=None, timeout=None):
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_resp.text = "still rate limited"
            return mock_resp

        with patch("tools.specialist.requests.post", side_effect=always_429):
            with patch("tools.specialist.time.sleep"):
                import pytest
                from tools.specialist import _call_featherless
                with pytest.raises(RuntimeError, match="failed after"):
                    _call_featherless("code", "", "test-key")


class TestSpecialistConcurrencyGate:
    """(d) Concurrency semaphore limits simultaneous in-flight calls."""

    def test_semaphore_size(self):
        """Semaphore is created with the configured concurrency size."""
        import tools.specialist as specialist_module

        # Reset the global semaphore so we can test its construction
        original = specialist_module._semaphore
        specialist_module._semaphore = None
        original_concurrency = specialist_module._CONCURRENCY
        specialist_module._CONCURRENCY = 3

        try:
            sem = specialist_module._get_semaphore()
            # threading.Semaphore stores its counter in _value
            assert sem._value == 3, f"Expected semaphore value 3, got {sem._value}"
        finally:
            specialist_module._semaphore = original
            specialist_module._CONCURRENCY = original_concurrency

    def test_concurrent_calls_capped(self):
        """
        The module's OWN threading.Semaphore must cap simultaneous in-flight
        calls. fake_post does not gate itself — it only records observed
        concurrency, so any cap seen comes from the production gate in
        _call_featherless.
        """
        import tools.specialist as specialist_module

        # Force the real gate to size 2 and reset the lazy singleton.
        original_sem = specialist_module._semaphore
        original_conc = specialist_module._CONCURRENCY
        specialist_module._semaphore = None
        specialist_module._CONCURRENCY = 2

        max_concurrent = 0
        current_concurrent = 0
        lock = threading.Lock()

        def fake_post(url, json=None, headers=None, timeout=None):
            nonlocal max_concurrent, current_concurrent
            with lock:
                current_concurrent += 1
                max_concurrent = max(max_concurrent, current_concurrent)
            time.sleep(0.02)  # hold the slot so overlap is observable
            with lock:
                current_concurrent -= 1
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": "NO_ISSUES"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }
            return mock_resp

        results = []

        def run_one():
            try:
                results.append(specialist_module._call_featherless("x=1", "", "k"))
            except Exception:
                results.append("error")

        try:
            with patch("tools.specialist.requests.post", side_effect=fake_post):
                threads = [threading.Thread(target=run_one) for _ in range(6)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            # The production gate must hold concurrency at or below 2 ...
            assert max_concurrent <= 2, (
                f"production gate failed: max_concurrent={max_concurrent} > 2"
            )
            # ... and the test must actually have exercised concurrency.
            assert max_concurrent >= 2, (
                f"test ineffective: never reached 2 concurrent (got {max_concurrent})"
            )
            assert all(r == "NO_ISSUES" for r in results), results
        finally:
            specialist_module._semaphore = original_sem
            specialist_module._CONCURRENCY = original_conc
