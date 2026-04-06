#!/usr/bin/env python3
"""
Tests for the Rate Limiter module.

Verifies token bucket, sliding window, adaptive rate limiting,
and the global rate limiter manager.
"""

import pytest
import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.core.rate_limiter import (
    TokenBucketRateLimiter, SlidingWindowRateLimiter,
    AdaptiveRateLimiter, GlobalRateLimiter,
    RateLimitConfig, RateLimitStrategy
)


def run(coro):
    return asyncio.run(coro)


class TestTokenBucketRateLimiter:

    def test_acquire_within_capacity(self):
        """Should succeed when tokens are available."""
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=5)
        limiter = TokenBucketRateLimiter(config)
        assert run(limiter.acquire(1)) is True

    def test_acquire_consumes_tokens(self):
        """Acquiring tokens should reduce available count."""
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=3)
        limiter = TokenBucketRateLimiter(config)

        assert run(limiter.acquire(1)) is True
        assert run(limiter.acquire(1)) is True
        assert run(limiter.acquire(1)) is True
        # Fourth request should fail (burst_capacity=3)
        assert run(limiter.acquire(1)) is False

    def test_acquire_multiple_tokens(self):
        """Should support acquiring multiple tokens at once."""
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=5)
        limiter = TokenBucketRateLimiter(config)

        assert run(limiter.acquire(5)) is True
        assert run(limiter.acquire(1)) is False

    def test_tokens_replenish_over_time(self):
        """Tokens should replenish based on rate and elapsed time."""
        config = RateLimitConfig(requests_per_second=1000.0, burst_capacity=5)
        limiter = TokenBucketRateLimiter(config)

        # Drain all tokens
        run(limiter.acquire(5))
        assert run(limiter.acquire(1)) is False

        # Simulate time passing by adjusting last_update
        limiter.last_update -= 0.01  # 10ms at 1000/s = 10 tokens
        assert run(limiter.acquire(1)) is True


class TestSlidingWindowRateLimiter:

    def test_acquire_within_limit(self):
        config = RateLimitConfig(requests_per_second=5.0)
        limiter = SlidingWindowRateLimiter(config)
        for _ in range(5):
            assert run(limiter.acquire()) is True

    def test_acquire_over_limit(self):
        config = RateLimitConfig(requests_per_second=3.0)
        limiter = SlidingWindowRateLimiter(config)
        for _ in range(3):
            assert run(limiter.acquire()) is True
        assert run(limiter.acquire()) is False

    def test_old_requests_expire(self):
        """Requests outside the window should be removed."""
        config = RateLimitConfig(requests_per_second=2.0)
        limiter = SlidingWindowRateLimiter(config)

        run(limiter.acquire())
        run(limiter.acquire())
        assert run(limiter.acquire()) is False

        # Simulate window expiry
        limiter.requests = [t - 2.0 for t in limiter.requests]
        assert run(limiter.acquire()) is True


class TestAdaptiveRateLimiter:

    def test_initial_rate_matches_config(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=20)
        limiter = AdaptiveRateLimiter(config)
        assert limiter.current_rate == 10.0

    def test_rate_decreases_on_errors(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=20)
        limiter = AdaptiveRateLimiter(config)
        limiter.last_adjustment = time.time() - 60  # Force adjustment window

        # Record many errors
        for _ in range(10):
            limiter.record_error()
        limiter.record_success(0.1)  # Need at least one response time

        limiter._maybe_adjust_rate()
        assert limiter.current_rate < 10.0

    def test_rate_increases_on_good_performance(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=20)
        limiter = AdaptiveRateLimiter(config)
        limiter.current_rate = 5.0  # Start below max
        limiter.last_adjustment = time.time() - 60

        # Record fast, error-free performance
        for _ in range(20):
            limiter.record_success(0.1)

        limiter._maybe_adjust_rate()
        assert limiter.current_rate > 5.0
        assert limiter.current_rate <= 10.0

    def test_rate_does_not_exceed_configured_max(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=20)
        limiter = AdaptiveRateLimiter(config)
        limiter.current_rate = 9.5
        limiter.last_adjustment = time.time() - 60

        for _ in range(20):
            limiter.record_success(0.1)

        limiter._maybe_adjust_rate()
        assert limiter.current_rate <= 10.0

    def test_no_adjustment_within_interval(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=20)
        limiter = AdaptiveRateLimiter(config)
        # last_adjustment is recent (now), so no adjustment should happen
        original_rate = limiter.current_rate

        for _ in range(10):
            limiter.record_error()

        limiter._maybe_adjust_rate()
        assert limiter.current_rate == original_rate


class TestGlobalRateLimiter:

    def test_creates_limiters_per_endpoint(self):
        g = GlobalRateLimiter()
        run(g.acquire("api_a"))
        run(g.acquire("api_b"))
        assert "api_a" in g.limiters
        assert "api_b" in g.limiters

    def test_acquire_returns_bool(self):
        g = GlobalRateLimiter()
        result = run(g.acquire("test_endpoint"))
        assert isinstance(result, bool)

    def test_record_success_updates_stats(self):
        g = GlobalRateLimiter()
        run(g.acquire("ep1"))
        g.record_success("ep1", 0.05)
        stats = g.get_stats()
        assert stats["ep1"]["avg_response_time"] == pytest.approx(0.05)

    def test_record_error_updates_stats(self):
        g = GlobalRateLimiter()
        run(g.acquire("ep1"))
        g.record_error("ep1")
        stats = g.get_stats()
        assert stats["ep1"]["error_count"] == 1

    def test_stats_empty_when_no_endpoints(self):
        g = GlobalRateLimiter()
        assert g.get_stats() == {}

    def test_custom_config_per_endpoint(self):
        g = GlobalRateLimiter()
        custom = RateLimitConfig(requests_per_second=100.0, burst_capacity=50)
        limiter = g.get_limiter("fast_endpoint", custom)
        assert limiter.config.requests_per_second == 100.0
