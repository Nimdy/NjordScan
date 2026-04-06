#!/usr/bin/env python3
"""
Tests for core infrastructure: circuit breaker and rate limiter.

Tests real state transitions and rate limiting behavior.
"""

import pytest
import asyncio
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.core.circuit_breaker import (
    CircuitBreaker, CircuitBreakerConfig, CircuitState,
    CircuitBreakerOpenError, ModuleCircuitBreakerManager
)
from njordscan.core.rate_limiter import (
    TokenBucketRateLimiter, SlidingWindowRateLimiter,
    AdaptiveRateLimiter, GlobalRateLimiter, RateLimitConfig
)


# ===================================================================== #
#  Circuit Breaker
# ===================================================================== #

class TestCircuitBreaker:

    def _make_breaker(self, threshold=3, recovery=0.2, success_threshold=2):
        config = CircuitBreakerConfig(
            failure_threshold=threshold,
            recovery_timeout=recovery,
            success_threshold=success_threshold
        )
        return CircuitBreaker("test", config)

    def test_starts_closed(self):
        cb = self._make_breaker()
        assert cb.state == CircuitState.CLOSED

    def test_success_keeps_closed(self):
        cb = self._make_breaker()
        async def ok():
            return 42
        result = asyncio.run(cb.call(ok))
        assert result == 42
        assert cb.state == CircuitState.CLOSED

    def test_opens_after_threshold_failures(self):
        cb = self._make_breaker(threshold=3)
        async def fail():
            raise ValueError("boom")
        for _ in range(3):
            with pytest.raises(ValueError):
                asyncio.run(cb.call(fail))
        assert cb.state == CircuitState.OPEN

    def test_open_circuit_fails_fast(self):
        cb = self._make_breaker(threshold=1)
        async def fail():
            raise ValueError("boom")
        with pytest.raises(ValueError):
            asyncio.run(cb.call(fail))
        assert cb.state == CircuitState.OPEN
        with pytest.raises(CircuitBreakerOpenError):
            asyncio.run(cb.call(fail))

    def test_half_open_after_recovery_timeout(self):
        cb = self._make_breaker(threshold=1, recovery=0.05)
        async def fail():
            raise ValueError("boom")
        with pytest.raises(ValueError):
            asyncio.run(cb.call(fail))
        assert cb.state == CircuitState.OPEN
        time.sleep(0.06)
        async def ok():
            return "recovered"
        result = asyncio.run(cb.call(ok))
        assert result == "recovered"

    def test_half_open_closes_after_success_threshold(self):
        cb = self._make_breaker(threshold=1, recovery=0.05, success_threshold=2)
        async def fail():
            raise ValueError("boom")
        async def ok():
            return "ok"
        # Trip the breaker
        with pytest.raises(ValueError):
            asyncio.run(cb.call(fail))
        assert cb.state == CircuitState.OPEN
        time.sleep(0.06)
        # First success -> half_open
        asyncio.run(cb.call(ok))
        assert cb.state == CircuitState.HALF_OPEN
        # Second success -> closed
        asyncio.run(cb.call(ok))
        assert cb.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        cb = self._make_breaker(threshold=1, recovery=0.05)
        async def fail():
            raise ValueError("boom")
        async def ok():
            return "ok"
        with pytest.raises(ValueError):
            asyncio.run(cb.call(fail))
        time.sleep(0.06)
        # First call transitions to half-open, but if it fails -> back to open
        with pytest.raises(ValueError):
            asyncio.run(cb.call(fail))
        assert cb.state == CircuitState.OPEN

    def test_success_resets_failure_count(self):
        cb = self._make_breaker(threshold=3)
        async def fail():
            raise ValueError("boom")
        async def ok():
            return "ok"
        # 2 failures
        for _ in range(2):
            with pytest.raises(ValueError):
                asyncio.run(cb.call(fail))
        assert cb.failure_count == 2
        # 1 success resets
        asyncio.run(cb.call(ok))
        assert cb.failure_count == 0
        assert cb.state == CircuitState.CLOSED

    def test_stats_accuracy(self):
        cb = self._make_breaker(threshold=5)
        async def ok():
            return 1
        async def fail():
            raise ValueError("x")
        asyncio.run(cb.call(ok))
        asyncio.run(cb.call(ok))
        with pytest.raises(ValueError):
            asyncio.run(cb.call(fail))
        stats = cb.get_stats()
        assert stats['total_calls'] == 3
        assert stats['total_successes'] == 2
        assert stats['total_failures'] == 1
        assert abs(stats['success_rate'] - 2/3) < 0.01

    def test_manual_reset(self):
        cb = self._make_breaker(threshold=1)
        async def fail():
            raise ValueError("x")
        with pytest.raises(ValueError):
            asyncio.run(cb.call(fail))
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0


class TestModuleCircuitBreakerManager:

    def test_creates_breakers_on_demand(self):
        mgr = ModuleCircuitBreakerManager()
        b1 = mgr.get_circuit_breaker("mod_a")
        b2 = mgr.get_circuit_breaker("mod_b")
        assert b1 is not b2
        assert mgr.get_circuit_breaker("mod_a") is b1  # same instance

    def test_execute_with_breaker(self):
        mgr = ModuleCircuitBreakerManager()
        async def ok():
            return 99
        result = asyncio.run(mgr.execute_with_breaker("test_mod", ok))
        assert result == 99

    def test_get_all_stats(self):
        mgr = ModuleCircuitBreakerManager()
        async def ok():
            return 1
        asyncio.run(mgr.execute_with_breaker("a", ok))
        asyncio.run(mgr.execute_with_breaker("b", ok))
        stats = mgr.get_all_stats()
        assert 'a' in stats and 'b' in stats
        assert stats['a']['total_calls'] == 1

    def test_reset_all(self):
        mgr = ModuleCircuitBreakerManager()
        async def fail():
            raise ValueError("x")
        for _ in range(3):
            with pytest.raises(ValueError):
                asyncio.run(mgr.execute_with_breaker("mod", fail))
        mgr.reset_all()
        assert mgr.get_circuit_breaker("mod").state == CircuitState.CLOSED


# ===================================================================== #
#  Rate Limiter
# ===================================================================== #

class TestTokenBucketRateLimiter:

    def test_allows_within_burst(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=5)
        limiter = TokenBucketRateLimiter(config)
        results = []
        async def test():
            for _ in range(5):
                results.append(await limiter.acquire())
        asyncio.run(test())
        assert all(results), "Should allow up to burst capacity"

    def test_rejects_over_burst(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=3)
        limiter = TokenBucketRateLimiter(config)
        results = []
        async def test():
            for _ in range(5):
                results.append(await limiter.acquire())
        asyncio.run(test())
        assert results[:3] == [True, True, True]
        assert not all(results[3:]), "Should reject when burst exhausted"

    def test_tokens_replenish_over_time(self):
        config = RateLimitConfig(requests_per_second=100.0, burst_capacity=2)
        limiter = TokenBucketRateLimiter(config)
        async def test():
            await limiter.acquire()
            await limiter.acquire()
            denied = not await limiter.acquire()
            assert denied, "Should be denied after burst"
            await asyncio.sleep(0.05)  # Wait for replenishment
            allowed = await limiter.acquire()
            assert allowed, "Should be allowed after replenishment"
        asyncio.run(test())


class TestSlidingWindowRateLimiter:

    def test_allows_within_limit(self):
        config = RateLimitConfig(requests_per_second=5.0)
        limiter = SlidingWindowRateLimiter(config)
        async def test():
            results = [await limiter.acquire() for _ in range(5)]
            return results
        results = asyncio.run(test())
        assert all(results)

    def test_rejects_over_limit(self):
        config = RateLimitConfig(requests_per_second=3.0)
        limiter = SlidingWindowRateLimiter(config)
        async def test():
            results = [await limiter.acquire() for _ in range(5)]
            return results
        results = asyncio.run(test())
        assert sum(results) == 3  # Only 3 allowed


class TestAdaptiveRateLimiter:

    def test_records_success(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=10)
        limiter = AdaptiveRateLimiter(config)
        limiter.record_success(0.5)
        limiter.record_success(0.3)
        assert len(limiter.response_times) == 2

    def test_records_error(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=10)
        limiter = AdaptiveRateLimiter(config)
        limiter.record_error()
        limiter.record_error()
        assert limiter.error_count == 2

    def test_decreases_rate_on_errors(self):
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=20)
        limiter = AdaptiveRateLimiter(config)
        # Record lots of errors
        for _ in range(20):
            limiter.record_error()
        limiter.record_success(0.5)  # Need at least one for avg calc
        # Force adjustment by setting last_adjustment far in past
        limiter.last_adjustment = time.time() - 60
        limiter._maybe_adjust_rate()
        assert limiter.current_rate < 10.0, "Rate should decrease on high error rate"


class TestGlobalRateLimiter:

    def test_separate_endpoints(self):
        g = GlobalRateLimiter()
        l1 = g.get_limiter("api_a")
        l2 = g.get_limiter("api_b")
        assert l1 is not l2

    def test_stats_per_endpoint(self):
        g = GlobalRateLimiter()
        g.get_limiter("ep1")
        g.record_success("ep1", 0.1)
        g.record_error("ep1")
        stats = g.get_stats()
        assert 'ep1' in stats
        assert stats['ep1']['error_count'] == 1
