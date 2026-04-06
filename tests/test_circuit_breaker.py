#!/usr/bin/env python3
"""
Tests for the Circuit Breaker module.

Verifies state transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED),
failure counting, recovery behavior, and statistics tracking.
"""

import pytest
import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.core.circuit_breaker import (
    CircuitBreaker, CircuitBreakerConfig, CircuitState,
    CircuitBreakerOpenError, ModuleCircuitBreakerManager
)


def run(coro):
    return asyncio.run(coro)


async def succeeding_func():
    return "ok"


async def failing_func():
    raise ValueError("boom")


class TestCircuitBreakerStateTransitions:

    def test_starts_closed(self):
        cb = CircuitBreaker("test")
        assert cb.state == CircuitState.CLOSED

    def test_opens_after_threshold_failures(self):
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test", config)

        for _ in range(3):
            with pytest.raises(ValueError):
                run(cb.call(failing_func))

        assert cb.state == CircuitState.OPEN

    def test_open_circuit_fails_fast(self):
        config = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker("test", config)

        # Trip the breaker
        for _ in range(2):
            with pytest.raises(ValueError):
                run(cb.call(failing_func))

        assert cb.state == CircuitState.OPEN

        # Next call should fail fast without running the function
        with pytest.raises(CircuitBreakerOpenError):
            run(cb.call(succeeding_func))

    def test_transitions_to_half_open_after_timeout(self):
        config = CircuitBreakerConfig(failure_threshold=2, recovery_timeout=0)
        cb = CircuitBreaker("test", config)

        for _ in range(2):
            with pytest.raises(ValueError):
                run(cb.call(failing_func))

        assert cb.state == CircuitState.OPEN

        # With recovery_timeout=0, next call should transition to HALF_OPEN
        # and attempt the function
        result = run(cb.call(succeeding_func))
        assert result == "ok"
        # After success in half-open, may still be half-open until success_threshold is met

    def test_closes_after_success_threshold_in_half_open(self):
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0,
            success_threshold=2
        )
        cb = CircuitBreaker("test", config)

        # Trip the breaker
        for _ in range(2):
            with pytest.raises(ValueError):
                run(cb.call(failing_func))

        assert cb.state == CircuitState.OPEN

        # With timeout=0, transitions to HALF_OPEN and succeeds
        run(cb.call(succeeding_func))
        assert cb.state == CircuitState.HALF_OPEN

        run(cb.call(succeeding_func))
        assert cb.state == CircuitState.CLOSED

    def test_failure_in_half_open_reopens(self):
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0,
            success_threshold=3
        )
        cb = CircuitBreaker("test", config)

        # Trip the breaker
        for _ in range(2):
            with pytest.raises(ValueError):
                run(cb.call(failing_func))

        # Transition to HALF_OPEN via success
        run(cb.call(succeeding_func))
        assert cb.state == CircuitState.HALF_OPEN

        # Fail again during HALF_OPEN
        with pytest.raises(ValueError):
            run(cb.call(failing_func))

        assert cb.state == CircuitState.OPEN

    def test_success_in_closed_resets_failure_count(self):
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test", config)

        # Two failures (below threshold)
        for _ in range(2):
            with pytest.raises(ValueError):
                run(cb.call(failing_func))

        assert cb.failure_count == 2

        # Success resets failure count
        run(cb.call(succeeding_func))
        assert cb.failure_count == 0
        assert cb.state == CircuitState.CLOSED


class TestCircuitBreakerStats:

    def test_tracks_total_calls(self):
        cb = CircuitBreaker("test")
        run(cb.call(succeeding_func))
        run(cb.call(succeeding_func))
        stats = cb.get_stats()
        assert stats['total_calls'] == 2
        assert stats['total_successes'] == 2
        assert stats['total_failures'] == 0

    def test_tracks_failures(self):
        cb = CircuitBreaker("test")
        with pytest.raises(ValueError):
            run(cb.call(failing_func))
        stats = cb.get_stats()
        assert stats['total_failures'] == 1
        assert stats['last_failure_time'] is not None

    def test_success_rate_calculation(self):
        config = CircuitBreakerConfig(failure_threshold=10)
        cb = CircuitBreaker("test", config)
        run(cb.call(succeeding_func))
        run(cb.call(succeeding_func))
        with pytest.raises(ValueError):
            run(cb.call(failing_func))

        stats = cb.get_stats()
        assert abs(stats['success_rate'] - 2 / 3) < 0.01


class TestCircuitBreakerReset:

    def test_manual_reset(self):
        config = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker("test", config)

        for _ in range(2):
            with pytest.raises(ValueError):
                run(cb.call(failing_func))

        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

        # Should work again after reset
        result = run(cb.call(succeeding_func))
        assert result == "ok"


class TestModuleCircuitBreakerManager:

    def test_creates_breakers_on_demand(self):
        mgr = ModuleCircuitBreakerManager()
        cb = mgr.get_circuit_breaker("headers")
        assert cb.name == "headers"
        assert cb.state == CircuitState.CLOSED

    def test_returns_same_breaker_for_same_module(self):
        mgr = ModuleCircuitBreakerManager()
        cb1 = mgr.get_circuit_breaker("headers")
        cb2 = mgr.get_circuit_breaker("headers")
        assert cb1 is cb2

    def test_execute_with_breaker(self):
        mgr = ModuleCircuitBreakerManager()
        result = run(mgr.execute_with_breaker("test_mod", succeeding_func))
        assert result == "ok"

    def test_get_all_stats(self):
        mgr = ModuleCircuitBreakerManager()
        run(mgr.execute_with_breaker("mod_a", succeeding_func))
        run(mgr.execute_with_breaker("mod_b", succeeding_func))
        stats = mgr.get_all_stats()
        assert "mod_a" in stats
        assert "mod_b" in stats
        assert stats["mod_a"]["total_calls"] == 1

    def test_reset_all(self):
        mgr = ModuleCircuitBreakerManager()
        config = CircuitBreakerConfig(failure_threshold=1)
        mgr.circuit_breakers["mod_a"] = CircuitBreaker("mod_a", config)

        with pytest.raises(ValueError):
            run(mgr.execute_with_breaker("mod_a", failing_func))

        assert mgr.circuit_breakers["mod_a"].state == CircuitState.OPEN
        mgr.reset_all()
        assert mgr.circuit_breakers["mod_a"].state == CircuitState.CLOSED
