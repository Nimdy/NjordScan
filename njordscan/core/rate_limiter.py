"""
Rate Limiting for API Calls and Resource Management

Implements token bucket and sliding window rate limiting algorithms.
"""

import time
import asyncio
from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class RateLimitStrategy(Enum):
    """Rate limiting strategies."""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"

@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_second: float = 10.0
    burst_capacity: int = 20
    strategy: RateLimitStrategy = RateLimitStrategy.TOKEN_BUCKET

class TokenBucketRateLimiter:
    """Token bucket rate limiter implementation."""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.tokens = float(config.burst_capacity)
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> bool:
        """Acquire tokens from bucket."""
        async with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            
            # Add tokens based on time passed
            tokens_to_add = time_passed * self.config.requests_per_second
            self.tokens = min(self.config.burst_capacity, self.tokens + tokens_to_add)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    async def wait_for_tokens(self, tokens: int = 1) -> None:
        """Wait until tokens are available."""
        while not await self.acquire(tokens):
            # Calculate wait time
            wait_time = tokens / self.config.requests_per_second
            await asyncio.sleep(min(wait_time, 1.0))  # Cap at 1 second

class SlidingWindowRateLimiter:
    """Sliding window rate limiter implementation."""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.window_size = 1.0  # 1 second window
        self.requests = []
        self.lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> bool:
        """Check if request is within rate limit."""
        async with self.lock:
            now = time.time()
            
            # Remove old requests outside window
            cutoff = now - self.window_size
            self.requests = [req_time for req_time in self.requests if req_time > cutoff]
            
            # Check if we can make the request
            if len(self.requests) + tokens <= self.config.requests_per_second:
                # Add new requests
                for _ in range(tokens):
                    self.requests.append(now)
                return True
            
            return False
    
    async def wait_for_tokens(self, tokens: int = 1) -> None:
        """Wait until request can be made."""
        while not await self.acquire(tokens):
            await asyncio.sleep(0.1)

class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on response times and errors."""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.base_limiter = TokenBucketRateLimiter(config)
        
        # Adaptive parameters
        self.current_rate = config.requests_per_second
        self.error_count = 0
        self.response_times = []
        self.last_adjustment = time.time()
        
        # Thresholds
        self.error_threshold = 0.1  # 10% error rate
        self.response_time_threshold = 2.0  # 2 seconds
        self.adjustment_interval = 30.0  # 30 seconds
    
    async def acquire(self, tokens: int = 1) -> bool:
        """Acquire with adaptive rate limiting."""
        self._maybe_adjust_rate()
        return await self.base_limiter.acquire(tokens)
    
    async def wait_for_tokens(self, tokens: int = 1) -> None:
        """Wait for tokens with adaptive limiting."""
        await self.base_limiter.wait_for_tokens(tokens)
    
    def record_success(self, response_time: float):
        """Record successful request."""
        self.response_times.append(response_time)
        if len(self.response_times) > 100:
            self.response_times.pop(0)
    
    def record_error(self):
        """Record failed request."""
        self.error_count += 1
    
    def _maybe_adjust_rate(self):
        """Adjust rate based on performance metrics."""
        now = time.time()
        if now - self.last_adjustment < self.adjustment_interval:
            return
        
        self.last_adjustment = now
        
        # Calculate metrics
        total_requests = len(self.response_times) + self.error_count
        if total_requests == 0:
            return
        
        error_rate = self.error_count / total_requests
        avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        
        # Adjust rate based on metrics
        if error_rate > self.error_threshold or avg_response_time > self.response_time_threshold:
            # Decrease rate
            self.current_rate = max(1.0, self.current_rate * 0.8)
            logger.warning(f"Decreasing rate to {self.current_rate} req/s due to errors/latency")
        elif error_rate < 0.05 and avg_response_time < 1.0:
            # Increase rate
            self.current_rate = min(self.config.requests_per_second, self.current_rate * 1.2)
            logger.info(f"Increasing rate to {self.current_rate} req/s")
        
        # Update base limiter
        self.base_limiter.config.requests_per_second = self.current_rate
        
        # Reset counters
        self.error_count = 0
        self.response_times.clear()

class GlobalRateLimiter:
    """Global rate limiter managing multiple endpoints and modules."""
    
    def __init__(self):
        self.limiters: Dict[str, AdaptiveRateLimiter] = {}
        self.default_config = RateLimitConfig(requests_per_second=5.0, burst_capacity=10)
    
    def get_limiter(self, endpoint: str, config: Optional[RateLimitConfig] = None) -> AdaptiveRateLimiter:
        """Get or create rate limiter for endpoint."""
        if endpoint not in self.limiters:
            limiter_config = config or self.default_config
            self.limiters[endpoint] = AdaptiveRateLimiter(limiter_config)
        
        return self.limiters[endpoint]
    
    async def acquire(self, endpoint: str, tokens: int = 1) -> bool:
        """Acquire tokens for specific endpoint."""
        limiter = self.get_limiter(endpoint)
        return await limiter.acquire(tokens)
    
    async def wait_for_tokens(self, endpoint: str, tokens: int = 1) -> None:
        """Wait for tokens for specific endpoint."""
        limiter = self.get_limiter(endpoint)
        await limiter.wait_for_tokens(tokens)
    
    def record_success(self, endpoint: str, response_time: float):
        """Record successful request for endpoint."""
        if endpoint in self.limiters:
            self.limiters[endpoint].record_success(response_time)
    
    def record_error(self, endpoint: str):
        """Record error for endpoint."""
        if endpoint in self.limiters:
            self.limiters[endpoint].record_error()
    
    def get_stats(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all rate limiters."""
        stats = {}
        for endpoint, limiter in self.limiters.items():
            stats[endpoint] = {
                'current_rate': limiter.current_rate,
                'configured_rate': limiter.config.requests_per_second,
                'error_count': limiter.error_count,
                'avg_response_time': sum(limiter.response_times) / len(limiter.response_times) if limiter.response_times else 0
            }
        return stats

# Global instance
global_rate_limiter = GlobalRateLimiter()
