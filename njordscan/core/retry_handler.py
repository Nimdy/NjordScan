"""
Intelligent Retry Handler with Exponential Backoff

Handles transient failures with smart retry strategies.
"""

import asyncio
import random
import time
from typing import Any, Callable, List, Optional, Type, Union
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class RetryStrategy(Enum):
    """Retry strategies."""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_DELAY = "fixed_delay"
    FIBONACCI_BACKOFF = "fibonacci_backoff"

@dataclass
class RetryConfig:
    """Retry configuration."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    retryable_exceptions: List[Type[Exception]] = None

class RetryHandler:
    """Intelligent retry handler with multiple strategies."""
    
    def __init__(self, config: RetryConfig = None):
        self.config = config or RetryConfig()
        if self.config.retryable_exceptions is None:
            self.config.retryable_exceptions = [
                ConnectionError,
                TimeoutError,
                OSError,
                asyncio.TimeoutError
            ]
        
        # Statistics
        self.total_attempts = 0
        self.total_retries = 0
        self.successful_retries = 0
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        last_exception = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            self.total_attempts += 1
            
            try:
                result = await func(*args, **kwargs)
                
                if attempt > 1:
                    self.successful_retries += 1
                    logger.info(f"Function succeeded on attempt {attempt}")
                
                return result
                
            except Exception as e:
                last_exception = e
                
                # Check if exception is retryable
                if not self._is_retryable_exception(e):
                    logger.debug(f"Non-retryable exception: {type(e).__name__}")
                    raise e
                
                # Don't retry on last attempt
                if attempt == self.config.max_attempts:
                    logger.warning(f"Max attempts ({self.config.max_attempts}) reached")
                    break
                
                # Calculate delay and wait
                delay = self._calculate_delay(attempt)
                logger.warning(f"Attempt {attempt} failed: {e}. Retrying in {delay:.2f}s")
                
                self.total_retries += 1
                await asyncio.sleep(delay)
        
        # All attempts failed
        raise last_exception
    
    def _is_retryable_exception(self, exception: Exception) -> bool:
        """Check if exception is retryable."""
        return any(isinstance(exception, exc_type) for exc_type in self.config.retryable_exceptions)
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay based on retry strategy."""
        if self.config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.base_delay * (self.config.exponential_base ** (attempt - 1))
        elif self.config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.base_delay * attempt
        elif self.config.strategy == RetryStrategy.FIXED_DELAY:
            delay = self.config.base_delay
        elif self.config.strategy == RetryStrategy.FIBONACCI_BACKOFF:
            delay = self.config.base_delay * self._fibonacci(attempt)
        else:
            delay = self.config.base_delay
        
        # Apply max delay limit
        delay = min(delay, self.config.max_delay)
        
        # Add jitter to avoid thundering herd
        if self.config.jitter:
            jitter_range = delay * 0.1  # 10% jitter
            delay += random.uniform(-jitter_range, jitter_range)
        
        return max(0.1, delay)  # Minimum 100ms delay
    
    def _fibonacci(self, n: int) -> int:
        """Calculate nth Fibonacci number."""
        if n <= 1:
            return 1
        a, b = 1, 1
        for _ in range(2, n + 1):
            a, b = b, a + b
        return b
    
    def get_stats(self) -> dict:
        """Get retry statistics."""
        return {
            'total_attempts': self.total_attempts,
            'total_retries': self.total_retries,
            'successful_retries': self.successful_retries,
            'retry_success_rate': (self.successful_retries / self.total_retries) if self.total_retries > 0 else 0
        }

class ModuleRetryManager:
    """Manages retry handlers for different modules."""
    
    def __init__(self):
        self.retry_handlers: dict[str, RetryHandler] = {}
        self.module_configs = {
            'headers': RetryConfig(max_attempts=2, base_delay=0.5),
            'runtime': RetryConfig(max_attempts=3, base_delay=1.0),
            'dependencies': RetryConfig(max_attempts=5, base_delay=2.0, max_delay=30.0),
            'ai_endpoints': RetryConfig(max_attempts=3, base_delay=1.0, max_delay=10.0)
        }
    
    def get_retry_handler(self, module_name: str) -> RetryHandler:
        """Get or create retry handler for module."""
        if module_name not in self.retry_handlers:
            config = self.module_configs.get(module_name, RetryConfig())
            self.retry_handlers[module_name] = RetryHandler(config)
        
        return self.retry_handlers[module_name]
    
    async def execute_with_retry(self, module_name: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with module-specific retry logic."""
        retry_handler = self.get_retry_handler(module_name)
        return await retry_handler.execute(func, *args, **kwargs)
    
    def get_all_stats(self) -> dict[str, dict]:
        """Get statistics for all retry handlers."""
        return {name: handler.get_stats() for name, handler in self.retry_handlers.items()}

# Decorator for easy retry functionality
def retry(config: RetryConfig = None):
    """Decorator to add retry functionality to async functions."""
    def decorator(func: Callable):
        retry_handler = RetryHandler(config)
        
        async def wrapper(*args, **kwargs):
            return await retry_handler.execute(func, *args, **kwargs)
        
        wrapper.retry_stats = retry_handler.get_stats
        return wrapper
    
    return decorator

# Context manager for retry operations
class RetryContext:
    """Context manager for retry operations."""
    
    def __init__(self, config: RetryConfig = None):
        self.retry_handler = RetryHandler(config)
        self.result = None
        self.exception = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type and self.retry_handler._is_retryable_exception(exc_val):
            # Store exception for potential retry
            self.exception = exc_val
            return True  # Suppress exception
        return False
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function within retry context."""
        return await self.retry_handler.execute(func, *args, **kwargs)
