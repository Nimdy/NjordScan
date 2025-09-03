"""
Circuit Breaker Pattern for Module Reliability

Prevents cascading failures by temporarily disabling failing modules.
"""

import time
import asyncio
from enum import Enum
from typing import Any, Callable, Dict, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, calls fail fast
    HALF_OPEN = "half_open" # Testing if service has recovered

@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5
    recovery_timeout: int = 60  # seconds
    expected_exception: type = Exception
    success_threshold: int = 3  # successes needed to close from half-open

class CircuitBreaker:
    """Circuit breaker implementation for module reliability."""
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        
        # State tracking
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        
        # Statistics
        self.total_calls = 0
        self.total_failures = 0
        self.total_successes = 0
        
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        self.total_calls += 1
        
        # Check if circuit should transition states
        self._update_state()
        
        if self.state == CircuitState.OPEN:
            logger.warning(f"Circuit breaker {self.name} is OPEN - failing fast")
            raise CircuitBreakerOpenError(f"Circuit breaker {self.name} is open")
        
        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
            
        except self.config.expected_exception as e:
            self._on_failure()
            raise e
    
    def _update_state(self):
        """Update circuit breaker state based on current conditions."""
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                logger.info(f"Circuit breaker {self.name} transitioning to HALF_OPEN")
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt recovery."""
        if not self.last_failure_time:
            return False
        return (time.time() - self.last_failure_time) >= self.config.recovery_timeout
    
    def _on_success(self):
        """Handle successful call."""
        self.total_successes += 1
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                logger.info(f"Circuit breaker {self.name} transitioning to CLOSED")
                self.state = CircuitState.CLOSED
                self.failure_count = 0
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success
            self.failure_count = 0
    
    def _on_failure(self):
        """Handle failed call."""
        self.total_failures += 1
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if (self.state == CircuitState.CLOSED and 
            self.failure_count >= self.config.failure_threshold):
            logger.warning(f"Circuit breaker {self.name} transitioning to OPEN")
            self.state = CircuitState.OPEN
        elif self.state == CircuitState.HALF_OPEN:
            logger.warning(f"Circuit breaker {self.name} failed during recovery - back to OPEN")
            self.state = CircuitState.OPEN
    
    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            'name': self.name,
            'state': self.state.value,
            'total_calls': self.total_calls,
            'total_successes': self.total_successes,
            'total_failures': self.total_failures,
            'failure_count': self.failure_count,
            'success_rate': (self.total_successes / self.total_calls) if self.total_calls > 0 else 0,
            'last_failure_time': self.last_failure_time
        }
    
    def reset(self):
        """Manually reset circuit breaker to closed state."""
        logger.info(f"Manually resetting circuit breaker {self.name}")
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None

class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""
    pass

class ModuleCircuitBreakerManager:
    """Manages circuit breakers for all scanning modules."""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
    
    def get_circuit_breaker(self, module_name: str) -> CircuitBreaker:
        """Get or create circuit breaker for module."""
        if module_name not in self.circuit_breakers:
            config = CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=30,
                success_threshold=2
            )
            self.circuit_breakers[module_name] = CircuitBreaker(module_name, config)
        
        return self.circuit_breakers[module_name]
    
    async def execute_with_breaker(self, module_name: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        circuit_breaker = self.get_circuit_breaker(module_name)
        return await circuit_breaker.call(func, *args, **kwargs)
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all circuit breakers."""
        return {name: cb.get_stats() for name, cb in self.circuit_breakers.items()}
    
    def reset_all(self):
        """Reset all circuit breakers."""
        for circuit_breaker in self.circuit_breakers.values():
            circuit_breaker.reset()
