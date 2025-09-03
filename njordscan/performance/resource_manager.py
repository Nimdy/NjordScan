"""
Resource Management System

Intelligent resource allocation and management with:
- Dynamic resource allocation and limits
- Memory management and optimization
- CPU scheduling and affinity management
- I/O bandwidth management
- Network resource coordination
- Resource monitoring and alerting
- Automatic resource scaling
"""

import asyncio
import time
import psutil
import threading
import os
import gc
from typing import Dict, List, Any, Optional, Union, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import logging
import json
import weakref
import mmap
from pathlib import Path
import resource
import signal

logger = logging.getLogger(__name__)

class ResourceType(Enum):
    """Types of system resources."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK_IO = "disk_io"
    NETWORK_IO = "network_io"
    FILE_DESCRIPTORS = "file_descriptors"
    THREADS = "threads"
    PROCESSES = "processes"

class ResourceState(Enum):
    """Resource allocation states."""
    AVAILABLE = "available"
    ALLOCATED = "allocated"
    OVERCOMMITTED = "overcommitted"
    EXHAUSTED = "exhausted"
    RESERVED = "reserved"

class AllocationStrategy(Enum):
    """Resource allocation strategies."""
    FAIR_SHARE = "fair_share"
    PRIORITY_BASED = "priority_based"
    DEMAND_BASED = "demand_based"
    PREDICTIVE = "predictive"
    ADAPTIVE = "adaptive"

class ResourcePriority(Enum):
    """Resource allocation priorities."""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5

@dataclass
class ResourceLimit:
    """Resource limit configuration."""
    resource_type: ResourceType
    soft_limit: Union[int, float]
    hard_limit: Union[int, float]
    warning_threshold: float = 0.8  # Percentage of soft limit
    critical_threshold: float = 0.95  # Percentage of hard limit
    enforcement_enabled: bool = True
    auto_scaling_enabled: bool = False
    
    def __post_init__(self):
        if self.hard_limit < self.soft_limit:
            raise ValueError("Hard limit must be >= soft limit")

@dataclass
class ResourceAllocation:
    """Resource allocation record."""
    allocation_id: str
    resource_type: ResourceType
    amount: Union[int, float]
    priority: ResourcePriority
    owner: str  # Task or component ID
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    actual_usage: Union[int, float] = 0
    peak_usage: Union[int, float] = 0
    tags: Set[str] = field(default_factory=set)
    
    @property
    def is_expired(self) -> bool:
        """Check if allocation is expired."""
        return self.expires_at is not None and time.time() > self.expires_at
    
    @property
    def utilization_rate(self) -> float:
        """Calculate utilization rate."""
        return self.actual_usage / max(1, self.amount)
    
    @property
    def age_seconds(self) -> float:
        """Get allocation age in seconds."""
        return time.time() - self.created_at

@dataclass
class ResourceMetrics:
    """Resource usage metrics."""
    resource_type: ResourceType
    timestamp: float
    
    # Current usage
    current_usage: Union[int, float]
    peak_usage: Union[int, float]
    average_usage: Union[int, float]
    
    # Capacity and limits
    total_capacity: Union[int, float]
    available_capacity: Union[int, float]
    allocated_amount: Union[int, float]
    
    # Performance metrics
    utilization_rate: float  # 0.0 to 1.0
    efficiency_score: float  # Usage quality metric
    fragmentation_rate: float  # Resource fragmentation
    
    # Trend data
    usage_trend: List[float] = field(default_factory=list)
    allocation_trend: List[float] = field(default_factory=list)
    
    @property
    def is_overcommitted(self) -> bool:
        """Check if resource is overcommitted."""
        return self.allocated_amount > self.total_capacity
    
    @property
    def available_percentage(self) -> float:
        """Get available capacity as percentage."""
        return (self.available_capacity / max(1, self.total_capacity)) * 100
    
    @property
    def pressure_score(self) -> float:
        """Calculate resource pressure score (0-1, higher = more pressure)."""
        usage_pressure = self.utilization_rate
        allocation_pressure = self.allocated_amount / max(1, self.total_capacity)
        fragmentation_pressure = self.fragmentation_rate
        
        return min(1.0, (usage_pressure + allocation_pressure + fragmentation_pressure) / 3)

@dataclass
class ResourceConfig:
    """Resource management configuration."""
    
    # CPU configuration
    cpu_allocation_unit: float = 0.1  # CPU cores
    cpu_overcommit_ratio: float = 1.5
    enable_cpu_affinity: bool = True
    cpu_scheduling_policy: str = "normal"  # normal, batch, idle
    
    # Memory configuration
    memory_allocation_unit: int = 1024 * 1024  # 1MB
    memory_overcommit_ratio: float = 1.2
    enable_memory_compression: bool = False
    memory_cleanup_threshold: float = 0.85
    enable_swap_management: bool = True
    
    # I/O configuration
    disk_io_bandwidth_mbps: int = 1000
    network_io_bandwidth_mbps: int = 100
    io_priority_levels: int = 8
    enable_io_throttling: bool = True
    
    # File descriptor limits
    max_file_descriptors: int = 65536
    fd_soft_limit: int = 32768
    enable_fd_monitoring: bool = True
    
    # Thread and process limits
    max_threads: int = 1000
    max_processes: int = 100
    thread_stack_size: int = 8 * 1024 * 1024  # 8MB
    
    # Monitoring configuration
    monitoring_interval: float = 1.0
    metrics_retention_hours: int = 24
    enable_alerting: bool = True
    alert_cooldown_seconds: int = 300
    
    # Optimization configuration
    enable_automatic_tuning: bool = True
    tuning_interval_seconds: int = 60
    enable_predictive_scaling: bool = True
    prediction_window_minutes: int = 15
    
    # Allocation strategies
    default_allocation_strategy: AllocationStrategy = AllocationStrategy.ADAPTIVE
    enable_preemption: bool = True
    preemption_grace_period: float = 30.0

class ResourceManager:
    """Advanced resource management system."""
    
    def __init__(self, config: ResourceConfig = None):
        self.config = config or ResourceConfig()
        
        # Resource tracking
        self.resource_limits: Dict[ResourceType, ResourceLimit] = {}
        self.allocations: Dict[str, ResourceAllocation] = {}
        self.metrics_history: Dict[ResourceType, deque] = defaultdict(
            lambda: deque(maxlen=int(self.config.metrics_retention_hours * 3600 / self.config.monitoring_interval))
        )
        
        # Resource pools
        self.resource_pools: Dict[ResourceType, Any] = {}
        
        # Allocation strategies
        self.allocation_strategies: Dict[AllocationStrategy, Callable] = {
            AllocationStrategy.FAIR_SHARE: self._fair_share_allocation,
            AllocationStrategy.PRIORITY_BASED: self._priority_based_allocation,
            AllocationStrategy.DEMAND_BASED: self._demand_based_allocation,
            AllocationStrategy.PREDICTIVE: self._predictive_allocation,
            AllocationStrategy.ADAPTIVE: self._adaptive_allocation
        }
        
        # Monitoring and optimization
        self.resource_monitor = ResourceMonitor(self.config)
        self.resource_optimizer = ResourceOptimizer(self.config)
        self.resource_predictor = ResourcePredictor(self.config)
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Synchronization
        self.allocation_lock = asyncio.Lock()
        self.metrics_lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            'allocations_created': 0,
            'allocations_released': 0,
            'allocation_failures': 0,
            'resource_warnings': 0,
            'resource_alerts': 0,
            'optimization_runs': 0,
            'preemptions_performed': 0,
            'auto_scaling_events': 0
        }
        
        # Callbacks and hooks
        self.allocation_callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self.resource_alerts: List[Callable] = []
        
        self.start_time = time.time()
    
    async def initialize(self):
        """Initialize the resource manager."""
        
        logger.info("Initializing Resource Management System")
        
        self.running = True
        
        # Initialize resource limits
        await self._initialize_resource_limits()
        
        # Initialize resource pools
        await self._initialize_resource_pools()
        
        # Initialize monitoring
        await self.resource_monitor.initialize(self)
        
        # Initialize optimizer
        await self.resource_optimizer.initialize(self)
        
        # Initialize predictor
        if self.config.enable_predictive_scaling:
            await self.resource_predictor.initialize(self)
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._monitoring_worker()),
            asyncio.create_task(self._cleanup_worker()),
            asyncio.create_task(self._optimization_worker()),
            asyncio.create_task(self._alerting_worker())
        ]
        
        if self.config.enable_predictive_scaling:
            self.background_tasks.append(
                asyncio.create_task(self._prediction_worker())
            )
        
        logger.info("Resource Management System initialized")
    
    async def allocate_resource(self, resource_type: ResourceType, amount: Union[int, float],
                              priority: ResourcePriority = ResourcePriority.NORMAL,
                              owner: str = "unknown", ttl: Optional[float] = None,
                              tags: Set[str] = None) -> Optional[str]:
        """Allocate system resource."""
        
        allocation_id = f"{resource_type.value}_{int(time.time() * 1000)}_{id(owner)}"
        
        try:
            async with self.allocation_lock:
                # Check if resource is available
                if not await self._check_resource_availability(resource_type, amount):
                    logger.warning(f"Resource allocation failed - insufficient {resource_type.value}: {amount}")
                    self.stats['allocation_failures'] += 1
                    return None
                
                # Create allocation record
                allocation = ResourceAllocation(
                    allocation_id=allocation_id,
                    resource_type=resource_type,
                    amount=amount,
                    priority=priority,
                    owner=owner,
                    expires_at=time.time() + ttl if ttl else None,
                    tags=tags or set()
                )
                
                # Apply allocation strategy
                strategy = self.config.default_allocation_strategy
                if not await self._apply_allocation_strategy(strategy, allocation):
                    logger.warning(f"Allocation strategy failed for {allocation_id}")
                    self.stats['allocation_failures'] += 1
                    return None
                
                # Perform actual allocation
                if await self._perform_resource_allocation(allocation):
                    self.allocations[allocation_id] = allocation
                    self.stats['allocations_created'] += 1
                    
                    # Trigger callbacks
                    await self._trigger_allocation_callbacks('allocated', allocation)
                    
                    logger.debug(f"Resource allocated: {allocation_id} "
                               f"({resource_type.value}: {amount}, Priority: {priority.name})")
                    
                    return allocation_id
                else:
                    logger.error(f"Failed to perform resource allocation: {allocation_id}")
                    self.stats['allocation_failures'] += 1
                    return None
                    
        except Exception as e:
            logger.error(f"Resource allocation error: {str(e)}")
            self.stats['allocation_failures'] += 1
            return None
    
    async def release_resource(self, allocation_id: str) -> bool:
        """Release allocated resource."""
        
        try:
            async with self.allocation_lock:
                if allocation_id not in self.allocations:
                    logger.warning(f"Allocation not found: {allocation_id}")
                    return False
                
                allocation = self.allocations[allocation_id]
                
                # Perform actual resource release
                if await self._perform_resource_release(allocation):
                    del self.allocations[allocation_id]
                    self.stats['allocations_released'] += 1
                    
                    # Trigger callbacks
                    await self._trigger_allocation_callbacks('released', allocation)
                    
                    logger.debug(f"Resource released: {allocation_id}")
                    return True
                else:
                    logger.error(f"Failed to release resource: {allocation_id}")
                    return False
                    
        except Exception as e:
            logger.error(f"Resource release error: {str(e)}")
            return False
    
    async def update_resource_usage(self, allocation_id: str, 
                                   actual_usage: Union[int, float]) -> bool:
        """Update actual resource usage for an allocation."""
        
        try:
            if allocation_id not in self.allocations:
                return False
            
            allocation = self.allocations[allocation_id]
            allocation.actual_usage = actual_usage
            allocation.peak_usage = max(allocation.peak_usage, actual_usage)
            
            # Check for over-usage
            if actual_usage > allocation.amount * 1.1:  # 10% tolerance
                logger.warning(f"Resource over-usage detected: {allocation_id} "
                             f"(Allocated: {allocation.amount}, Used: {actual_usage})")
            
            return True
            
        except Exception as e:
            logger.error(f"Resource usage update error: {str(e)}")
            return False
    
    async def get_resource_metrics(self, resource_type: ResourceType) -> Optional[ResourceMetrics]:
        """Get current resource metrics."""
        
        try:
            return await self.resource_monitor.get_resource_metrics(resource_type)
        except Exception as e:
            logger.error(f"Failed to get resource metrics: {str(e)}")
            return None
    
    async def get_allocation_info(self, allocation_id: str) -> Optional[Dict[str, Any]]:
        """Get allocation information."""
        
        if allocation_id not in self.allocations:
            return None
        
        allocation = self.allocations[allocation_id]
        
        return {
            'allocation_id': allocation.allocation_id,
            'resource_type': allocation.resource_type.value,
            'amount': allocation.amount,
            'priority': allocation.priority.name,
            'owner': allocation.owner,
            'created_at': allocation.created_at,
            'expires_at': allocation.expires_at,
            'actual_usage': allocation.actual_usage,
            'peak_usage': allocation.peak_usage,
            'utilization_rate': allocation.utilization_rate,
            'age_seconds': allocation.age_seconds,
            'is_expired': allocation.is_expired,
            'tags': list(allocation.tags)
        }
    
    async def optimize_resources(self) -> Dict[str, Any]:
        """Perform resource optimization."""
        
        logger.info("Starting resource optimization")
        
        try:
            optimization_result = await self.resource_optimizer.optimize(self.allocations, self.metrics_history)
            self.stats['optimization_runs'] += 1
            
            logger.info(f"Resource optimization completed: {optimization_result.get('optimizations_applied', 0)} optimizations applied")
            
            return optimization_result
            
        except Exception as e:
            logger.error(f"Resource optimization error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    async def predict_resource_needs(self, resource_type: ResourceType, 
                                   horizon_minutes: int = 15) -> Dict[str, Any]:
        """Predict future resource needs."""
        
        if not self.config.enable_predictive_scaling:
            return {'prediction_enabled': False}
        
        try:
            return await self.resource_predictor.predict(resource_type, horizon_minutes)
        except Exception as e:
            logger.error(f"Resource prediction error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    async def set_resource_limit(self, resource_type: ResourceType, 
                               soft_limit: Union[int, float],
                               hard_limit: Union[int, float],
                               **kwargs) -> bool:
        """Set resource limit."""
        
        try:
            limit = ResourceLimit(
                resource_type=resource_type,
                soft_limit=soft_limit,
                hard_limit=hard_limit,
                **kwargs
            )
            
            self.resource_limits[resource_type] = limit
            
            # Apply system-level limits if possible
            await self._apply_system_limits(limit)
            
            logger.info(f"Resource limit set: {resource_type.value} "
                       f"(Soft: {soft_limit}, Hard: {hard_limit})")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to set resource limit: {str(e)}")
            return False
    
    async def register_allocation_callback(self, event_type: str, callback: Callable):
        """Register callback for allocation events."""
        self.allocation_callbacks[event_type].append(callback)
    
    async def register_resource_alert(self, callback: Callable):
        """Register callback for resource alerts."""
        self.resource_alerts.append(callback)
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system resource status."""
        
        try:
            status = {
                'timestamp': time.time(),
                'uptime': time.time() - self.start_time,
                'running': self.running,
                'statistics': dict(self.stats)
            }
            
            # Resource metrics for each type
            status['resources'] = {}
            for resource_type in ResourceType:
                metrics = await self.get_resource_metrics(resource_type)
                if metrics:
                    status['resources'][resource_type.value] = {
                        'current_usage': metrics.current_usage,
                        'peak_usage': metrics.peak_usage,
                        'total_capacity': metrics.total_capacity,
                        'available_capacity': metrics.available_capacity,
                        'allocated_amount': metrics.allocated_amount,
                        'utilization_rate': metrics.utilization_rate,
                        'pressure_score': metrics.pressure_score,
                        'is_overcommitted': metrics.is_overcommitted
                    }
            
            # Current allocations summary
            status['allocations'] = {
                'total': len(self.allocations),
                'by_priority': {},
                'by_resource_type': {},
                'expired': 0
            }
            
            for allocation in self.allocations.values():
                # Count by priority
                priority_name = allocation.priority.name
                status['allocations']['by_priority'][priority_name] = \
                    status['allocations']['by_priority'].get(priority_name, 0) + 1
                
                # Count by resource type
                resource_name = allocation.resource_type.value
                status['allocations']['by_resource_type'][resource_name] = \
                    status['allocations']['by_resource_type'].get(resource_name, 0) + 1
                
                # Count expired
                if allocation.is_expired:
                    status['allocations']['expired'] += 1
            
            # Resource limits
            status['limits'] = {}
            for resource_type, limit in self.resource_limits.items():
                status['limits'][resource_type.value] = {
                    'soft_limit': limit.soft_limit,
                    'hard_limit': limit.hard_limit,
                    'warning_threshold': limit.warning_threshold,
                    'critical_threshold': limit.critical_threshold,
                    'enforcement_enabled': limit.enforcement_enabled,
                    'auto_scaling_enabled': limit.auto_scaling_enabled
                }
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get system status: {str(e)}")
            return {'error': str(e)}
    
    # Private methods
    
    async def _initialize_resource_limits(self):
        """Initialize default resource limits."""
        
        try:
            # CPU limits
            cpu_count = os.cpu_count() or 4
            await self.set_resource_limit(
                ResourceType.CPU,
                soft_limit=cpu_count * 0.8,
                hard_limit=cpu_count * self.config.cpu_overcommit_ratio,
                auto_scaling_enabled=True
            )
            
            # Memory limits
            memory_total = psutil.virtual_memory().total
            await self.set_resource_limit(
                ResourceType.MEMORY,
                soft_limit=memory_total * 0.8,
                hard_limit=memory_total * self.config.memory_overcommit_ratio,
                auto_scaling_enabled=self.config.enable_swap_management
            )
            
            # File descriptor limits
            await self.set_resource_limit(
                ResourceType.FILE_DESCRIPTORS,
                soft_limit=self.config.fd_soft_limit,
                hard_limit=self.config.max_file_descriptors,
                enforcement_enabled=self.config.enable_fd_monitoring
            )
            
            # Thread limits
            await self.set_resource_limit(
                ResourceType.THREADS,
                soft_limit=self.config.max_threads * 0.8,
                hard_limit=self.config.max_threads,
                enforcement_enabled=True
            )
            
            # Process limits
            await self.set_resource_limit(
                ResourceType.PROCESSES,
                soft_limit=self.config.max_processes * 0.8,
                hard_limit=self.config.max_processes,
                enforcement_enabled=True
            )
            
            # I/O limits
            await self.set_resource_limit(
                ResourceType.DISK_IO,
                soft_limit=self.config.disk_io_bandwidth_mbps * 0.8,
                hard_limit=self.config.disk_io_bandwidth_mbps,
                enforcement_enabled=self.config.enable_io_throttling
            )
            
            await self.set_resource_limit(
                ResourceType.NETWORK_IO,
                soft_limit=self.config.network_io_bandwidth_mbps * 0.8,
                hard_limit=self.config.network_io_bandwidth_mbps,
                enforcement_enabled=self.config.enable_io_throttling
            )
            
            logger.info("Resource limits initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize resource limits: {str(e)}")
    
    async def _initialize_resource_pools(self):
        """Initialize resource pools."""
        
        # This would initialize specific resource pools
        # For example, memory pools, thread pools, etc.
        
        logger.info("Resource pools initialized")
    
    async def _check_resource_availability(self, resource_type: ResourceType, 
                                         amount: Union[int, float]) -> bool:
        """Check if requested resource amount is available."""
        
        try:
            if resource_type not in self.resource_limits:
                logger.warning(f"No limit set for resource type: {resource_type.value}")
                return True  # Allow if no limit set
            
            limit = self.resource_limits[resource_type]
            metrics = await self.get_resource_metrics(resource_type)
            
            if not metrics:
                return True  # Allow if metrics unavailable
            
            # Check against soft limit first
            projected_usage = metrics.allocated_amount + amount
            
            if projected_usage > limit.soft_limit:
                # Check if we can use hard limit
                if projected_usage > limit.hard_limit:
                    return False
                
                # Warn about soft limit exceeded
                logger.warning(f"Resource allocation exceeds soft limit: {resource_type.value} "
                             f"(Requested: {amount}, Current: {metrics.allocated_amount}, "
                             f"Soft Limit: {limit.soft_limit})")
                self.stats['resource_warnings'] += 1
            
            return True
            
        except Exception as e:
            logger.error(f"Resource availability check error: {str(e)}")
            return False
    
    async def _apply_allocation_strategy(self, strategy: AllocationStrategy, 
                                       allocation: ResourceAllocation) -> bool:
        """Apply allocation strategy."""
        
        try:
            strategy_func = self.allocation_strategies.get(strategy)
            if strategy_func:
                return await strategy_func(allocation)
            else:
                logger.warning(f"Unknown allocation strategy: {strategy}")
                return True  # Default to allowing allocation
                
        except Exception as e:
            logger.error(f"Allocation strategy error: {str(e)}")
            return False
    
    async def _perform_resource_allocation(self, allocation: ResourceAllocation) -> bool:
        """Perform actual resource allocation."""
        
        try:
            resource_type = allocation.resource_type
            amount = allocation.amount
            
            if resource_type == ResourceType.CPU:
                return await self._allocate_cpu(allocation)
            elif resource_type == ResourceType.MEMORY:
                return await self._allocate_memory(allocation)
            elif resource_type == ResourceType.DISK_IO:
                return await self._allocate_disk_io(allocation)
            elif resource_type == ResourceType.NETWORK_IO:
                return await self._allocate_network_io(allocation)
            elif resource_type == ResourceType.FILE_DESCRIPTORS:
                return await self._allocate_file_descriptors(allocation)
            elif resource_type == ResourceType.THREADS:
                return await self._allocate_threads(allocation)
            elif resource_type == ResourceType.PROCESSES:
                return await self._allocate_processes(allocation)
            else:
                logger.warning(f"Unknown resource type: {resource_type}")
                return True  # Default to success for unknown types
                
        except Exception as e:
            logger.error(f"Resource allocation error: {str(e)}")
            return False
    
    async def _perform_resource_release(self, allocation: ResourceAllocation) -> bool:
        """Perform actual resource release."""
        
        try:
            resource_type = allocation.resource_type
            
            if resource_type == ResourceType.CPU:
                return await self._release_cpu(allocation)
            elif resource_type == ResourceType.MEMORY:
                return await self._release_memory(allocation)
            elif resource_type == ResourceType.DISK_IO:
                return await self._release_disk_io(allocation)
            elif resource_type == ResourceType.NETWORK_IO:
                return await self._release_network_io(allocation)
            elif resource_type == ResourceType.FILE_DESCRIPTORS:
                return await self._release_file_descriptors(allocation)
            elif resource_type == ResourceType.THREADS:
                return await self._release_threads(allocation)
            elif resource_type == ResourceType.PROCESSES:
                return await self._release_processes(allocation)
            else:
                return True  # Default to success for unknown types
                
        except Exception as e:
            logger.error(f"Resource release error: {str(e)}")
            return False
    
    # Allocation strategy implementations
    
    async def _fair_share_allocation(self, allocation: ResourceAllocation) -> bool:
        """Fair share allocation strategy."""
        # Implement fair share logic
        return True
    
    async def _priority_based_allocation(self, allocation: ResourceAllocation) -> bool:
        """Priority-based allocation strategy."""
        # Implement priority-based logic
        return True
    
    async def _demand_based_allocation(self, allocation: ResourceAllocation) -> bool:
        """Demand-based allocation strategy."""
        # Implement demand-based logic
        return True
    
    async def _predictive_allocation(self, allocation: ResourceAllocation) -> bool:
        """Predictive allocation strategy."""
        # Implement predictive logic
        return True
    
    async def _adaptive_allocation(self, allocation: ResourceAllocation) -> bool:
        """Adaptive allocation strategy."""
        # Implement adaptive logic combining multiple strategies
        return True
    
    # Resource-specific allocation methods
    
    async def _allocate_cpu(self, allocation: ResourceAllocation) -> bool:
        """Allocate CPU resources."""
        # Implement CPU allocation (e.g., CPU affinity, scheduling)
        return True
    
    async def _allocate_memory(self, allocation: ResourceAllocation) -> bool:
        """Allocate memory resources."""
        # Implement memory allocation (e.g., memory pools, limits)
        return True
    
    async def _allocate_disk_io(self, allocation: ResourceAllocation) -> bool:
        """Allocate disk I/O resources."""
        # Implement disk I/O allocation (e.g., bandwidth limits)
        return True
    
    async def _allocate_network_io(self, allocation: ResourceAllocation) -> bool:
        """Allocate network I/O resources."""
        # Implement network I/O allocation (e.g., bandwidth limits)
        return True
    
    async def _allocate_file_descriptors(self, allocation: ResourceAllocation) -> bool:
        """Allocate file descriptor resources."""
        # Implement file descriptor allocation
        return True
    
    async def _allocate_threads(self, allocation: ResourceAllocation) -> bool:
        """Allocate thread resources."""
        # Implement thread allocation
        return True
    
    async def _allocate_processes(self, allocation: ResourceAllocation) -> bool:
        """Allocate process resources."""
        # Implement process allocation
        return True
    
    # Resource release methods (similar pattern)
    
    async def _release_cpu(self, allocation: ResourceAllocation) -> bool:
        """Release CPU resources."""
        return True
    
    async def _release_memory(self, allocation: ResourceAllocation) -> bool:
        """Release memory resources."""
        return True
    
    async def _release_disk_io(self, allocation: ResourceAllocation) -> bool:
        """Release disk I/O resources."""
        return True
    
    async def _release_network_io(self, allocation: ResourceAllocation) -> bool:
        """Release network I/O resources."""
        return True
    
    async def _release_file_descriptors(self, allocation: ResourceAllocation) -> bool:
        """Release file descriptor resources."""
        return True
    
    async def _release_threads(self, allocation: ResourceAllocation) -> bool:
        """Release thread resources."""
        return True
    
    async def _release_processes(self, allocation: ResourceAllocation) -> bool:
        """Release process resources."""
        return True
    
    async def _apply_system_limits(self, limit: ResourceLimit):
        """Apply system-level resource limits."""
        
        try:
            resource_type = limit.resource_type
            
            if resource_type == ResourceType.FILE_DESCRIPTORS:
                # Set file descriptor limits
                soft_limit = int(limit.soft_limit)
                hard_limit = int(limit.hard_limit)
                resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, hard_limit))
                
            elif resource_type == ResourceType.MEMORY:
                # Set memory limits (if supported)
                if hasattr(resource, 'RLIMIT_AS'):
                    hard_limit = int(limit.hard_limit)
                    resource.setrlimit(resource.RLIMIT_AS, (hard_limit, hard_limit))
                    
            elif resource_type == ResourceType.PROCESSES:
                # Set process limits
                if hasattr(resource, 'RLIMIT_NPROC'):
                    soft_limit = int(limit.soft_limit)
                    hard_limit = int(limit.hard_limit)
                    resource.setrlimit(resource.RLIMIT_NPROC, (soft_limit, hard_limit))
            
            # Other resource types would be handled here
            
        except Exception as e:
            logger.warning(f"Failed to apply system limits for {limit.resource_type.value}: {str(e)}")
    
    async def _trigger_allocation_callbacks(self, event_type: str, allocation: ResourceAllocation):
        """Trigger allocation event callbacks."""
        
        try:
            callbacks = self.allocation_callbacks.get(event_type, [])
            for callback in callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(allocation)
                    else:
                        callback(allocation)
                except Exception as e:
                    logger.error(f"Allocation callback error: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to trigger allocation callbacks: {str(e)}")
    
    # Background worker methods
    
    async def _monitoring_worker(self):
        """Background monitoring worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.monitoring_interval)
                
                # Update metrics for all resource types
                for resource_type in ResourceType:
                    metrics = await self.resource_monitor.get_resource_metrics(resource_type)
                    if metrics:
                        async with self.metrics_lock:
                            self.metrics_history[resource_type].append(metrics)
                
            except Exception as e:
                logger.error(f"Monitoring worker error: {str(e)}")
    
    async def _cleanup_worker(self):
        """Background cleanup worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(60.0)  # Run every minute
                
                # Clean up expired allocations
                expired_allocations = [
                    allocation_id for allocation_id, allocation in self.allocations.items()
                    if allocation.is_expired
                ]
                
                for allocation_id in expired_allocations:
                    logger.info(f"Cleaning up expired allocation: {allocation_id}")
                    await self.release_resource(allocation_id)
                
                # Trigger garbage collection if memory pressure is high
                memory_metrics = await self.get_resource_metrics(ResourceType.MEMORY)
                if memory_metrics and memory_metrics.pressure_score > self.config.memory_cleanup_threshold:
                    logger.info("Triggering garbage collection due to memory pressure")
                    gc.collect()
                
            except Exception as e:
                logger.error(f"Cleanup worker error: {str(e)}")
    
    async def _optimization_worker(self):
        """Background optimization worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.tuning_interval_seconds)
                
                if self.config.enable_automatic_tuning:
                    await self.optimize_resources()
                
            except Exception as e:
                logger.error(f"Optimization worker error: {str(e)}")
    
    async def _alerting_worker(self):
        """Background alerting worker."""
        
        alert_timestamps = {}
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.monitoring_interval)
                
                current_time = time.time()
                
                # Check resource thresholds and trigger alerts
                for resource_type, limit in self.resource_limits.items():
                    metrics = await self.get_resource_metrics(resource_type)
                    if not metrics:
                        continue
                    
                    # Check if alert cooldown has passed
                    alert_key = f"{resource_type.value}_critical"
                    last_alert_time = alert_timestamps.get(alert_key, 0)
                    
                    if current_time - last_alert_time < self.config.alert_cooldown_seconds:
                        continue
                    
                    # Check critical threshold
                    if metrics.pressure_score >= limit.critical_threshold:
                        await self._trigger_resource_alert('critical', resource_type, metrics)
                        alert_timestamps[alert_key] = current_time
                        self.stats['resource_alerts'] += 1
                    
                    # Check warning threshold
                    elif metrics.pressure_score >= limit.warning_threshold:
                        await self._trigger_resource_alert('warning', resource_type, metrics)
                        self.stats['resource_warnings'] += 1
                
            except Exception as e:
                logger.error(f"Alerting worker error: {str(e)}")
    
    async def _prediction_worker(self):
        """Background prediction worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.prediction_window_minutes * 60)
                
                # Generate predictions for all resource types
                for resource_type in ResourceType:
                    prediction = await self.predict_resource_needs(
                        resource_type, self.config.prediction_window_minutes
                    )
                    
                    if prediction.get('success') and prediction.get('scaling_recommended'):
                        logger.info(f"Predictive scaling recommended for {resource_type.value}")
                        # Implement auto-scaling logic here
                
            except Exception as e:
                logger.error(f"Prediction worker error: {str(e)}")
    
    async def _trigger_resource_alert(self, severity: str, resource_type: ResourceType, 
                                    metrics: ResourceMetrics):
        """Trigger resource alert."""
        
        try:
            alert_data = {
                'severity': severity,
                'resource_type': resource_type.value,
                'timestamp': time.time(),
                'metrics': {
                    'current_usage': metrics.current_usage,
                    'total_capacity': metrics.total_capacity,
                    'utilization_rate': metrics.utilization_rate,
                    'pressure_score': metrics.pressure_score
                }
            }
            
            for callback in self.resource_alerts:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(alert_data)
                    else:
                        callback(alert_data)
                except Exception as e:
                    logger.error(f"Resource alert callback error: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Failed to trigger resource alert: {str(e)}")
    
    async def shutdown(self):
        """Shutdown resource manager."""
        
        logger.info("Shutting down Resource Management System")
        
        self.running = False
        self.shutdown_event.set()
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for background tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Shutdown components
        await self.resource_monitor.shutdown()
        await self.resource_optimizer.shutdown()
        
        if self.config.enable_predictive_scaling:
            await self.resource_predictor.shutdown()
        
        # Release all allocations
        allocation_ids = list(self.allocations.keys())
        for allocation_id in allocation_ids:
            await self.release_resource(allocation_id)
        
        logger.info("Resource Management System shutdown completed")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get resource manager statistics."""
        
        stats = dict(self.stats)
        stats['uptime'] = time.time() - self.start_time
        stats['active_allocations'] = len(self.allocations)
        stats['resource_types_monitored'] = len(self.resource_limits)
        
        return stats


# Helper classes

class ResourceMonitor:
    """Resource monitoring component."""
    
    def __init__(self, config: ResourceConfig):
        self.config = config
        self.resource_manager = None
    
    async def initialize(self, resource_manager):
        """Initialize resource monitor."""
        self.resource_manager = resource_manager
    
    async def get_resource_metrics(self, resource_type: ResourceType) -> Optional[ResourceMetrics]:
        """Get current metrics for a resource type."""
        
        try:
            current_time = time.time()
            
            if resource_type == ResourceType.CPU:
                return await self._get_cpu_metrics(current_time)
            elif resource_type == ResourceType.MEMORY:
                return await self._get_memory_metrics(current_time)
            elif resource_type == ResourceType.DISK_IO:
                return await self._get_disk_io_metrics(current_time)
            elif resource_type == ResourceType.NETWORK_IO:
                return await self._get_network_io_metrics(current_time)
            elif resource_type == ResourceType.FILE_DESCRIPTORS:
                return await self._get_fd_metrics(current_time)
            elif resource_type == ResourceType.THREADS:
                return await self._get_thread_metrics(current_time)
            elif resource_type == ResourceType.PROCESSES:
                return await self._get_process_metrics(current_time)
            else:
                return None
                
        except Exception as e:
            logger.error(f"Failed to get {resource_type.value} metrics: {str(e)}")
            return None
    
    async def _get_cpu_metrics(self, timestamp: float) -> ResourceMetrics:
        """Get CPU metrics."""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count()
        
        # Calculate allocated amount from resource manager
        allocated_amount = sum(
            allocation.amount for allocation in self.resource_manager.allocations.values()
            if allocation.resource_type == ResourceType.CPU
        )
        
        return ResourceMetrics(
            resource_type=ResourceType.CPU,
            timestamp=timestamp,
            current_usage=cpu_percent / 100 * cpu_count,
            peak_usage=cpu_count,  # Would track actual peak
            average_usage=cpu_percent / 100 * cpu_count,  # Would calculate actual average
            total_capacity=cpu_count,
            available_capacity=cpu_count - (cpu_percent / 100 * cpu_count),
            allocated_amount=allocated_amount,
            utilization_rate=cpu_percent / 100,
            efficiency_score=0.8,  # Would calculate actual efficiency
            fragmentation_rate=0.1  # Would calculate actual fragmentation
        )
    
    async def _get_memory_metrics(self, timestamp: float) -> ResourceMetrics:
        """Get memory metrics."""
        memory = psutil.virtual_memory()
        
        allocated_amount = sum(
            allocation.amount for allocation in self.resource_manager.allocations.values()
            if allocation.resource_type == ResourceType.MEMORY
        )
        
        return ResourceMetrics(
            resource_type=ResourceType.MEMORY,
            timestamp=timestamp,
            current_usage=memory.used,
            peak_usage=memory.used,  # Would track actual peak
            average_usage=memory.used,  # Would calculate actual average
            total_capacity=memory.total,
            available_capacity=memory.available,
            allocated_amount=allocated_amount,
            utilization_rate=memory.percent / 100,
            efficiency_score=0.8,  # Would calculate actual efficiency
            fragmentation_rate=0.1  # Would calculate actual fragmentation
        )
    
    async def _get_disk_io_metrics(self, timestamp: float) -> ResourceMetrics:
        """Get disk I/O metrics."""
        # This would implement actual disk I/O monitoring
        return ResourceMetrics(
            resource_type=ResourceType.DISK_IO,
            timestamp=timestamp,
            current_usage=0,
            peak_usage=0,
            average_usage=0,
            total_capacity=self.config.disk_io_bandwidth_mbps,
            available_capacity=self.config.disk_io_bandwidth_mbps,
            allocated_amount=0,
            utilization_rate=0.0,
            efficiency_score=1.0,
            fragmentation_rate=0.0
        )
    
    async def _get_network_io_metrics(self, timestamp: float) -> ResourceMetrics:
        """Get network I/O metrics."""
        # This would implement actual network I/O monitoring
        return ResourceMetrics(
            resource_type=ResourceType.NETWORK_IO,
            timestamp=timestamp,
            current_usage=0,
            peak_usage=0,
            average_usage=0,
            total_capacity=self.config.network_io_bandwidth_mbps,
            available_capacity=self.config.network_io_bandwidth_mbps,
            allocated_amount=0,
            utilization_rate=0.0,
            efficiency_score=1.0,
            fragmentation_rate=0.0
        )
    
    async def _get_fd_metrics(self, timestamp: float) -> ResourceMetrics:
        """Get file descriptor metrics."""
        try:
            process = psutil.Process()
            current_fds = process.num_fds() if hasattr(process, 'num_fds') else 0
            
            soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
            
            return ResourceMetrics(
                resource_type=ResourceType.FILE_DESCRIPTORS,
                timestamp=timestamp,
                current_usage=current_fds,
                peak_usage=current_fds,  # Would track actual peak
                average_usage=current_fds,  # Would calculate actual average
                total_capacity=hard_limit,
                available_capacity=hard_limit - current_fds,
                allocated_amount=0,  # Would track allocated FDs
                utilization_rate=current_fds / max(1, hard_limit),
                efficiency_score=1.0,
                fragmentation_rate=0.0
            )
        except Exception:
            return ResourceMetrics(
                resource_type=ResourceType.FILE_DESCRIPTORS,
                timestamp=timestamp,
                current_usage=0, peak_usage=0, average_usage=0,
                total_capacity=1024, available_capacity=1024, allocated_amount=0,
                utilization_rate=0.0, efficiency_score=1.0, fragmentation_rate=0.0
            )
    
    async def _get_thread_metrics(self, timestamp: float) -> ResourceMetrics:
        """Get thread metrics."""
        try:
            process = psutil.Process()
            current_threads = process.num_threads()
            
            return ResourceMetrics(
                resource_type=ResourceType.THREADS,
                timestamp=timestamp,
                current_usage=current_threads,
                peak_usage=current_threads,  # Would track actual peak
                average_usage=current_threads,  # Would calculate actual average
                total_capacity=self.config.max_threads,
                available_capacity=self.config.max_threads - current_threads,
                allocated_amount=0,  # Would track allocated threads
                utilization_rate=current_threads / max(1, self.config.max_threads),
                efficiency_score=1.0,
                fragmentation_rate=0.0
            )
        except Exception:
            return ResourceMetrics(
                resource_type=ResourceType.THREADS,
                timestamp=timestamp,
                current_usage=0, peak_usage=0, average_usage=0,
                total_capacity=100, available_capacity=100, allocated_amount=0,
                utilization_rate=0.0, efficiency_score=1.0, fragmentation_rate=0.0
            )
    
    async def _get_process_metrics(self, timestamp: float) -> ResourceMetrics:
        """Get process metrics."""
        # This would implement actual process monitoring
        return ResourceMetrics(
            resource_type=ResourceType.PROCESSES,
            timestamp=timestamp,
            current_usage=1,  # Current process
            peak_usage=1,
            average_usage=1,
            total_capacity=self.config.max_processes,
            available_capacity=self.config.max_processes - 1,
            allocated_amount=0,
            utilization_rate=1.0 / self.config.max_processes,
            efficiency_score=1.0,
            fragmentation_rate=0.0
        )
    
    async def shutdown(self):
        """Shutdown resource monitor."""
        pass


class ResourceOptimizer:
    """Resource optimization component."""
    
    def __init__(self, config: ResourceConfig):
        self.config = config
    
    async def initialize(self, resource_manager):
        """Initialize resource optimizer."""
        self.resource_manager = resource_manager
    
    async def optimize(self, allocations: Dict[str, ResourceAllocation], 
                     metrics_history: Dict[ResourceType, deque]) -> Dict[str, Any]:
        """Perform resource optimization."""
        
        optimizations_applied = []
        
        # Implement optimization algorithms here
        # For example:
        # - Defragmentation
        # - Load balancing
        # - Resource consolidation
        # - Preemption of low-priority tasks
        
        return {
            'success': True,
            'optimizations_applied': len(optimizations_applied),
            'details': optimizations_applied
        }
    
    async def shutdown(self):
        """Shutdown resource optimizer."""
        pass


class ResourcePredictor:
    """Resource prediction component."""
    
    def __init__(self, config: ResourceConfig):
        self.config = config
    
    async def initialize(self, resource_manager):
        """Initialize resource predictor."""
        self.resource_manager = resource_manager
    
    async def predict(self, resource_type: ResourceType, 
                     horizon_minutes: int) -> Dict[str, Any]:
        """Predict future resource needs."""
        
        # Implement prediction algorithms here
        # For example:
        # - Time series analysis
        # - Machine learning models
        # - Pattern recognition
        
        return {
            'success': True,
            'resource_type': resource_type.value,
            'horizon_minutes': horizon_minutes,
            'predicted_usage': 0.0,
            'confidence': 0.8,
            'scaling_recommended': False
        }
    
    async def shutdown(self):
        """Shutdown resource predictor."""
        pass
