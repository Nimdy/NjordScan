"""
Performance Optimizer

Comprehensive performance optimization system including:
- Intelligent scanning optimization strategies
- Resource allocation and management
- Parallel processing coordination
- Memory and CPU optimization
- I/O optimization and batching
- Performance profiling and analysis
"""

import asyncio
import time
import psutil
import threading
from typing import Dict, List, Any, Optional, Set, Tuple, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import logging
import json
import gc
from pathlib import Path

logger = logging.getLogger(__name__)

class OptimizationStrategy(Enum):
    """Performance optimization strategies."""
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    MEMORY_OPTIMIZED = "memory_optimized"
    CPU_OPTIMIZED = "cpu_optimized"
    IO_OPTIMIZED = "io_optimized"

class ScanMode(Enum):
    """Scanning execution modes."""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    DISTRIBUTED = "distributed"
    ADAPTIVE = "adaptive"

class ResourceType(Enum):
    """System resource types."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK_IO = "disk_io"
    NETWORK_IO = "network_io"
    GPU = "gpu"

@dataclass
class PerformanceProfile:
    """Performance profile configuration."""
    profile_id: str
    name: str
    description: str
    
    # Resource limits
    max_cpu_percent: float = 80.0
    max_memory_percent: float = 75.0
    max_disk_io_mbps: float = 500.0
    max_network_io_mbps: float = 100.0
    
    # Parallelization settings
    max_threads: int = 0  # 0 = auto-detect
    max_processes: int = 0  # 0 = auto-detect
    thread_pool_size: int = 0  # 0 = auto-calculate
    process_pool_size: int = 0  # 0 = auto-calculate
    
    # Optimization settings
    enable_caching: bool = True
    cache_size_mb: int = 512
    enable_compression: bool = True
    batch_size: int = 100
    chunk_size: int = 1024
    
    # Memory management
    enable_gc_optimization: bool = True
    gc_threshold_mb: int = 100
    memory_cleanup_interval: int = 300  # seconds
    
    # I/O optimization
    enable_async_io: bool = True
    io_buffer_size: int = 65536
    max_concurrent_files: int = 50
    
    # Adaptive settings
    enable_adaptive_scaling: bool = True
    performance_monitoring: bool = True
    auto_tuning: bool = True

@dataclass
class ResourceMetrics:
    """System resource metrics."""
    timestamp: float
    
    # CPU metrics
    cpu_percent: float
    cpu_count: int
    cpu_freq: float
    
    # Memory metrics
    memory_percent: float
    memory_available: int
    memory_used: int
    memory_total: int
    
    # Disk I/O metrics
    disk_read_mbps: float
    disk_write_mbps: float
    disk_usage_percent: float
    
    # Network I/O metrics
    network_sent_mbps: float
    network_recv_mbps: float
    
    # Process metrics
    process_cpu_percent: float
    process_memory_percent: float
    process_memory_rss: int
    process_memory_vms: int
    thread_count: int
    file_descriptors: int

@dataclass
class PerformanceMetrics:
    """Performance analysis metrics."""
    
    # Timing metrics
    total_execution_time: float = 0.0
    initialization_time: float = 0.0
    scanning_time: float = 0.0
    processing_time: float = 0.0
    reporting_time: float = 0.0
    
    # Throughput metrics
    files_per_second: float = 0.0
    lines_per_second: float = 0.0
    findings_per_second: float = 0.0
    
    # Resource utilization
    peak_cpu_usage: float = 0.0
    peak_memory_usage: float = 0.0
    average_cpu_usage: float = 0.0
    average_memory_usage: float = 0.0
    
    # Efficiency metrics
    cpu_efficiency: float = 0.0  # work done per CPU cycle
    memory_efficiency: float = 0.0  # work done per MB
    io_efficiency: float = 0.0  # work done per I/O operation
    
    # Optimization impact
    cache_hit_rate: float = 0.0
    parallelization_factor: float = 0.0
    optimization_speedup: float = 0.0

@dataclass
class OptimizationResult:
    """Result of performance optimization."""
    optimization_id: str
    strategy: OptimizationStrategy
    
    # Performance improvement
    before_metrics: PerformanceMetrics
    after_metrics: PerformanceMetrics
    improvement_factor: float
    
    # Applied optimizations
    optimizations_applied: List[str] = field(default_factory=list)
    configuration_changes: Dict[str, Any] = field(default_factory=dict)
    
    # Resource impact
    resource_savings: Dict[ResourceType, float] = field(default_factory=dict)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    optimization_time: float = field(default_factory=time.time)
    optimization_duration: float = 0.0

class PerformanceOptimizer:
    """Comprehensive performance optimization engine."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Optimizer configuration
        self.optimizer_config = {
            'auto_optimization': self.config.get('auto_optimization', True),
            'optimization_interval': self.config.get('optimization_interval', 3600),  # 1 hour
            'performance_threshold': self.config.get('performance_threshold', 0.8),
            'enable_profiling': self.config.get('enable_profiling', True),
            'profiling_sample_rate': self.config.get('profiling_sample_rate', 0.1),
            'optimization_history_size': self.config.get('optimization_history_size', 100)
        }
        
        # Performance profiles
        self.profiles: Dict[str, PerformanceProfile] = {}
        self.active_profile: Optional[PerformanceProfile] = None
        
        # System information
        self.system_info = self._get_system_info()
        
        # Resource monitoring
        self.resource_monitor = ResourceMonitor()
        self.performance_monitor = PerformanceMonitor()
        
        # Optimization history
        self.optimization_history: List[OptimizationResult] = []
        
        # Thread pools
        self.thread_pool: Optional[ThreadPoolExecutor] = None
        self.process_pool: Optional[ProcessPoolExecutor] = None
        
        # Performance tracking
        self.current_metrics = PerformanceMetrics()
        self.baseline_metrics: Optional[PerformanceMetrics] = None
        
        # Optimization locks
        self.optimization_lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            'optimizations_performed': 0,
            'total_speedup_factor': 0.0,
            'total_resource_savings': 0.0,
            'auto_optimizations': 0,
            'manual_optimizations': 0,
            'failed_optimizations': 0
        }
        
        self.start_time = time.time()
    
    async def initialize(self):
        """Initialize the performance optimizer."""
        
        logger.info("Initializing Performance Optimizer")
        
        # Initialize resource monitoring
        await self.resource_monitor.initialize()
        await self.performance_monitor.initialize()
        
        # Load default profiles
        await self._load_default_profiles()
        
        # Auto-detect optimal profile
        optimal_profile = await self._auto_detect_optimal_profile()
        if optimal_profile:
            await self.set_active_profile(optimal_profile.profile_id)
        
        # Initialize thread pools
        await self._initialize_thread_pools()
        
        # Start background optimization if enabled
        if self.optimizer_config['auto_optimization']:
            asyncio.create_task(self._auto_optimization_worker())
        
        logger.info(f"Performance Optimizer initialized with profile: {self.active_profile.name if self.active_profile else 'None'}")
    
    async def optimize_scan_performance(self, scan_context: Dict[str, Any]) -> OptimizationResult:
        """Optimize performance for a specific scan context."""
        
        optimization_start_time = time.time()
        optimization_id = f"opt_{int(optimization_start_time)}"
        
        logger.info(f"Starting scan performance optimization: {optimization_id}")
        
        async with self.optimization_lock:
            try:
                # Capture baseline metrics
                baseline_metrics = await self._capture_performance_metrics()
                
                # Analyze scan context
                scan_analysis = await self._analyze_scan_context(scan_context)
                
                # Determine optimization strategy
                strategy = await self._determine_optimization_strategy(scan_analysis)
                
                logger.info(f"Using optimization strategy: {strategy.value}")
                
                # Apply optimizations
                applied_optimizations = []
                configuration_changes = {}
                
                # CPU optimization
                if strategy in [OptimizationStrategy.CPU_OPTIMIZED, OptimizationStrategy.AGGRESSIVE]:
                    cpu_opts = await self._optimize_cpu_usage(scan_analysis)
                    applied_optimizations.extend(cpu_opts['optimizations'])
                    configuration_changes.update(cpu_opts['config_changes'])
                
                # Memory optimization
                if strategy in [OptimizationStrategy.MEMORY_OPTIMIZED, OptimizationStrategy.AGGRESSIVE]:
                    memory_opts = await self._optimize_memory_usage(scan_analysis)
                    applied_optimizations.extend(memory_opts['optimizations'])
                    configuration_changes.update(memory_opts['config_changes'])
                
                # I/O optimization
                if strategy in [OptimizationStrategy.IO_OPTIMIZED, OptimizationStrategy.AGGRESSIVE]:
                    io_opts = await self._optimize_io_performance(scan_analysis)
                    applied_optimizations.extend(io_opts['optimizations'])
                    configuration_changes.update(io_opts['config_changes'])
                
                # Parallelization optimization
                if strategy != OptimizationStrategy.CONSERVATIVE:
                    parallel_opts = await self._optimize_parallelization(scan_analysis)
                    applied_optimizations.extend(parallel_opts['optimizations'])
                    configuration_changes.update(parallel_opts['config_changes'])
                
                # Caching optimization
                cache_opts = await self._optimize_caching(scan_analysis)
                applied_optimizations.extend(cache_opts['optimizations'])
                configuration_changes.update(cache_opts['config_changes'])
                
                # Capture post-optimization metrics
                optimized_metrics = await self._capture_performance_metrics()
                
                # Calculate improvement
                improvement_factor = await self._calculate_improvement_factor(
                    baseline_metrics, optimized_metrics
                )
                
                # Generate recommendations
                recommendations = await self._generate_optimization_recommendations(
                    scan_analysis, applied_optimizations
                )
                
                # Create optimization result
                result = OptimizationResult(
                    optimization_id=optimization_id,
                    strategy=strategy,
                    before_metrics=baseline_metrics,
                    after_metrics=optimized_metrics,
                    improvement_factor=improvement_factor,
                    optimizations_applied=applied_optimizations,
                    configuration_changes=configuration_changes,
                    recommendations=recommendations,
                    optimization_duration=time.time() - optimization_start_time
                )
                
                # Calculate resource savings
                result.resource_savings = await self._calculate_resource_savings(
                    baseline_metrics, optimized_metrics
                )
                
                # Store optimization result
                self.optimization_history.append(result)
                if len(self.optimization_history) > self.optimizer_config['optimization_history_size']:
                    self.optimization_history.pop(0)
                
                # Update statistics
                self.stats['optimizations_performed'] += 1
                self.stats['total_speedup_factor'] += improvement_factor
                self.stats['manual_optimizations'] += 1
                
                logger.info(f"Scan optimization completed: {optimization_id} "
                           f"(Improvement: {improvement_factor:.2f}x, "
                           f"Optimizations: {len(applied_optimizations)})")
                
                return result
                
            except Exception as e:
                logger.error(f"Scan optimization failed: {optimization_id} - {str(e)}")
                self.stats['failed_optimizations'] += 1
                raise
    
    async def set_active_profile(self, profile_id: str) -> bool:
        """Set active performance profile."""
        
        if profile_id not in self.profiles:
            logger.error(f"Performance profile not found: {profile_id}")
            return False
        
        logger.info(f"Setting active performance profile: {profile_id}")
        
        self.active_profile = self.profiles[profile_id]
        
        # Apply profile configuration
        await self._apply_profile_configuration(self.active_profile)
        
        return True
    
    async def create_custom_profile(self, profile: PerformanceProfile) -> bool:
        """Create custom performance profile."""
        
        logger.info(f"Creating custom performance profile: {profile.profile_id}")
        
        try:
            # Validate profile
            if not await self._validate_profile(profile):
                logger.error(f"Profile validation failed: {profile.profile_id}")
                return False
            
            # Store profile
            self.profiles[profile.profile_id] = profile
            
            logger.info(f"Custom profile created successfully: {profile.profile_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create custom profile: {str(e)}")
            return False
    
    async def get_performance_recommendations(self, scan_context: Dict[str, Any] = None) -> List[str]:
        """Get performance optimization recommendations."""
        
        logger.info("Generating performance recommendations")
        
        try:
            recommendations = []
            
            # System-based recommendations
            system_recs = await self._get_system_recommendations()
            recommendations.extend(system_recs)
            
            # Resource-based recommendations
            resource_metrics = await self.resource_monitor.get_current_metrics()
            resource_recs = await self._get_resource_recommendations(resource_metrics)
            recommendations.extend(resource_recs)
            
            # Historical performance recommendations
            if self.optimization_history:
                history_recs = await self._get_historical_recommendations()
                recommendations.extend(history_recs)
            
            # Scan context specific recommendations
            if scan_context:
                context_recs = await self._get_context_recommendations(scan_context)
                recommendations.extend(context_recs)
            
            # Remove duplicates and sort by priority
            unique_recommendations = list(set(recommendations))
            unique_recommendations.sort(key=lambda x: self._get_recommendation_priority(x), reverse=True)
            
            return unique_recommendations
            
        except Exception as e:
            logger.error(f"Failed to generate recommendations: {str(e)}")
            return []
    
    async def benchmark_performance(self, test_scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run performance benchmarks."""
        
        logger.info(f"Running performance benchmarks with {len(test_scenarios)} scenarios")
        
        benchmark_results = {
            'benchmark_id': f"benchmark_{int(time.time())}",
            'timestamp': time.time(),
            'system_info': self.system_info,
            'scenarios': []
        }
        
        try:
            for i, scenario in enumerate(test_scenarios):
                logger.info(f"Running benchmark scenario {i+1}/{len(test_scenarios)}: {scenario.get('name', 'Unnamed')}")
                
                scenario_result = await self._run_benchmark_scenario(scenario)
                benchmark_results['scenarios'].append(scenario_result)
            
            # Calculate overall performance score
            benchmark_results['overall_score'] = await self._calculate_benchmark_score(benchmark_results['scenarios'])
            
            # Generate performance insights
            benchmark_results['insights'] = await self._generate_benchmark_insights(benchmark_results)
            
            logger.info(f"Performance benchmarks completed. Overall score: {benchmark_results['overall_score']:.2f}")
            
            return benchmark_results
            
        except Exception as e:
            logger.error(f"Performance benchmarking failed: {str(e)}")
            return benchmark_results
    
    # Private methods
    
    async def _load_default_profiles(self):
        """Load default performance profiles."""
        
        # Conservative profile
        conservative = PerformanceProfile(
            profile_id="conservative",
            name="Conservative",
            description="Safe performance settings with minimal resource usage",
            max_cpu_percent=50.0,
            max_memory_percent=60.0,
            max_threads=2,
            max_processes=1,
            enable_caching=True,
            cache_size_mb=128,
            batch_size=50,
            enable_adaptive_scaling=False
        )
        
        # Balanced profile
        balanced = PerformanceProfile(
            profile_id="balanced",
            name="Balanced",
            description="Balanced performance and resource usage",
            max_cpu_percent=70.0,
            max_memory_percent=70.0,
            max_threads=0,  # Auto-detect
            max_processes=0,  # Auto-detect
            enable_caching=True,
            cache_size_mb=256,
            batch_size=100,
            enable_adaptive_scaling=True
        )
        
        # Aggressive profile
        aggressive = PerformanceProfile(
            profile_id="aggressive",
            name="Aggressive",
            description="Maximum performance with high resource usage",
            max_cpu_percent=90.0,
            max_memory_percent=85.0,
            max_threads=0,  # Auto-detect
            max_processes=0,  # Auto-detect
            enable_caching=True,
            cache_size_mb=512,
            batch_size=200,
            enable_adaptive_scaling=True,
            enable_compression=True,
            enable_async_io=True
        )
        
        # Memory optimized profile
        memory_optimized = PerformanceProfile(
            profile_id="memory_optimized",
            name="Memory Optimized",
            description="Optimized for low memory usage",
            max_cpu_percent=80.0,
            max_memory_percent=60.0,
            max_threads=0,
            max_processes=1,  # Single process to minimize memory
            enable_caching=True,
            cache_size_mb=64,
            batch_size=25,
            enable_gc_optimization=True,
            gc_threshold_mb=50,
            memory_cleanup_interval=120
        )
        
        # CPU optimized profile
        cpu_optimized = PerformanceProfile(
            profile_id="cpu_optimized",
            name="CPU Optimized",
            description="Optimized for maximum CPU utilization",
            max_cpu_percent=95.0,
            max_memory_percent=80.0,
            max_threads=0,  # Use all available
            max_processes=0,  # Use all available
            enable_caching=True,
            cache_size_mb=512,
            batch_size=500,
            enable_adaptive_scaling=True
        )
        
        profiles = [conservative, balanced, aggressive, memory_optimized, cpu_optimized]
        
        for profile in profiles:
            self.profiles[profile.profile_id] = profile
        
        logger.info(f"Loaded {len(profiles)} default performance profiles")
    
    async def _auto_detect_optimal_profile(self) -> Optional[PerformanceProfile]:
        """Auto-detect optimal performance profile based on system resources."""
        
        try:
            # Get system resources
            cpu_count = psutil.cpu_count()
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # Determine optimal profile based on resources
            if cpu_count >= 8 and memory_gb >= 16:
                return self.profiles.get("aggressive")
            elif cpu_count >= 4 and memory_gb >= 8:
                return self.profiles.get("balanced")
            elif memory_gb < 4:
                return self.profiles.get("memory_optimized")
            elif cpu_count >= 4:
                return self.profiles.get("cpu_optimized")
            else:
                return self.profiles.get("conservative")
                
        except Exception as e:
            logger.error(f"Failed to auto-detect optimal profile: {str(e)}")
            return self.profiles.get("balanced")
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information."""
        
        try:
            return {
                'cpu_count': psutil.cpu_count(),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available,
                'disk_usage': psutil.disk_usage('/').total,
                'boot_time': psutil.boot_time(),
                'platform': psutil.os.name if hasattr(psutil, 'os') else 'unknown'
            }
        except Exception as e:
            logger.error(f"Failed to get system info: {str(e)}")
            return {}
    
    async def _initialize_thread_pools(self):
        """Initialize thread and process pools."""
        
        if not self.active_profile:
            return
        
        # Calculate pool sizes
        max_threads = self.active_profile.max_threads or (psutil.cpu_count() * 2)
        max_processes = self.active_profile.max_processes or psutil.cpu_count()
        
        # Initialize thread pool
        self.thread_pool = ThreadPoolExecutor(
            max_workers=max_threads,
            thread_name_prefix="njordscan_thread"
        )
        
        # Initialize process pool
        self.process_pool = ProcessPoolExecutor(
            max_workers=max_processes
        )
        
        logger.info(f"Initialized thread pool (size: {max_threads}) and process pool (size: {max_processes})")
    
    async def _apply_profile_configuration(self, profile: PerformanceProfile):
        """Apply performance profile configuration."""
        
        logger.info(f"Applying performance profile configuration: {profile.name}")
        
        # Configure garbage collection
        if profile.enable_gc_optimization:
            gc.set_threshold(700, 10, 10)  # Optimize GC thresholds
        
        # Reinitialize pools with new settings
        if self.thread_pool:
            self.thread_pool.shutdown(wait=False)
        if self.process_pool:
            self.process_pool.shutdown(wait=False)
        
        await self._initialize_thread_pools()
    
    async def _analyze_scan_context(self, scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan context for optimization opportunities."""
        
        analysis = {
            'file_count': scan_context.get('file_count', 0),
            'total_size_mb': scan_context.get('total_size_mb', 0),
            'file_types': scan_context.get('file_types', []),
            'complexity_score': scan_context.get('complexity_score', 0),
            'scan_scope': scan_context.get('scan_scope', 'full'),
            'target_paths': scan_context.get('target_paths', []),
            'exclude_paths': scan_context.get('exclude_paths', [])
        }
        
        # Calculate optimization metrics
        analysis['files_per_mb'] = analysis['file_count'] / max(1, analysis['total_size_mb'])
        analysis['avg_file_size_kb'] = (analysis['total_size_mb'] * 1024) / max(1, analysis['file_count'])
        analysis['parallelization_potential'] = min(1.0, analysis['file_count'] / 10)
        
        return analysis
    
    async def _determine_optimization_strategy(self, scan_analysis: Dict[str, Any]) -> OptimizationStrategy:
        """Determine optimal optimization strategy based on scan analysis."""
        
        file_count = scan_analysis['file_count']
        total_size_mb = scan_analysis['total_size_mb']
        complexity_score = scan_analysis['complexity_score']
        
        # Get current system resources
        resource_metrics = await self.resource_monitor.get_current_metrics()
        
        # Strategy decision logic
        if resource_metrics.memory_percent > 80:
            return OptimizationStrategy.MEMORY_OPTIMIZED
        elif resource_metrics.cpu_percent > 80:
            return OptimizationStrategy.IO_OPTIMIZED
        elif file_count > 10000 or total_size_mb > 1000:
            return OptimizationStrategy.AGGRESSIVE
        elif complexity_score > 0.8:
            return OptimizationStrategy.CPU_OPTIMIZED
        else:
            return OptimizationStrategy.BALANCED
    
    async def _optimize_cpu_usage(self, scan_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize CPU usage for scanning."""
        
        optimizations = []
        config_changes = {}
        
        # Adjust thread pool size based on CPU availability
        cpu_count = psutil.cpu_count()
        optimal_threads = min(cpu_count * 2, scan_analysis['file_count'])
        
        if optimal_threads != (self.active_profile.max_threads or cpu_count * 2):
            config_changes['max_threads'] = optimal_threads
            optimizations.append(f"Adjusted thread pool size to {optimal_threads}")
        
        # Enable CPU-intensive optimizations for complex scans
        if scan_analysis['complexity_score'] > 0.7:
            config_changes['enable_parallel_ast_parsing'] = True
            optimizations.append("Enabled parallel AST parsing for complex code")
        
        return {
            'optimizations': optimizations,
            'config_changes': config_changes
        }
    
    async def _optimize_memory_usage(self, scan_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize memory usage for scanning."""
        
        optimizations = []
        config_changes = {}
        
        # Adjust batch size based on available memory
        available_memory_mb = psutil.virtual_memory().available / (1024**2)
        optimal_batch_size = min(200, int(available_memory_mb / 10))
        
        if optimal_batch_size != self.active_profile.batch_size:
            config_changes['batch_size'] = optimal_batch_size
            optimizations.append(f"Adjusted batch size to {optimal_batch_size}")
        
        # Enable memory cleanup for large scans
        if scan_analysis['total_size_mb'] > 500:
            config_changes['enable_memory_cleanup'] = True
            config_changes['memory_cleanup_interval'] = 60
            optimizations.append("Enabled aggressive memory cleanup")
        
        return {
            'optimizations': optimizations,
            'config_changes': config_changes
        }
    
    async def _optimize_io_performance(self, scan_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize I/O performance for scanning."""
        
        optimizations = []
        config_changes = {}
        
        # Optimize buffer size based on average file size
        avg_file_size_kb = scan_analysis['avg_file_size_kb']
        
        if avg_file_size_kb > 100:
            config_changes['io_buffer_size'] = 131072  # 128KB
            optimizations.append("Increased I/O buffer size for large files")
        elif avg_file_size_kb < 10:
            config_changes['io_buffer_size'] = 16384   # 16KB
            optimizations.append("Decreased I/O buffer size for small files")
        
        # Enable async I/O for large file counts
        if scan_analysis['file_count'] > 1000:
            config_changes['enable_async_io'] = True
            config_changes['max_concurrent_files'] = 100
            optimizations.append("Enabled async I/O for large file counts")
        
        return {
            'optimizations': optimizations,
            'config_changes': config_changes
        }
    
    async def _optimize_parallelization(self, scan_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize parallelization strategy."""
        
        optimizations = []
        config_changes = {}
        
        parallelization_potential = scan_analysis['parallelization_potential']
        
        if parallelization_potential > 0.8:
            config_changes['scan_mode'] = ScanMode.PARALLEL.value
            config_changes['enable_file_level_parallelism'] = True
            optimizations.append("Enabled aggressive file-level parallelism")
        elif parallelization_potential > 0.5:
            config_changes['scan_mode'] = ScanMode.ADAPTIVE.value
            optimizations.append("Enabled adaptive parallelization")
        
        return {
            'optimizations': optimizations,
            'config_changes': config_changes
        }
    
    async def _optimize_caching(self, scan_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize caching strategy."""
        
        optimizations = []
        config_changes = {}
        
        # Adjust cache size based on scan size
        if scan_analysis['total_size_mb'] > 1000:
            config_changes['cache_size_mb'] = 1024
            optimizations.append("Increased cache size for large scan")
        elif scan_analysis['file_count'] > 5000:
            config_changes['cache_size_mb'] = 512
            optimizations.append("Optimized cache size for many files")
        
        # Enable compression for large caches
        if config_changes.get('cache_size_mb', 0) > 512:
            config_changes['enable_cache_compression'] = True
            optimizations.append("Enabled cache compression")
        
        return {
            'optimizations': optimizations,
            'config_changes': config_changes
        }
    
    async def _capture_performance_metrics(self) -> PerformanceMetrics:
        """Capture current performance metrics."""
        
        # This would capture actual performance metrics
        # For now, return mock data
        return PerformanceMetrics(
            total_execution_time=10.0,
            files_per_second=50.0,
            peak_cpu_usage=75.0,
            peak_memory_usage=60.0,
            cache_hit_rate=0.85
        )
    
    async def _calculate_improvement_factor(self, before: PerformanceMetrics, 
                                          after: PerformanceMetrics) -> float:
        """Calculate performance improvement factor."""
        
        if before.total_execution_time <= 0:
            return 1.0
        
        return before.total_execution_time / max(0.1, after.total_execution_time)
    
    async def _auto_optimization_worker(self):
        """Background worker for automatic optimization."""
        
        while True:
            try:
                logger.debug("Running automatic performance optimization check")
                
                # Check if optimization is needed
                current_performance = await self._assess_current_performance()
                
                if current_performance < self.optimizer_config['performance_threshold']:
                    logger.info(f"Performance below threshold ({current_performance:.2f}), triggering optimization")
                    
                    # Perform automatic optimization
                    scan_context = await self._get_current_scan_context()
                    result = await self.optimize_scan_performance(scan_context)
                    
                    self.stats['auto_optimizations'] += 1
                    
                    logger.info(f"Automatic optimization completed with {result.improvement_factor:.2f}x improvement")
                
                # Wait for next optimization cycle
                await asyncio.sleep(self.optimizer_config['optimization_interval'])
                
            except Exception as e:
                logger.error(f"Auto-optimization worker error: {str(e)}")
                await asyncio.sleep(300)  # Wait 5 minutes on error
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance optimizer statistics."""
        
        stats = dict(self.stats)
        stats['uptime'] = time.time() - self.start_time
        stats['active_profile'] = self.active_profile.name if self.active_profile else None
        stats['available_profiles'] = len(self.profiles)
        stats['optimization_history_size'] = len(self.optimization_history)
        
        if self.stats['optimizations_performed'] > 0:
            stats['average_speedup'] = self.stats['total_speedup_factor'] / self.stats['optimizations_performed']
        else:
            stats['average_speedup'] = 1.0
        
        return stats
    
    async def shutdown(self):
        """Shutdown performance optimizer."""
        
        logger.info("Shutting down Performance Optimizer")
        
        # Shutdown thread pools
        if self.thread_pool:
            self.thread_pool.shutdown(wait=True)
        if self.process_pool:
            self.process_pool.shutdown(wait=True)
        
        # Shutdown monitors
        await self.resource_monitor.shutdown()
        await self.performance_monitor.shutdown()
        
        logger.info("Performance Optimizer shutdown completed")


# Helper classes

class ResourceMonitor:
    """System resource monitoring."""
    
    def __init__(self):
        self.monitoring = False
        self.metrics_history = []
    
    async def initialize(self):
        """Initialize resource monitoring."""
        self.monitoring = True
        asyncio.create_task(self._monitoring_worker())
    
    async def get_current_metrics(self) -> ResourceMetrics:
        """Get current resource metrics."""
        
        try:
            # Get process info
            process = psutil.Process()
            
            return ResourceMetrics(
                timestamp=time.time(),
                cpu_percent=psutil.cpu_percent(),
                cpu_count=psutil.cpu_count(),
                cpu_freq=psutil.cpu_freq().current if psutil.cpu_freq() else 0,
                memory_percent=psutil.virtual_memory().percent,
                memory_available=psutil.virtual_memory().available,
                memory_used=psutil.virtual_memory().used,
                memory_total=psutil.virtual_memory().total,
                disk_read_mbps=0,  # Would calculate from disk I/O stats
                disk_write_mbps=0,  # Would calculate from disk I/O stats
                disk_usage_percent=psutil.disk_usage('/').percent,
                network_sent_mbps=0,  # Would calculate from network stats
                network_recv_mbps=0,  # Would calculate from network stats
                process_cpu_percent=process.cpu_percent(),
                process_memory_percent=process.memory_percent(),
                process_memory_rss=process.memory_info().rss,
                process_memory_vms=process.memory_info().vms,
                thread_count=process.num_threads(),
                file_descriptors=process.num_fds() if hasattr(process, 'num_fds') else 0
            )
        except Exception as e:
            logger.error(f"Failed to get resource metrics: {str(e)}")
            return ResourceMetrics(timestamp=time.time(), cpu_percent=0, cpu_count=1, cpu_freq=0,
                                 memory_percent=0, memory_available=0, memory_used=0, memory_total=0,
                                 disk_read_mbps=0, disk_write_mbps=0, disk_usage_percent=0,
                                 network_sent_mbps=0, network_recv_mbps=0, process_cpu_percent=0,
                                 process_memory_percent=0, process_memory_rss=0, process_memory_vms=0,
                                 thread_count=0, file_descriptors=0)
    
    async def _monitoring_worker(self):
        """Background monitoring worker."""
        
        while self.monitoring:
            try:
                metrics = await self.get_current_metrics()
                self.metrics_history.append(metrics)
                
                # Keep only last 1000 metrics
                if len(self.metrics_history) > 1000:
                    self.metrics_history.pop(0)
                
                await asyncio.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                logger.error(f"Resource monitoring error: {str(e)}")
                await asyncio.sleep(5)
    
    async def shutdown(self):
        """Shutdown resource monitoring."""
        self.monitoring = False


class PerformanceMonitor:
    """Performance monitoring and profiling."""
    
    def __init__(self):
        self.profiling_enabled = False
        self.performance_data = []
    
    async def initialize(self):
        """Initialize performance monitoring."""
        self.profiling_enabled = True
    
    async def shutdown(self):
        """Shutdown performance monitoring."""
        self.profiling_enabled = False

