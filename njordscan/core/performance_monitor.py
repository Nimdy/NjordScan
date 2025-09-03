"""
Performance Monitoring and Profiling System

Monitors scan performance, resource usage, and provides optimization insights.
"""

import time
import psutil
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
import logging
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Performance metrics for a scan operation."""
    operation_name: str
    start_time: float
    end_time: float
    duration: float
    cpu_percent: float
    memory_mb: float
    success: bool
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SystemMetrics:
    """System-wide performance metrics."""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_io_read: int
    disk_io_write: int
    network_sent: int
    network_recv: int

class PerformanceMonitor:
    """Monitors and analyzes scan performance."""
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.operation_metrics: List[PerformanceMetrics] = []
        self.system_metrics: deque = deque(maxlen=max_history)
        
        # Performance statistics
        self.module_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'total_calls': 0,
            'total_duration': 0.0,
            'avg_duration': 0.0,
            'min_duration': float('inf'),
            'max_duration': 0.0,
            'success_rate': 0.0,
            'errors': []
        })
        
        # Resource tracking
        self.process = psutil.Process()
        self.baseline_memory = self.process.memory_info().rss / 1024 / 1024
        
        # Monitoring task
        self.monitoring_task: Optional[asyncio.Task] = None
        self.monitoring_enabled = False
    
    async def start_monitoring(self, interval: float = 1.0):
        """Start continuous system monitoring."""
        if self.monitoring_enabled:
            return
        
        self.monitoring_enabled = True
        self.monitoring_task = asyncio.create_task(self._monitor_system(interval))
        logger.info("Performance monitoring started")
    
    async def stop_monitoring(self):
        """Stop system monitoring."""
        self.monitoring_enabled = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        logger.info("Performance monitoring stopped")
    
    async def _monitor_system(self, interval: float):
        """Continuously monitor system metrics."""
        while self.monitoring_enabled:
            try:
                # Get system metrics
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                disk_io = psutil.disk_io_counters()
                network_io = psutil.net_io_counters()
                
                metrics = SystemMetrics(
                    timestamp=time.time(),
                    cpu_percent=cpu_percent,
                    memory_percent=memory.percent,
                    memory_used_mb=memory.used / 1024 / 1024,
                    disk_io_read=disk_io.read_bytes if disk_io else 0,
                    disk_io_write=disk_io.write_bytes if disk_io else 0,
                    network_sent=network_io.bytes_sent if network_io else 0,
                    network_recv=network_io.bytes_recv if network_io else 0
                )
                
                self.system_metrics.append(metrics)
                
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in system monitoring: {e}")
                await asyncio.sleep(interval)
    
    @asynccontextmanager
    async def measure_operation(self, operation_name: str, metadata: Dict[str, Any] = None):
        """Context manager to measure operation performance."""
        start_time = time.time()
        start_memory = self.process.memory_info().rss / 1024 / 1024
        start_cpu = self.process.cpu_percent()
        
        success = True
        error_message = None
        
        try:
            yield
        except Exception as e:
            success = False
            error_message = str(e)
            raise
        finally:
            end_time = time.time()
            end_memory = self.process.memory_info().rss / 1024 / 1024
            end_cpu = self.process.cpu_percent()
            
            duration = end_time - start_time
            
            metrics = PerformanceMetrics(
                operation_name=operation_name,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                cpu_percent=(start_cpu + end_cpu) / 2,
                memory_mb=end_memory - start_memory,
                success=success,
                error_message=error_message,
                metadata=metadata or {}
            )
            
            self._record_metrics(metrics)
    
    def _record_metrics(self, metrics: PerformanceMetrics):
        """Record performance metrics."""
        self.operation_metrics.append(metrics)
        
        # Keep only recent metrics
        if len(self.operation_metrics) > self.max_history:
            self.operation_metrics.pop(0)
        
        # Update module statistics
        module_name = metrics.operation_name
        stats = self.module_stats[module_name]
        
        stats['total_calls'] += 1
        stats['total_duration'] += metrics.duration
        stats['avg_duration'] = stats['total_duration'] / stats['total_calls']
        stats['min_duration'] = min(stats['min_duration'], metrics.duration)
        stats['max_duration'] = max(stats['max_duration'], metrics.duration)
        
        if not metrics.success:
            stats['errors'].append({
                'timestamp': metrics.start_time,
                'error': metrics.error_message
            })
            # Keep only recent errors
            if len(stats['errors']) > 100:
                stats['errors'].pop(0)
        
        # Calculate success rate
        successful_calls = stats['total_calls'] - len(stats['errors'])
        stats['success_rate'] = successful_calls / stats['total_calls']
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        if not self.operation_metrics:
            return {'message': 'No performance data available'}
        
        total_duration = sum(m.duration for m in self.operation_metrics)
        successful_operations = sum(1 for m in self.operation_metrics if m.success)
        
        # Memory analysis
        memory_usage = [m.memory_mb for m in self.operation_metrics]
        current_memory = self.process.memory_info().rss / 1024 / 1024
        memory_growth = current_memory - self.baseline_memory
        
        # Performance bottlenecks
        slowest_operations = sorted(
            self.operation_metrics, 
            key=lambda x: x.duration, 
            reverse=True
        )[:10]
        
        return {
            'total_operations': len(self.operation_metrics),
            'successful_operations': successful_operations,
            'success_rate': successful_operations / len(self.operation_metrics),
            'total_scan_time': total_duration,
            'average_operation_time': total_duration / len(self.operation_metrics),
            'memory_baseline_mb': self.baseline_memory,
            'current_memory_mb': current_memory,
            'memory_growth_mb': memory_growth,
            'peak_memory_usage_mb': max(memory_usage) if memory_usage else 0,
            'slowest_operations': [
                {
                    'operation': op.operation_name,
                    'duration': op.duration,
                    'memory_mb': op.memory_mb
                }
                for op in slowest_operations
            ],
            'module_statistics': dict(self.module_stats)
        }
    
    def get_module_performance(self, module_name: str) -> Dict[str, Any]:
        """Get performance data for specific module."""
        if module_name not in self.module_stats:
            return {'error': f'No data for module {module_name}'}
        
        stats = self.module_stats[module_name]
        module_metrics = [m for m in self.operation_metrics if m.operation_name == module_name]
        
        # Performance trends
        recent_metrics = module_metrics[-10:]  # Last 10 operations
        if len(recent_metrics) > 1:
            trend = 'improving' if recent_metrics[-1].duration < recent_metrics[0].duration else 'degrading'
        else:
            trend = 'stable'
        
        return {
            **stats,
            'performance_trend': trend,
            'recent_operations': len(recent_metrics),
            'memory_impact': sum(m.memory_mb for m in module_metrics) / len(module_metrics) if module_metrics else 0
        }
    
    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate optimization recommendations based on performance data."""
        recommendations = []
        
        # Memory leak detection
        if len(self.operation_metrics) > 10:
            recent_memory = [m.memory_mb for m in self.operation_metrics[-10:]]
            if sum(recent_memory) > 0 and max(recent_memory) > 100:  # More than 100MB growth
                recommendations.append({
                    'type': 'memory_optimization',
                    'priority': 'high',
                    'message': 'Potential memory leak detected. Consider reviewing memory usage patterns.',
                    'details': f'Peak memory growth: {max(recent_memory):.2f} MB'
                })
        
        # Slow module detection
        for module_name, stats in self.module_stats.items():
            if stats['avg_duration'] > 30:  # Slower than 30 seconds
                recommendations.append({
                    'type': 'performance_optimization',
                    'priority': 'medium',
                    'message': f'Module {module_name} is running slowly.',
                    'details': f'Average duration: {stats["avg_duration"]:.2f}s',
                    'suggestion': 'Consider implementing caching or optimizing scanning logic.'
                })
        
        # High error rate detection
        for module_name, stats in self.module_stats.items():
            if stats['success_rate'] < 0.8:  # Less than 80% success rate
                recommendations.append({
                    'type': 'reliability_improvement',
                    'priority': 'high',
                    'message': f'Module {module_name} has high error rate.',
                    'details': f'Success rate: {stats["success_rate"]:.1%}',
                    'suggestion': 'Review error patterns and implement better error handling.'
                })
        
        # Resource usage recommendations
        if self.system_metrics:
            recent_cpu = [m.cpu_percent for m in list(self.system_metrics)[-10:]]
            avg_cpu = sum(recent_cpu) / len(recent_cpu) if recent_cpu else 0
            
            if avg_cpu > 80:
                recommendations.append({
                    'type': 'resource_optimization',
                    'priority': 'medium',
                    'message': 'High CPU usage detected.',
                    'details': f'Average CPU: {avg_cpu:.1f}%',
                    'suggestion': 'Consider reducing concurrency or optimizing CPU-intensive operations.'
                })
        
        return recommendations
    
    def export_metrics(self, format: str = 'json') -> str:
        """Export performance metrics in various formats."""
        data = {
            'performance_summary': self.get_performance_summary(),
            'module_statistics': dict(self.module_stats),
            'optimization_recommendations': self.get_optimization_recommendations(),
            'export_timestamp': time.time()
        }
        
        if format == 'json':
            import json
            return json.dumps(data, indent=2, default=str)
        elif format == 'csv':
            # Simple CSV export for operation metrics
            import io
            output = io.StringIO()
            output.write('operation,duration,memory_mb,cpu_percent,success,timestamp\n')
            for m in self.operation_metrics:
                output.write(f'{m.operation_name},{m.duration},{m.memory_mb},{m.cpu_percent},{m.success},{m.start_time}\n')
            return output.getvalue()
        else:
            return str(data)
    
    def reset_metrics(self):
        """Reset all performance metrics."""
        self.operation_metrics.clear()
        self.system_metrics.clear()
        self.module_stats.clear()
        self.baseline_memory = self.process.memory_info().rss / 1024 / 1024
        logger.info("Performance metrics reset")

# Global performance monitor instance
global_performance_monitor = PerformanceMonitor()
