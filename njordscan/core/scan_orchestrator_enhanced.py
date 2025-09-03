"""
Enhanced Scan Orchestrator with Advanced Performance and Reliability Features

Integrates circuit breakers, rate limiting, retry logic, and performance monitoring.
"""

import asyncio
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from ..config import Config
from ..vulnerability import Vulnerability, VulnerabilityIdGenerator
from ..report.formatter import ReportFormatter
from ..utils import detect_framework, NjordScore
from ..cache import CacheManager
from ..plugins import PluginManager

from .circuit_breaker import ModuleCircuitBreakerManager, CircuitBreakerOpenError
from .rate_limiter import GlobalRateLimiter
from .retry_handler import ModuleRetryManager
from .performance_monitor import PerformanceMonitor, global_performance_monitor

import logging

logger = logging.getLogger(__name__)

class EnhancedScanOrchestrator:
    """Enhanced scanner orchestrator with reliability and performance features."""
    
    def __init__(self, config: Config):
        self.config = config
        self.console = Console()
        self.modules: Dict[str, Any] = {}
        self.plugins: Dict[str, Any] = {}
        
        # Core components
        self.cache_manager = CacheManager(enabled=config.use_cache)
        self.report_formatter = ReportFormatter(config)
        self.njord_score = NjordScore()
        self.plugin_manager = PluginManager()
        self.vuln_id_generator = VulnerabilityIdGenerator()
        
        # Enhanced reliability components
        self.circuit_breaker_manager = ModuleCircuitBreakerManager()
        self.rate_limiter = GlobalRateLimiter()
        self.retry_manager = ModuleRetryManager()
        self.performance_monitor = global_performance_monitor
        
        # Load scanning modules and plugins
        self._load_modules()
        self._load_plugins()
    
    def _load_modules(self):
        """Load and initialize core scanning modules."""
        from ..modules import (
            HeadersModule, ConfigsModule, CodeStaticModule,
            DependenciesModule, RuntimeModule, AIEndpointsModule
        )
        
        available_modules = {
            'headers': HeadersModule,
            'configs': ConfigsModule,
            'code_static': CodeStaticModule,
            'dependencies': DependenciesModule,
            'runtime': RuntimeModule,
            'ai_endpoints': AIEndpointsModule
        }
        
        for module_name, module_class in available_modules.items():
            if self.config.is_module_enabled(module_name):
                try:
                    module = module_class(self.config, self.vuln_id_generator)
                    if module.should_run(self.config.mode):
                        self.modules[module_name] = module
                        logger.info(f"Loaded module: {module_name}")
                except Exception as e:
                    logger.error(f"Failed to load module {module_name}: {e}")
    
    def _load_plugins(self):
        """Load and initialize plugins with enhanced error handling."""
        try:
            enabled_plugins = [name for name, config in self.config.plugins.items() 
                             if config.get('enabled', False)]
            
            plugin_classes = self.plugin_manager.load_plugins(enabled_plugins)
            
            for plugin_name, plugin_class in plugin_classes.items():
                try:
                    plugin_config = self.config.get_plugin_config(plugin_name)
                    plugin = plugin_class(self.config, self.vuln_id_generator)
                    
                    if self._validate_plugin(plugin):
                        self.plugins[plugin_name] = plugin
                        logger.info(f"Loaded plugin: {plugin_name}")
                        
                        # Configure plugin-specific rate limiting
                        if hasattr(plugin, 'get_rate_limit_config'):
                            rate_config = plugin.get_rate_limit_config()
                            self.rate_limiter.get_limiter(f"plugin_{plugin_name}", rate_config)
                    
                except Exception as e:
                    logger.error(f"Failed to load plugin {plugin_name}: {e}")
        
        except Exception as e:
            logger.error(f"Plugin loading error: {e}")
    
    def _validate_plugin(self, plugin) -> bool:
        """Enhanced plugin validation."""
        try:
            # Basic validation
            if not hasattr(plugin, 'scan'):
                return False
            
            # Framework compatibility
            if hasattr(plugin, 'supports_framework'):
                if not plugin.supports_framework(self.config.framework):
                    return False
            
            # Mode compatibility
            if hasattr(plugin, 'should_run'):
                if not plugin.should_run(self.config.mode):
                    return False
            
            # Pre-scan validation
            if hasattr(plugin, 'pre_scan_validation'):
                if not asyncio.run(plugin.pre_scan_validation(self.config.target)):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Plugin validation error: {e}")
            return False
    
    async def scan(self) -> Dict[str, Any]:
        """Execute enhanced scanning process with reliability features."""
        start_time = time.time()
        
        # Start performance monitoring
        await self.performance_monitor.start_monitoring()
        
        try:
            async with self.performance_monitor.measure_operation("full_scan"):
                # Detect framework if auto
                if self.config.framework == 'auto':
                    detected_framework = detect_framework(self.config.target)
                    self.config.framework = detected_framework
                    logger.info(f"Detected framework: {detected_framework}")
                
                # Display scan info
                self._display_scan_info()
                
                # Check cache first
                cache_key = self._generate_cache_key()
                cached_results = self.cache_manager.get_cached_results(cache_key)
                
                if cached_results and not self.config.force_scan:
                    logger.info("Using cached results")
                    vulnerabilities = [Vulnerability.from_dict(v) for v in cached_results]
                else:
                    # Run scanning with enhanced reliability
                    vulnerabilities = await self._run_enhanced_scan()
                    
                    # Cache results
                    vuln_dicts = [v.to_dict() for v in vulnerabilities]
                    self.cache_manager.cache_results(
                        cache_key, vuln_dicts, 
                        target=self.config.target,
                        framework=self.config.framework,
                        scan_mode=self.config.mode,
                        config_hash=self._get_config_hash()
                    )
                
                # Calculate scan duration
                scan_duration = time.time() - start_time
                
                # Compile final results with enhanced metrics
                final_results = await self._compile_enhanced_results(
                    vulnerabilities, scan_duration
                )
                
                return final_results
        
        finally:
            # Stop performance monitoring
            await self.performance_monitor.stop_monitoring()
    
    async def _run_enhanced_scan(self) -> List[Vulnerability]:
        """Run scanning with enhanced reliability features."""
        all_vulnerabilities = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            # Create tasks for core modules
            core_tasks = []
            for module_name, module in self.modules.items():
                task_id = progress.add_task(f"Scanning {module_name}...", total=100)
                task = self._run_module_with_reliability(module_name, module, progress, task_id)
                core_tasks.append((f"module_{module_name}", task))
            
            # Create tasks for plugins
            plugin_tasks = []
            for plugin_name, plugin in self.plugins.items():
                task_id = progress.add_task(f"Running plugin {plugin_name}...", total=100)
                task = self._run_plugin_with_reliability(plugin_name, plugin, progress, task_id)
                plugin_tasks.append((f"plugin_{plugin_name}", task))
            
            # Run all tasks with controlled concurrency
            semaphore = asyncio.Semaphore(self.config.max_concurrent)
            all_tasks = core_tasks + plugin_tasks
            
            async def run_with_semaphore(task_name, task):
                async with semaphore:
                    return await task
            
            # Execute tasks with concurrency control
            results = await asyncio.gather(
                *[run_with_semaphore(name, task) for name, task in all_tasks],
                return_exceptions=True
            )
            
            # Process results
            for i, result in enumerate(results):
                task_name = all_tasks[i][0]
                
                if isinstance(result, Exception):
                    logger.error(f"Task {task_name} failed: {result}")
                    continue
                
                if isinstance(result, list):
                    all_vulnerabilities.extend(result)
        
        return all_vulnerabilities
    
    async def _run_module_with_reliability(self, module_name: str, module, progress: Progress, task_id: int) -> List[Vulnerability]:
        """Run module with circuit breaker, retry, and rate limiting."""
        try:
            progress.update(task_id, completed=10)
            
            async with self.performance_monitor.measure_operation(f"module_{module_name}"):
                # Rate limiting for network-based modules
                if module_name in ['headers', 'runtime', 'ai_endpoints']:
                    await self.rate_limiter.wait_for_tokens(f"module_{module_name}")
                
                progress.update(task_id, completed=25)
                
                # Execute with circuit breaker and retry
                async def scan_operation():
                    return await module.scan(self.config.target)
                
                try:
                    vulnerabilities = await self.circuit_breaker_manager.execute_with_breaker(
                        module_name, 
                        lambda: self.retry_manager.execute_with_retry(module_name, scan_operation)
                    )
                    
                    # Record success for rate limiter
                    if module_name in ['headers', 'runtime', 'ai_endpoints']:
                        self.rate_limiter.record_success(f"module_{module_name}", 1.0)
                    
                    progress.update(task_id, completed=100)
                    return vulnerabilities
                    
                except CircuitBreakerOpenError:
                    logger.warning(f"Module {module_name} skipped due to circuit breaker")
                    progress.update(task_id, completed=100)
                    return []
                
        except Exception as e:
            # Record error for rate limiter
            if module_name in ['headers', 'runtime', 'ai_endpoints']:
                self.rate_limiter.record_error(f"module_{module_name}")
            
            logger.error(f"Module {module_name} failed: {e}")
            progress.update(task_id, completed=100)
            return []
    
    async def _run_plugin_with_reliability(self, plugin_name: str, plugin, progress: Progress, task_id: int) -> List[Vulnerability]:
        """Run plugin with enhanced reliability features."""
        try:
            progress.update(task_id, completed=10)
            
            async with self.performance_monitor.measure_operation(f"plugin_{plugin_name}"):
                # Rate limiting for plugins
                await self.rate_limiter.wait_for_tokens(f"plugin_{plugin_name}")
                
                progress.update(task_id, completed=25)
                
                # Execute plugin with reliability features
                async def plugin_operation():
                    plugin_results = await plugin.scan(self.config.target)
                    
                    # Convert results to Vulnerability objects
                    vulnerabilities = []
                    for result in plugin_results:
                        if isinstance(result, dict):
                            vuln = Vulnerability.from_dict(result)
                            vulnerabilities.append(vuln)
                        elif isinstance(result, Vulnerability):
                            vulnerabilities.append(result)
                    
                    return vulnerabilities
                
                try:
                    vulnerabilities = await self.circuit_breaker_manager.execute_with_breaker(
                        f"plugin_{plugin_name}",
                        lambda: self.retry_manager.execute_with_retry(plugin_name, plugin_operation)
                    )
                    
                    # Post-processing if available
                    if hasattr(plugin, 'post_scan_processing'):
                        processed_results = await plugin.post_scan_processing([v.to_dict() for v in vulnerabilities])
                        vulnerabilities = [Vulnerability.from_dict(r) for r in processed_results]
                    
                    # Record success
                    self.rate_limiter.record_success(f"plugin_{plugin_name}", 1.0)
                    
                    progress.update(task_id, completed=100)
                    return vulnerabilities
                    
                except CircuitBreakerOpenError:
                    logger.warning(f"Plugin {plugin_name} skipped due to circuit breaker")
                    progress.update(task_id, completed=100)
                    return []
                
        except Exception as e:
            # Record error
            self.rate_limiter.record_error(f"plugin_{plugin_name}")
            logger.error(f"Plugin {plugin_name} failed: {e}")
            progress.update(task_id, completed=100)
            return []
    
    async def _compile_enhanced_results(self, vulnerabilities: List[Vulnerability], scan_duration: float) -> Dict[str, Any]:
        """Compile results with enhanced metrics and diagnostics."""
        # Get performance metrics
        performance_summary = self.performance_monitor.get_performance_summary()
        circuit_breaker_stats = self.circuit_breaker_manager.get_all_stats()
        rate_limiter_stats = self.rate_limiter.get_stats()
        retry_stats = self.retry_manager.get_all_stats()
        
        # Get optimization recommendations
        optimization_recommendations = self.performance_monitor.get_optimization_recommendations()
        
        # Standard results
        final_results = {
            'target': self.config.target,
            'framework': self.config.framework,
            'scan_mode': self.config.mode,
            'scan_duration': scan_duration,
            'modules_run': list(self.modules.keys()),
            'plugins_run': list(self.plugins.keys()),
            'vulnerabilities': self._group_vulnerabilities_by_module(vulnerabilities),
            'njord_score': self.njord_score.calculate_score(vulnerabilities),
            'summary': self._generate_summary(vulnerabilities),
            
            # Enhanced metrics
            'performance_metrics': performance_summary,
            'reliability_metrics': {
                'circuit_breakers': circuit_breaker_stats,
                'rate_limiters': rate_limiter_stats,
                'retry_handlers': retry_stats
            },
            'optimization_recommendations': optimization_recommendations,
            'scan_metadata': {
                'scan_id': hashlib.sha256(f"{self.config.target}_{time.time()}".encode()).hexdigest()[:12],
                'njordscan_version': '0.1.0',
                'scan_timestamp': time.time(),
                'configuration_hash': self._get_config_hash()
            }
        }
        
        return final_results
    
    def _generate_cache_key(self) -> str:
        """Generate cache key for scan configuration."""
        key_data = {
            'target': self.config.target,
            'framework': self.config.framework,
            'mode': self.config.mode,
            'modules': sorted(self.modules.keys()),
            'plugins': sorted(self.plugins.keys()),
            'config_hash': self._get_config_hash()
        }
        
        key_string = str(key_data)
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def _get_config_hash(self) -> str:
        """Get hash of relevant configuration."""
        config_dict = self.config.to_dict()
        relevant_config = {
            'pentest_mode': config_dict['pentest_mode'],
            'timeout': config_dict['timeout'],
            'max_concurrent': config_dict['max_concurrent'],
            'plugins': config_dict['plugins']
        }
        return hashlib.sha256(str(relevant_config).encode()).hexdigest()
    
    def _group_vulnerabilities_by_module(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by module, including plugins."""
        grouped = {}
        for vuln in vulnerabilities:
            module = vuln.module
            
            # Mark plugin-generated vulnerabilities
            if module in self.plugins:
                module = f"plugin_{module}"
            
            if module not in grouped:
                grouped[module] = []
            grouped[module].append(vuln.to_dict())
        return grouped
    
    def _display_scan_info(self):
        """Display enhanced scan information."""
        from rich.table import Table
        
        info_table = Table(title="Enhanced Scan Configuration")
        info_table.add_column("Setting", style="cyan")
        info_table.add_column("Value", style="green")
        
        info_table.add_row("Target", self.config.target)
        info_table.add_row("Framework", self.config.framework)
        info_table.add_row("Mode", self.config.mode)
        info_table.add_row("Core Modules", ", ".join(self.modules.keys()))
        
        if self.plugins:
            info_table.add_row("Plugins", ", ".join(self.plugins.keys()))
        
        info_table.add_row("Pentest Mode", "Enabled" if self.config.pentest_mode else "Disabled")
        info_table.add_row("Performance Monitoring", "Enabled")
        info_table.add_row("Circuit Breakers", "Enabled")
        info_table.add_row("Rate Limiting", "Enabled")
        info_table.add_row("Retry Logic", "Enabled")
        
        self.console.print(info_table)
        self.console.print()
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate enhanced scan summary."""
        total_issues = len(vulnerabilities)
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        modules_with_findings = set()
        plugins_with_findings = set()
        
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            if vuln.module in self.plugins:
                plugins_with_findings.add(vuln.module)
            else:
                modules_with_findings.add(vuln.module)
        
        return {
            'total_issues': total_issues,
            'severity_breakdown': severity_counts,
            'modules_with_findings': len(modules_with_findings),
            'plugins_with_findings': len(plugins_with_findings),
            'scan_efficiency': f"{total_issues} issues found across {len(self.modules) + len(self.plugins)} scanners"
        }
    
    def display_results(self, results: Dict[str, Any]):
        """Display scan results with enhanced information."""
        self.report_formatter.display_terminal_report(results)
        
        # Display performance summary if verbose
        if self.config.verbose and 'performance_metrics' in results:
            self._display_performance_summary(results['performance_metrics'])
        
        # Save to file if specified
        if self.config.output_file:
            self.report_formatter.save_report(results, self.config.output_file)
            self.console.print(f"\n[green]Report saved to: {self.config.output_file}[/green]")
    
    def _display_performance_summary(self, performance_metrics: Dict[str, Any]):
        """Display performance summary."""
        from rich.panel import Panel
        from rich.text import Text
        
        perf_text = Text()
        perf_text.append("🚀 Performance Summary\n\n", style="bold cyan")
        perf_text.append(f"Total Operations: {performance_metrics.get('total_operations', 0)}\n", style="white")
        perf_text.append(f"Success Rate: {performance_metrics.get('success_rate', 0):.1%}\n", style="green")
        perf_text.append(f"Average Operation Time: {performance_metrics.get('average_operation_time', 0):.2f}s\n", style="yellow")
        perf_text.append(f"Memory Growth: {performance_metrics.get('memory_growth_mb', 0):.1f} MB\n", style="blue")
        
        panel = Panel(perf_text, title="Performance Metrics", style="cyan")
        self.console.print(panel)
