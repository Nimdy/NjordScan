"""
🛡️ Core Scanner Orchestrator v1.0.0

Main scanning orchestrator that coordinates all security modules, plugins,
and advanced orchestrators for comprehensive security analysis.
"""

import asyncio
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from .config import Config
from .vulnerability import Vulnerability, VulnerabilityIdGenerator
from .modules.base import BaseModule
from .report.formatter import ReportFormatter
# Import advanced reporting if available
try:
    from .reporting.reporting_orchestrator import ReportingOrchestrator
    ADVANCED_REPORTING = True
except ImportError:
    ADVANCED_REPORTING = False
from .utils import detect_framework, NjordScore
from .cache import CacheManager
from .plugins import PluginManager

# Import advanced orchestrators (with fallback)
try:
    from .core.scan_orchestrator_enhanced import EnhancedScanOrchestrator
    from .intelligence.intelligence_orchestrator import IntelligenceOrchestrator
    from .ai.ai_orchestrator import AISecurityOrchestrator
    from .performance.performance_orchestrator import PerformanceOrchestrator
    ADVANCED_ORCHESTRATORS = True
except ImportError:
    ADVANCED_ORCHESTRATORS = False

class Scanner:
    """Simple Scanner interface for backward compatibility."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize scanner with optional config."""
        if config is None:
            config = Config()
        self.orchestrator = ScanOrchestrator(config)
    
    def scan(self, target: str = None) -> List[Vulnerability]:
        """Perform security scan."""
        if target:
            self.orchestrator.config.target = target
        import asyncio
        return asyncio.run(self.orchestrator.scan())
    
    def __getattr__(self, name):
        """Delegate to orchestrator for other methods."""
        return getattr(self.orchestrator, name)

class ScanOrchestrator:
    """Main scanner orchestrator."""
    
    def __init__(self, config: Config):
        self.config = config
        self.console = Console()
        self.modules: Dict[str, BaseModule] = {}
        self.plugins: Dict[str, Any] = {}
        self.cache_manager = CacheManager(enabled=config.use_cache)
        self.report_formatter = ReportFormatter(config)
        self.njord_score = NjordScore()
        self.plugin_manager = PluginManager()
        self.vuln_id_generator = VulnerabilityIdGenerator()
        
        # Initialize advanced reporting if available
        self.reporting_orchestrator = None
        if ADVANCED_REPORTING and (config.mode in ['deep', 'enterprise'] or 
                                  getattr(config, 'reporting_config', None)):
            self.reporting_orchestrator = ReportingOrchestrator()
        
        # Initialize advanced orchestrators if available and enabled
        self.intelligence_orchestrator = None
        self.ai_orchestrator = None
        self.performance_orchestrator = None
        
        if ADVANCED_ORCHESTRATORS:
            # Enable AI enhancement for standard, deep, and enterprise modes
            if (config.ai_enhanced or config.behavioral_analysis or config.threat_intel or 
                config.mode in ['standard', 'deep', 'enterprise']):
                self.intelligence_orchestrator = IntelligenceOrchestrator()
                self.ai_orchestrator = AISecurityOrchestrator()
            
            if config.mode in ['deep', 'enterprise'] or config.performance_config.max_threads > 4:
                self.performance_orchestrator = PerformanceOrchestrator()
        
        # Load scanning modules and plugins
        self._load_modules()
        self._load_plugins()
    
    def _load_modules(self):
        """Load and initialize core scanning modules."""
        from .modules import MODULE_REGISTRY, get_available_modules
        
        # Get enabled modules based on configuration
        enabled_modules = self._get_enabled_modules()
        
        for module_name in enabled_modules:
            if module_name in MODULE_REGISTRY:
                try:
                    module_class = MODULE_REGISTRY[module_name]
                    module = module_class(self.config, self.vuln_id_generator)
                    
                    # Check if module should run in current mode
                    module_mode = self._map_cli_mode_to_module_mode(self.config.mode)
                    if hasattr(module, 'should_run') and module.should_run(module_mode):
                        self.modules[module_name] = module
                    elif not hasattr(module, 'should_run'):
                        # Default behavior for modules without should_run
                        self.modules[module_name] = module
                    
                    if self.config.verbose:
                        self.console.print(f"[green]✅ Loaded module: {module_name}[/green]")
                        
                except Exception as e:
                    if self.config.verbose:
                        self.console.print(f"[red]❌ Failed to load module {module_name}: {e}[/red]")
    
    def _get_enabled_modules(self) -> List[str]:
        """Get list of enabled modules based on configuration."""
        from .modules import get_available_modules
        
        all_modules = get_available_modules()
        
        # If only_modules is specified, use only those
        if self.config.only_modules:
            return [m for m in self.config.only_modules if m in all_modules]
        
        # Otherwise, use all modules except skipped ones
        enabled = [m for m in all_modules if m not in self.config.skip_modules]
        
        # Map CLI modes to module modes
        module_mode = self._map_cli_mode_to_module_mode(self.config.mode)
        
        # Filter based on mapped mode
        if module_mode == 'quick':
            # In quick mode, skip runtime testing by default
            enabled = [m for m in enabled if m != 'runtime']
        
        return enabled
    
    def _map_cli_mode_to_module_mode(self, cli_mode: str) -> str:
        """Map CLI modes to module-compatible modes."""
        mode_mapping = {
            'quick': 'static',      # Quick mode = static analysis only
            'standard': 'static',    # Standard mode = static analysis
            'deep': 'full',          # Deep mode = full analysis
            'enterprise': 'full',    # Enterprise mode = full analysis
            'static': 'static',      # Direct static mode
            'dynamic': 'dynamic',    # Direct dynamic mode
            'full': 'full'           # Direct full mode
        }
        return mode_mapping.get(cli_mode, 'static')
    
    def _load_plugins(self):
        """Load and initialize plugins."""
        try:
            # Get enabled plugin names
            enabled_plugins = [name for name, config in self.config.plugins.items() 
                             if config.get('enabled', False)]
            
            # Load plugins
            plugin_classes = self.plugin_manager.load_plugins(enabled_plugins)
            
            for plugin_name, plugin_class in plugin_classes.items():
                try:
                    # Get plugin-specific config
                    plugin_config = self.config.get_plugin_config(plugin_name)
                    
                    # Create plugin instance
                    plugin = plugin_class(self.config, self.vuln_id_generator)
                    
                    # Validate plugin
                    if self._validate_plugin(plugin):
                        self.plugins[plugin_name] = plugin
                        if self.config.verbose:
                            self.console.print(f"[green]Loaded plugin: {plugin_name}[/green]")
                    
                except Exception as e:
                    if self.config.verbose:
                        self.console.print(f"[red]Failed to load plugin {plugin_name}: {e}[/red]")
        
        except Exception as e:
            if self.config.verbose:
                self.console.print(f"[yellow]Plugin loading error: {e}[/yellow]")
    
    def _validate_plugin(self, plugin) -> bool:
        """Validate plugin before use."""
        try:
            # Check if plugin has required methods
            if not hasattr(plugin, 'scan'):
                return False
            
            # Check framework compatibility
            if hasattr(plugin, 'supports_framework'):
                if not plugin.supports_framework(self.config.framework):
                    return False
            
            # Check if plugin should run in current mode
            if hasattr(plugin, 'should_run'):
                if not plugin.should_run(self.config.mode):
                    return False
            
            # Run pre-scan validation if available
            if hasattr(plugin, 'pre_scan_validation'):
                if not asyncio.run(plugin.pre_scan_validation(self.config.target)):
                    return False
            
            return True
            
        except Exception:
            return False
    
    async def scan(self) -> Dict[str, Any]:
        """Execute the main scanning process."""
        start_time = time.time()
        
        # Detect framework if auto
        if self.config.framework == 'auto':
            detected_framework = detect_framework(self.config.target)
            self.config.framework = detected_framework
            if self.config.verbose:
                self.console.print(f"[blue]Detected framework: {detected_framework}[/blue]")
        
        # Display scan info
        self._display_scan_info()
        
        # Check cache first
        cache_key = self._generate_cache_key()
        cached_results = self.cache_manager.get_cached_results(cache_key)
        
        if cached_results and not self.config.force_scan:
            if self.config.verbose:
                self.console.print("[yellow]Using cached results[/yellow]")
            vulnerabilities = [Vulnerability.from_dict(v) for v in cached_results]
        else:
            # Run scanning modules and plugins
            vulnerabilities = await self._run_scan_modules_and_plugins()
            
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
        
        # Enhance vulnerabilities with AI analysis if available
        if self.ai_orchestrator:
            try:
                # Convert vulnerabilities to dict format for AI enhancement
                vuln_dicts = [v.to_dict() for v in vulnerabilities]
                
                # Enhance with AI analysis
                enhanced_vuln_dicts = self.ai_orchestrator.enhance_vulnerabilities_with_ai_analysis(vuln_dicts)
                
                # Convert back to Vulnerability objects
                vulnerabilities = [Vulnerability.from_dict(v) for v in enhanced_vuln_dicts]
                
                if self.config.verbose:
                    self.console.print("[blue]✅ AI analysis enhancement applied[/blue]")
                    
            except Exception as e:
                if self.config.verbose:
                    self.console.print(f"[yellow]⚠️ AI enhancement failed: {e}[/yellow]")
        
        # Compile final results
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
            'ai_enhanced': self.ai_orchestrator is not None
        }
        
        return final_results
    
    async def _run_scan_modules_and_plugins(self) -> List[Vulnerability]:
        """Run all enabled scanning modules and plugins concurrently."""
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
                task = self._run_module_with_progress(module, progress, task_id)
                core_tasks.append((f"module_{module_name}", task))
            
            # Create tasks for plugins
            plugin_tasks = []
            for plugin_name, plugin in self.plugins.items():
                task_id = progress.add_task(f"Running plugin {plugin_name}...", total=100)
                task = self._run_plugin_with_progress(plugin, progress, task_id)
                plugin_tasks.append((f"plugin_{plugin_name}", task))
            
            # Run all tasks concurrently
            all_tasks = core_tasks + plugin_tasks
            for task_name, task in all_tasks:
                try:
                    task_vulnerabilities = await task
                    all_vulnerabilities.extend(task_vulnerabilities)
                except Exception as e:
                    if self.config.verbose:
                        self.console.print(f"[red]Error in {task_name}: {str(e)}[/red]")
        
        return all_vulnerabilities
    
    async def _run_module_with_progress(self, module: BaseModule, progress: Progress, task_id: int) -> List[Vulnerability]:
        """Run a single module with progress tracking."""
        try:
            progress.update(task_id, completed=25)
            
            # Run the module
            vulnerabilities = await module.scan(self.config.target)
            
            progress.update(task_id, completed=100)
            return vulnerabilities
            
        except Exception as e:
            progress.update(task_id, completed=100)
            raise e
    
    async def _run_plugin_with_progress(self, plugin, progress: Progress, task_id: int) -> List[Vulnerability]:
        """Run a single plugin with progress tracking."""
        try:
            progress.update(task_id, completed=25)
            
            # Run the plugin
            plugin_results = await plugin.scan(self.config.target)
            
            # Convert plugin results to Vulnerability objects
            vulnerabilities = []
            for result in plugin_results:
                if isinstance(result, dict):
                    # Convert dict to Vulnerability
                    vuln = Vulnerability.from_dict(result)
                    vulnerabilities.append(vuln)
                elif isinstance(result, Vulnerability):
                    vulnerabilities.append(result)
            
            # Post-processing if available
            if hasattr(plugin, 'post_scan_processing'):
                processed_results = await plugin.post_scan_processing([v.to_dict() for v in vulnerabilities])
                vulnerabilities = [Vulnerability.from_dict(r) for r in processed_results]
            
            progress.update(task_id, completed=100)
            return vulnerabilities
            
        except Exception as e:
            progress.update(task_id, completed=100)
            raise e
    
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
        """Display scan information."""
        info_table = Table(title="Scan Configuration")
        info_table.add_column("Setting", style="cyan")
        info_table.add_column("Value", style="green")
        
        info_table.add_row("Target", self.config.target)
        info_table.add_row("Framework", self.config.framework)
        info_table.add_row("Mode", self.config.mode)
        info_table.add_row("Core Modules", ", ".join(self.modules.keys()))
        
        if self.plugins:
            info_table.add_row("Plugins", ", ".join(self.plugins.keys()))
        
        info_table.add_row("Pentest Mode", "Enabled" if self.config.pentest_mode else "Disabled")
        
        self.console.print(info_table)
        self.console.print()
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate scan summary."""
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
            'plugins_with_findings': len(plugins_with_findings)
        }
    
    def display_results(self, results: Dict[str, Any]):
        """Display scan results in the terminal."""
        self.report_formatter.display_terminal_report(results)
        
        # Save to file if specified, otherwise save default report
        if self.config.output_file:
            self.report_formatter.save_report(results, self.config.output_file)
            self.console.print(f"\n[green]Report saved to: {self.config.output_file}[/green]")
        else:
            # Save default report as Markdown
            default_report_path = self._generate_default_report_path(results)
            self.report_formatter.save_markdown_report(results, default_report_path)
            self.console.print(f"\n[green]Report saved to: {default_report_path}[/green]")
    
    def _generate_default_report_path(self, results: Dict[str, Any]) -> str:
        """Generate default report path based on scan results."""
        from datetime import datetime
        import os
        
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate filename based on target and timestamp
        target_name = Path(self.config.target).name or "scan"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"njordscan_report_{target_name}_{timestamp}.md"
        
        return str(reports_dir / filename)

# Backward compatibility - Scanner class is defined above