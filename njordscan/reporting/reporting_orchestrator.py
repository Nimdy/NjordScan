"""
Reporting Orchestrator

Coordinates comprehensive reporting and visualization including:
- Multi-format report generation
- Interactive dashboard creation
- Compliance reporting
- Trend analysis and historical reporting
- Real-time monitoring dashboards
- Executive and technical reporting
"""

import asyncio
import time
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

from .report_generator import ReportGenerator, ReportConfiguration, ReportData, GeneratedReport, ReportFormat, ReportAudience
from .visualization_engine import VisualizationEngine, DashboardConfiguration, VisualizationData, ChartConfiguration

logger = logging.getLogger(__name__)

@dataclass
class ReportingConfiguration:
    """Configuration for comprehensive reporting."""
    
    # Output settings
    output_directory: Path = Path("reports")
    base_url: str = "http://localhost:8080"
    
    # Report generation
    default_formats: List[ReportFormat] = None
    generate_executive_reports: bool = True
    generate_technical_reports: bool = True
    generate_compliance_reports: bool = True
    
    # Dashboard settings
    enable_dashboards: bool = True
    dashboard_auto_refresh: bool = True
    dashboard_refresh_interval: int = 300  # 5 minutes
    
    # Visualization settings
    enable_charts: bool = True
    chart_theme: str = "security"
    enable_interactive_charts: bool = True
    
    # Historical tracking
    enable_trend_analysis: bool = True
    historical_data_retention: int = 365  # days
    
    # Performance settings
    max_concurrent_reports: int = 3
    report_timeout: int = 300  # 5 minutes
    enable_caching: bool = True
    cache_duration: int = 3600  # 1 hour
    
    # Notification settings
    enable_notifications: bool = False
    notification_webhooks: List[str] = None
    
    def __post_init__(self):
        if self.default_formats is None:
            self.default_formats = [ReportFormat.HTML, ReportFormat.JSON]
        if self.notification_webhooks is None:
            self.notification_webhooks = []

@dataclass
class ReportingRequest:
    """Request for report generation."""
    request_id: str
    request_type: str  # full_report, dashboard, compliance, trend_analysis
    
    # Data sources
    scan_data: Dict[str, Any]
    historical_data: List[Dict[str, Any]] = None
    compliance_data: Dict[str, Any] = None
    
    # Report configuration
    audiences: List[ReportAudience] = None
    formats: List[ReportFormat] = None
    include_dashboards: bool = True
    
    # Filtering and scope
    severity_filter: List[str] = None
    category_filter: List[str] = None
    
    # Output settings
    custom_output_path: Optional[Path] = None
    custom_title: Optional[str] = None
    
    # Priority and scheduling
    priority: str = "normal"  # low, normal, high, urgent
    schedule_time: Optional[float] = None
    
    def __post_init__(self):
        if self.audiences is None:
            self.audiences = [ReportAudience.TECHNICAL]
        if self.formats is None:
            self.formats = [ReportFormat.HTML]

@dataclass
class ReportingResult:
    """Result of comprehensive reporting."""
    request_id: str
    generation_time: float
    generation_duration: float
    
    # Generated reports
    generated_reports: Dict[ReportAudience, GeneratedReport]
    generated_dashboards: Dict[str, str]  # dashboard_id -> html_content
    
    # URLs and access
    report_urls: Dict[str, str]
    dashboard_urls: Dict[str, str]
    
    # Statistics
    total_reports: int
    total_dashboards: int
    total_file_size: int
    
    # Success metrics
    generation_success: bool
    generation_errors: List[str]
    
    # Metadata
    configuration: ReportingConfiguration
    orchestrator_version: str

class ReportingOrchestrator:
    """Comprehensive reporting and visualization orchestrator."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize components
        self.report_generator = ReportGenerator(config.get('report_generator', {}))
        self.visualization_engine = VisualizationEngine(config.get('visualization_engine', {}))
        
        # Orchestrator configuration
        self.reporting_config = ReportingConfiguration()
        if 'reporting' in config:
            for key, value in config['reporting'].items():
                if hasattr(self.reporting_config, key):
                    setattr(self.reporting_config, key, value)
        
        # Request queue and processing
        self.request_queue: asyncio.Queue = asyncio.Queue()
        self.active_requests: Dict[str, asyncio.Task] = {}
        self.completed_requests: Dict[str, ReportingResult] = {}
        
        # Historical data storage
        self.historical_data: List[Dict[str, Any]] = []
        
        # Cache for generated content
        self.report_cache: Dict[str, ReportingResult] = {}
        
        # Background tasks
        self.background_tasks: Set[asyncio.Task] = set()
        
        # Statistics
        self.stats = {
            'total_requests_processed': 0,
            'reports_generated': 0,
            'dashboards_created': 0,
            'total_processing_time': 0.0,
            'cache_hits': 0,
            'cache_misses': 0,
            'failed_requests': 0
        }
        
        self.start_time = time.time()
    
    async def initialize(self):
        """Initialize the reporting orchestrator."""
        
        logger.info("Initializing Reporting Orchestrator")
        
        # Create output directory
        self.reporting_config.output_directory.mkdir(parents=True, exist_ok=True)
        
        # Start background tasks
        await self._start_background_tasks()
        
        # Load historical data if available
        await self._load_historical_data()
        
        logger.info("Reporting Orchestrator initialized successfully")
    
    async def generate_comprehensive_report(self, request: ReportingRequest) -> ReportingResult:
        """Generate comprehensive report with all requested components."""
        
        generation_start_time = time.time()
        
        logger.info(f"Processing comprehensive reporting request: {request.request_id}")
        logger.info(f"Audiences: {[a.value for a in request.audiences]}, "
                   f"Formats: {[f.value for f in request.formats]}")
        
        try:
            # Check cache first
            cache_key = self._generate_cache_key(request)
            if (self.reporting_config.enable_caching and 
                cache_key in self.report_cache and
                self._is_cache_valid(cache_key)):
                
                cached_result = self.report_cache[cache_key]
                self.stats['cache_hits'] += 1
                logger.info(f"Returning cached report: {request.request_id}")
                return cached_result
            
            self.stats['cache_misses'] += 1
            
            # Initialize result
            result = ReportingResult(
                request_id=request.request_id,
                generation_time=generation_start_time,
                generation_duration=0.0,
                generated_reports={},
                generated_dashboards={},
                report_urls={},
                dashboard_urls={},
                total_reports=0,
                total_dashboards=0,
                total_file_size=0,
                generation_success=True,
                generation_errors=[],
                configuration=self.reporting_config,
                orchestrator_version="1.0.0"
            )
            
            # Prepare report data
            report_data = await self._prepare_report_data(request)
            
            # Generate reports for each audience
            report_tasks = []
            for audience in request.audiences:
                task = self._generate_audience_report(audience, request, report_data)
                report_tasks.append(task)
            
            # Generate dashboards if requested
            dashboard_tasks = []
            if request.include_dashboards and self.reporting_config.enable_dashboards:
                dashboard_tasks.append(self._generate_security_dashboard(request, report_data))
                
                if request.compliance_data:
                    dashboard_tasks.append(self._generate_compliance_dashboard(request, report_data))
                
                if request.historical_data:
                    dashboard_tasks.append(self._generate_trend_dashboard(request, report_data))
            
            # Execute all tasks
            all_tasks = report_tasks + dashboard_tasks
            
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*all_tasks, return_exceptions=True),
                    timeout=self.reporting_config.report_timeout
                )
                
                # Process report results
                for i, report_result in enumerate(results[:len(report_tasks)]):
                    if isinstance(report_result, Exception):
                        error_msg = f"Report generation failed for audience {request.audiences[i].value}: {str(report_result)}"
                        result.generation_errors.append(error_msg)
                        logger.error(error_msg)
                    else:
                        audience = request.audiences[i]
                        result.generated_reports[audience] = report_result
                        result.total_reports += 1
                        
                        # Generate URLs
                        for format_type, file_path in report_result.generated_files.items():
                            url_key = f"{audience.value}_{format_type.value}"
                            result.report_urls[url_key] = self._generate_file_url(file_path)
                
                # Process dashboard results
                dashboard_names = ['security', 'compliance', 'trends']
                for i, dashboard_result in enumerate(results[len(report_tasks):]):
                    if isinstance(dashboard_result, Exception):
                        error_msg = f"Dashboard generation failed for {dashboard_names[i]}: {str(dashboard_result)}"
                        result.generation_errors.append(error_msg)
                        logger.error(error_msg)
                    else:
                        dashboard_name = dashboard_names[i]
                        result.generated_dashboards[dashboard_name] = dashboard_result
                        result.total_dashboards += 1
                        
                        # Save dashboard HTML and generate URL
                        dashboard_file = await self._save_dashboard_html(
                            dashboard_result, dashboard_name, request.request_id
                        )
                        result.dashboard_urls[dashboard_name] = self._generate_file_url(dashboard_file)
                
            except asyncio.TimeoutError:
                error_msg = f"Report generation timed out after {self.reporting_config.report_timeout}s"
                result.generation_errors.append(error_msg)
                logger.error(error_msg)
                result.generation_success = False
            
            # Calculate total file size
            result.total_file_size = await self._calculate_total_file_size(result)
            
            # Finalize result
            result.generation_duration = time.time() - generation_start_time
            result.generation_success = (result.generation_success and 
                                       len(result.generation_errors) == 0 and
                                       (result.total_reports > 0 or result.total_dashboards > 0))
            
            # Cache successful result
            if (result.generation_success and self.reporting_config.enable_caching):
                self.report_cache[cache_key] = result
            
            # Update statistics
            self._update_statistics(result)
            
            # Store historical data
            await self._store_historical_data(request.scan_data)
            
            # Send notifications if configured
            if self.reporting_config.enable_notifications:
                await self._send_notifications(result)
            
            if result.generation_success:
                logger.info(f"Comprehensive reporting completed: {request.request_id} "
                           f"({result.total_reports} reports, {result.total_dashboards} dashboards, "
                           f"{result.generation_duration:.2f}s)")
            else:
                logger.error(f"Comprehensive reporting failed: {request.request_id}")
                self.stats['failed_requests'] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Comprehensive reporting failed: {request.request_id} - {str(e)}")
            
            # Return failed result
            return ReportingResult(
                request_id=request.request_id,
                generation_time=generation_start_time,
                generation_duration=time.time() - generation_start_time,
                generated_reports={},
                generated_dashboards={},
                report_urls={},
                dashboard_urls={},
                total_reports=0,
                total_dashboards=0,
                total_file_size=0,
                generation_success=False,
                generation_errors=[str(e)],
                configuration=self.reporting_config,
                orchestrator_version="1.0.0"
            )
    
    async def generate_real_time_dashboard(self, scan_data: Dict[str, Any]) -> str:
        """Generate real-time monitoring dashboard."""
        
        logger.info("Generating real-time monitoring dashboard")
        
        try:
            # Create dashboard configuration
            dashboard_config = await self.visualization_engine.create_security_overview_dashboard(scan_data)
            dashboard_config.auto_refresh = True
            dashboard_config.refresh_interval = self.reporting_config.dashboard_refresh_interval
            
            # Prepare data sources
            data_sources = {
                'severity_data': self.visualization_engine._prepare_severity_data(scan_data),
                'category_data': self.visualization_engine._prepare_category_data(scan_data),
                'findings_data': self.visualization_engine._prepare_findings_data(scan_data)
            }
            
            # Add risk score data
            risk_data = VisualizationData(
                data_id="risk_data",
                name="Risk Score",
                data=[{'value': scan_data.get('overall_risk_score', 0)}]
            )
            data_sources['risk_data'] = risk_data
            
            # Generate dashboard
            dashboard_html = await self.visualization_engine.generate_dashboard(dashboard_config, data_sources)
            
            return dashboard_html
            
        except Exception as e:
            logger.error(f"Failed to generate real-time dashboard: {str(e)}")
            return self._generate_error_dashboard(str(e))
    
    async def generate_trend_report(self, project_name: str, days: int = 30) -> Optional[ReportingResult]:
        """Generate trend analysis report."""
        
        logger.info(f"Generating trend report for {project_name} ({days} days)")
        
        try:
            # Get historical data
            historical_data = await self._get_historical_data(project_name, days)
            
            if not historical_data:
                logger.warning(f"No historical data found for {project_name}")
                return None
            
            # Create trend analysis request
            request = ReportingRequest(
                request_id=f"trend_report_{project_name}_{int(time.time())}",
                request_type="trend_analysis",
                scan_data=historical_data[-1] if historical_data else {},
                historical_data=historical_data,
                audiences=[ReportAudience.EXECUTIVE, ReportAudience.SECURITY],
                formats=[ReportFormat.HTML, ReportFormat.PDF],
                include_dashboards=True,
                custom_title=f"Security Trend Analysis - {project_name}"
            )
            
            # Generate comprehensive report
            return await self.generate_comprehensive_report(request)
            
        except Exception as e:
            logger.error(f"Failed to generate trend report: {str(e)}")
            return None
    
    async def _prepare_report_data(self, request: ReportingRequest) -> ReportData:
        """Prepare comprehensive report data."""
        
        scan_data = request.scan_data
        
        # Calculate summary statistics
        findings = scan_data.get('findings', [])
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Prepare report data
        report_data = ReportData(
            scan_id=scan_data.get('scan_id', 'unknown'),
            project_name=scan_data.get('project_name', 'Unknown Project'),
            scan_timestamp=scan_data.get('scan_timestamp', time.time()),
            scan_duration=scan_data.get('scan_duration', 0.0),
            njordscan_version=scan_data.get('njordscan_version', '1.0.0'),
            total_findings=len(findings),
            critical_findings=severity_counts.get('critical', 0),
            high_findings=severity_counts.get('high', 0),
            medium_findings=severity_counts.get('medium', 0),
            low_findings=severity_counts.get('low', 0),
            info_findings=severity_counts.get('info', 0),
            findings=findings,
            overall_risk_score=scan_data.get('overall_risk_score', 0.0),
            risk_level=scan_data.get('risk_level', 'unknown'),
            business_impact_score=scan_data.get('business_impact_score', 0.0),
            compliance_results=request.compliance_data or {},
            historical_data=request.historical_data or [],
            immediate_actions=scan_data.get('immediate_actions', []),
            short_term_recommendations=scan_data.get('short_term_recommendations', []),
            long_term_recommendations=scan_data.get('long_term_recommendations', []),
            project_metadata=scan_data.get('project_metadata', {}),
            environment_info=scan_data.get('environment_info', {})
        )
        
        # Add trend analysis if historical data is available
        if request.historical_data:
            report_data.trend_analysis = await self._analyze_trends(request.historical_data)
        
        return report_data
    
    async def _generate_audience_report(self, audience: ReportAudience, 
                                       request: ReportingRequest, 
                                       report_data: ReportData) -> GeneratedReport:
        """Generate report for specific audience."""
        
        # Create report configuration
        config = ReportConfiguration(
            title=request.custom_title or f"Security Analysis Report - {audience.value.title()}",
            subtitle=f"Generated for {report_data.project_name}",
            audience=audience,
            formats=request.formats,
            severity_filter=request.severity_filter or [],
            category_filter=request.category_filter or [],
            output_directory=request.custom_output_path or self.reporting_config.output_directory,
            include_charts=self.reporting_config.enable_charts,
            include_trend_analysis=len(report_data.historical_data) > 0,
            include_compliance_mapping=len(report_data.compliance_results) > 0
        )
        
        # Generate report
        return await self.report_generator.generate_report(report_data, config)
    
    async def _generate_security_dashboard(self, request: ReportingRequest, 
                                          report_data: ReportData) -> str:
        """Generate security overview dashboard."""
        
        return await self.visualization_engine.create_security_overview_dashboard(request.scan_data)
    
    async def _generate_compliance_dashboard(self, request: ReportingRequest, 
                                            report_data: ReportData) -> str:
        """Generate compliance dashboard."""
        
        dashboard_config = await self.visualization_engine.create_compliance_dashboard(
            request.compliance_data
        )
        
        # Prepare data sources (simplified)
        data_sources = {}
        
        return await self.visualization_engine.generate_dashboard(dashboard_config, data_sources)
    
    async def _generate_trend_dashboard(self, request: ReportingRequest, 
                                       report_data: ReportData) -> str:
        """Generate trend analysis dashboard."""
        
        # This would create a trend-specific dashboard
        return await self._generate_security_dashboard(request, report_data)
    
    async def _save_dashboard_html(self, dashboard_html: str, dashboard_name: str, 
                                  request_id: str) -> Path:
        """Save dashboard HTML to file."""
        
        filename = f"dashboard_{dashboard_name}_{request_id}.html"
        file_path = self.reporting_config.output_directory / filename
        
        file_path.write_text(dashboard_html, encoding='utf-8')
        
        return file_path
    
    def _generate_file_url(self, file_path: Path) -> str:
        """Generate URL for file access."""
        
        relative_path = file_path.relative_to(self.reporting_config.output_directory)
        return f"{self.reporting_config.base_url}/reports/{relative_path}"
    
    async def _calculate_total_file_size(self, result: ReportingResult) -> int:
        """Calculate total size of generated files."""
        
        total_size = 0
        
        # Add report file sizes
        for report in result.generated_reports.values():
            total_size += sum(report.file_sizes.values())
        
        # Add dashboard file sizes (estimate)
        for dashboard_html in result.generated_dashboards.values():
            total_size += len(dashboard_html.encode('utf-8'))
        
        return total_size
    
    def _generate_cache_key(self, request: ReportingRequest) -> str:
        """Generate cache key for request."""
        
        import hashlib
        
        key_data = {
            'scan_data_hash': hashlib.md5(
                json.dumps(request.scan_data, sort_keys=True, default=str).encode()
            ).hexdigest(),
            'audiences': [a.value for a in request.audiences],
            'formats': [f.value for f in request.formats],
            'filters': {
                'severity': request.severity_filter or [],
                'category': request.category_filter or []
            }
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached result is still valid."""
        
        # Simple time-based cache validation
        cached_result = self.report_cache.get(cache_key)
        if not cached_result:
            return False
        
        age = time.time() - cached_result.generation_time
        return age < self.reporting_config.cache_duration
    
    async def _analyze_trends(self, historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze trends in historical data."""
        
        if len(historical_data) < 2:
            return {}
        
        # Calculate trend metrics
        latest = historical_data[-1]
        previous = historical_data[-2]
        
        trends = {
            'total_findings_trend': latest.get('total_findings', 0) - previous.get('total_findings', 0),
            'risk_score_trend': latest.get('overall_risk_score', 0) - previous.get('overall_risk_score', 0),
            'critical_findings_trend': latest.get('critical_findings', 0) - previous.get('critical_findings', 0),
            'data_points': len(historical_data),
            'time_span_days': (latest.get('scan_timestamp', 0) - historical_data[0].get('scan_timestamp', 0)) / 86400
        }
        
        return trends
    
    async def _store_historical_data(self, scan_data: Dict[str, Any]):
        """Store scan data for historical analysis."""
        
        # Add timestamp if not present
        if 'scan_timestamp' not in scan_data:
            scan_data['scan_timestamp'] = time.time()
        
        # Add to historical data
        self.historical_data.append(scan_data)
        
        # Limit historical data based on retention policy
        cutoff_time = time.time() - (self.reporting_config.historical_data_retention * 86400)
        self.historical_data = [
            data for data in self.historical_data 
            if data.get('scan_timestamp', 0) > cutoff_time
        ]
    
    async def _get_historical_data(self, project_name: str, days: int) -> List[Dict[str, Any]]:
        """Get historical data for project."""
        
        cutoff_time = time.time() - (days * 86400)
        
        return [
            data for data in self.historical_data
            if (data.get('project_name') == project_name and
                data.get('scan_timestamp', 0) > cutoff_time)
        ]
    
    async def _load_historical_data(self):
        """Load historical data from storage."""
        
        # This would load from persistent storage
        logger.debug("Loading historical data")
    
    def _generate_error_dashboard(self, error_message: str) -> str:
        """Generate error dashboard HTML."""
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard Error</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; text-align: center; }}
                .error {{ color: #dc3545; border: 1px solid #dc3545; padding: 20px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="error">
                <h2>Dashboard Generation Error</h2>
                <p>{error_message}</p>
            </div>
        </body>
        </html>
        '''
    
    async def _start_background_tasks(self):
        """Start background maintenance tasks."""
        
        # Cache cleanup task
        task = asyncio.create_task(self._cache_cleanup_task())
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)
    
    async def _cache_cleanup_task(self):
        """Background task to clean up expired cache entries."""
        
        while True:
            try:
                current_time = time.time()
                expired_keys = []
                
                for cache_key, result in self.report_cache.items():
                    if current_time - result.generation_time > self.reporting_config.cache_duration:
                        expired_keys.append(cache_key)
                
                for key in expired_keys:
                    del self.report_cache[key]
                
                if expired_keys:
                    logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
                
                # Run every hour
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error(f"Cache cleanup task error: {str(e)}")
                await asyncio.sleep(3600)
    
    async def _send_notifications(self, result: ReportingResult):
        """Send notifications about report generation."""
        
        # This would send notifications via webhooks, email, etc.
        logger.debug(f"Sending notifications for report: {result.request_id}")
    
    def _update_statistics(self, result: ReportingResult):
        """Update orchestrator statistics."""
        
        self.stats['total_requests_processed'] += 1
        self.stats['reports_generated'] += result.total_reports
        self.stats['dashboards_created'] += result.total_dashboards
        self.stats['total_processing_time'] += result.generation_duration
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        
        stats = dict(self.stats)
        stats['uptime'] = time.time() - self.start_time
        stats['cache_size'] = len(self.report_cache)
        stats['historical_data_points'] = len(self.historical_data)
        
        return stats
    
    async def shutdown(self):
        """Shutdown the reporting orchestrator."""
        
        logger.info("Shutting down Reporting Orchestrator")
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        logger.info("Reporting Orchestrator shutdown completed")
