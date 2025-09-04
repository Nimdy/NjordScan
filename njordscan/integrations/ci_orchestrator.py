"""
CI/CD Integration Orchestrator

Comprehensive CI/CD pipeline integration system including:
- Multi-platform CI/CD support (GitHub Actions, GitLab CI, Jenkins, Azure DevOps)
- Quality gates and security policies
- Automated scanning triggers and webhooks
- Pull request automation and comments
- SARIF integration for security alerts
- Deployment gates and approval workflows
"""

import asyncio
import json
import time
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
import hashlib
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class CIPlatform(Enum):
    """Supported CI/CD platforms."""
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    CIRCLECI = "circleci"
    TRAVIS_CI = "travis_ci"
    BITBUCKET_PIPELINES = "bitbucket_pipelines"
    TEAMCITY = "teamcity"
    BAMBOO = "bamboo"
    DRONE = "drone"

class TriggerEvent(Enum):
    """CI/CD trigger events."""
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    MERGE_REQUEST = "merge_request"
    SCHEDULE = "schedule"
    MANUAL = "manual"
    RELEASE = "release"
    TAG = "tag"
    DEPLOYMENT = "deployment"

class ScanScope(Enum):
    """Scan scope for CI/CD integration."""
    FULL_SCAN = "full_scan"
    INCREMENTAL_SCAN = "incremental_scan"
    CHANGED_FILES_ONLY = "changed_files_only"
    DEPENDENCIES_ONLY = "dependencies_only"
    CONFIGURATION_ONLY = "configuration_only"

@dataclass
class CIConfiguration:
    """Configuration for CI/CD integration."""
    
    # Platform settings
    platform: CIPlatform
    repository_url: str
    branch_patterns: List[str] = field(default_factory=lambda: ["main", "master", "develop"])
    
    # Trigger configuration
    enabled_events: List[TriggerEvent] = field(default_factory=lambda: [TriggerEvent.PUSH, TriggerEvent.PULL_REQUEST])
    scan_scope: ScanScope = ScanScope.FULL_SCAN
    
    # Quality gates
    enable_quality_gates: bool = True
    fail_on_critical: bool = True
    fail_on_high: bool = False
    max_allowed_findings: Optional[int] = None
    security_score_threshold: float = 70.0
    
    # Scanning options
    timeout_minutes: int = 30
    parallel_scans: bool = True
    cache_dependencies: bool = True
    
    # Reporting and notifications
    generate_sarif: bool = True
    comment_on_pr: bool = True
    upload_artifacts: bool = True
    send_notifications: bool = True
    
    # Advanced options
    baseline_comparison: bool = True
    differential_scanning: bool = True
    security_hotspots_only: bool = False
    
    # Credentials and access
    api_token: Optional[str] = None
    webhook_secret: Optional[str] = None
    
    # Custom configuration
    custom_config_path: Optional[str] = None
    environment_variables: Dict[str, str] = field(default_factory=dict)

@dataclass
class CIScanRequest:
    """CI/CD scan request."""
    request_id: str
    platform: CIPlatform
    repository: str
    branch: str
    commit_sha: str
    
    # Trigger information
    trigger_event: TriggerEvent
    triggered_by: str
    trigger_timestamp: float
    
    # Scan configuration
    scan_scope: ScanScope
    target_paths: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    
    # Pull request information (if applicable)
    pull_request_id: Optional[int] = None
    base_branch: Optional[str] = None
    changed_files: List[str] = field(default_factory=list)
    
    # Environment context
    environment: str = "ci"
    build_number: Optional[str] = None
    job_id: Optional[str] = None
    
    # Custom parameters
    custom_parameters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CIScanResult:
    """CI/CD scan result."""
    request_id: str
    scan_id: str
    
    # Execution details
    start_time: float
    end_time: float
    duration: float
    
    # Results summary
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    
    # Quality gate results
    quality_gate_passed: bool
    quality_gate_details: Dict[str, Any] = field(default_factory=dict)
    
    # Security metrics
    security_score: float = 0.0
    risk_level: str = "unknown"
    new_findings: int = 0
    fixed_findings: int = 0
    
    # Generated artifacts
    sarif_report_path: Optional[str] = None
    html_report_path: Optional[str] = None
    json_report_path: Optional[str] = None
    
    # Integration outputs
    pr_comment_posted: bool = False
    security_alerts_created: bool = False
    notifications_sent: bool = False
    
    # Error handling
    scan_success: bool = True
    error_messages: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class QualityGateRule:
    """Quality gate rule definition."""
    rule_id: str
    name: str
    description: str
    
    # Rule conditions
    metric: str  # total_findings, critical_findings, security_score, etc.
    operator: str  # >, <, >=, <=, ==, !=
    threshold: Union[int, float]
    
    # Rule behavior
    severity: str = "error"  # error, warning, info
    block_deployment: bool = True
    
    # Context
    applies_to_branches: List[str] = field(default_factory=list)
    applies_to_events: List[TriggerEvent] = field(default_factory=list)
    
    # Metadata
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

class CIOrchestrator:
    """Comprehensive CI/CD integration orchestrator."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Orchestrator configuration
        self.orchestrator_config = {
            'max_concurrent_scans': self.config.get('max_concurrent_scans', 5),
            'default_timeout': self.config.get('default_timeout', 1800),  # 30 minutes
            'enable_caching': self.config.get('enable_caching', True),
            'cache_duration': self.config.get('cache_duration', 3600),  # 1 hour
            'webhook_port': self.config.get('webhook_port', 8080),
            'webhook_path': self.config.get('webhook_path', '/webhook'),
            'artifacts_directory': self.config.get('artifacts_directory', 'ci_artifacts')
        }
        
        # Platform integrations
        self.platform_integrations = {}
        
        # Quality gate engine
        from .quality_gates import QualityGateEngine
        self.quality_gate_engine = QualityGateEngine(config.get('quality_gates', {}))
        
        # Notification manager
        from .notification_manager import NotificationManager
        self.notification_manager = NotificationManager(config.get('notifications', {}))
        
        # Active scans and queue
        self.active_scans: Dict[str, asyncio.Task] = {}
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.scan_results: Dict[str, CIScanResult] = {}
        
        # Webhook handlers
        self.webhook_handlers: Dict[CIPlatform, callable] = {}
        
        # Baseline data for comparison
        self.baselines: Dict[str, Dict[str, Any]] = {}  # repo_branch -> baseline_data
        
        # Statistics
        self.stats = {
            'total_scans_triggered': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'quality_gates_passed': 0,
            'quality_gates_failed': 0,
            'pull_requests_commented': 0,
            'notifications_sent': 0,
            'total_scan_time': 0.0
        }
        
        self.start_time = time.time()
    
    async def initialize(self):
        """Initialize the CI/CD orchestrator."""
        
        logger.info("Initializing CI/CD Orchestrator")
        
        # Initialize platform integrations
        await self._initialize_platform_integrations()
        
        # Initialize quality gate engine
        await self.quality_gate_engine.initialize()
        
        # Initialize notification manager
        await self.notification_manager.initialize()
        
        # Setup webhook handlers
        await self._setup_webhook_handlers()
        
        # Start background workers
        await self._start_background_workers()
        
        # Create artifacts directory
        Path(self.orchestrator_config['artifacts_directory']).mkdir(parents=True, exist_ok=True)
        
        logger.info("CI/CD Orchestrator initialized successfully")
    
    async def register_ci_configuration(self, repo_id: str, config: CIConfiguration) -> bool:
        """Register CI/CD configuration for a repository."""
        
        logger.info(f"Registering CI/CD configuration for repository: {repo_id}")
        
        try:
            # Get platform integration
            platform_integration = self.platform_integrations.get(config.platform)
            if not platform_integration:
                logger.error(f"Platform integration not available: {config.platform.value}")
                return False
            
            # Register configuration with platform
            success = await platform_integration.register_repository(repo_id, config)
            
            if success:
                logger.info(f"CI/CD configuration registered successfully for {repo_id}")
            else:
                logger.error(f"Failed to register CI/CD configuration for {repo_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error registering CI/CD configuration for {repo_id}: {str(e)}")
            return False
    
    async def trigger_scan(self, scan_request: CIScanRequest) -> str:
        """Trigger a CI/CD scan."""
        
        logger.info(f"Triggering CI/CD scan: {scan_request.request_id}")
        logger.info(f"Repository: {scan_request.repository}, Branch: {scan_request.branch}, "
                   f"Event: {scan_request.trigger_event.value}")
        
        try:
            # Validate scan request
            if not await self._validate_scan_request(scan_request):
                raise ValueError("Invalid scan request")
            
            # Check for duplicate scans
            if await self._is_duplicate_scan(scan_request):
                logger.info(f"Duplicate scan detected, skipping: {scan_request.request_id}")
                return "skipped"
            
            # Add to scan queue
            await self.scan_queue.put(scan_request)
            
            self.stats['total_scans_triggered'] += 1
            
            logger.info(f"Scan queued successfully: {scan_request.request_id}")
            
            return scan_request.request_id
            
        except Exception as e:
            logger.error(f"Failed to trigger scan {scan_request.request_id}: {str(e)}")
            raise
    
    async def process_webhook(self, platform: CIPlatform, payload: Dict[str, Any], 
                            headers: Dict[str, str]) -> bool:
        """Process incoming webhook from CI/CD platform."""
        
        logger.info(f"Processing webhook from {platform.value}")
        
        try:
            # Get webhook handler
            handler = self.webhook_handlers.get(platform)
            if not handler:
                logger.error(f"No webhook handler for platform: {platform.value}")
                return False
            
            # Verify webhook signature if configured
            if not await self._verify_webhook_signature(platform, payload, headers):
                logger.warning(f"Webhook signature verification failed for {platform.value}")
                return False
            
            # Process webhook
            scan_request = await handler(payload, headers)
            
            if scan_request:
                # Trigger scan
                await self.trigger_scan(scan_request)
                return True
            else:
                logger.debug(f"Webhook did not result in scan trigger for {platform.value}")
                return True
                
        except Exception as e:
            logger.error(f"Error processing webhook from {platform.value}: {str(e)}")
            return False
    
    async def get_scan_result(self, request_id: str) -> Optional[CIScanResult]:
        """Get scan result by request ID."""
        
        return self.scan_results.get(request_id)
    
    async def get_scan_status(self, request_id: str) -> str:
        """Get scan status."""
        
        if request_id in self.active_scans:
            task = self.active_scans[request_id]
            if task.done():
                return "completed"
            else:
                return "running"
        elif request_id in self.scan_results:
            return "completed"
        else:
            return "not_found"
    
    async def cancel_scan(self, request_id: str) -> bool:
        """Cancel an active scan."""
        
        if request_id in self.active_scans:
            task = self.active_scans[request_id]
            task.cancel()
            del self.active_scans[request_id]
            logger.info(f"Scan cancelled: {request_id}")
            return True
        
        return False
    
    async def _initialize_platform_integrations(self):
        """Initialize platform-specific integrations."""
        
        # GitHub Actions
        if 'github' in self.config:
            from .github_integration import GitHubIntegration
            self.platform_integrations[CIPlatform.GITHUB_ACTIONS] = GitHubIntegration(
                self.config['github']
            )
        
        # GitLab CI
        if 'gitlab' in self.config:
            from .gitlab_integration import GitLabIntegration
            self.platform_integrations[CIPlatform.GITLAB_CI] = GitLabIntegration(
                self.config['gitlab']
            )
        
        # Jenkins
        if 'jenkins' in self.config:
            from .jenkins_integration import JenkinsIntegration
            self.platform_integrations[CIPlatform.JENKINS] = JenkinsIntegration(
                self.config['jenkins']
            )
        
        # Azure DevOps
        if 'azure_devops' in self.config:
            from .azure_devops_integration import AzureDevOpsIntegration
            self.platform_integrations[CIPlatform.AZURE_DEVOPS] = AzureDevOpsIntegration(
                self.config['azure_devops']
            )
        
        # Initialize all integrations
        for integration in self.platform_integrations.values():
            await integration.initialize()
    
    async def _setup_webhook_handlers(self):
        """Setup webhook handlers for each platform."""
        
        for platform, integration in self.platform_integrations.items():
            self.webhook_handlers[platform] = integration.process_webhook
    
    async def _start_background_workers(self):
        """Start background worker tasks."""
        
        # Start scan processor workers
        for i in range(self.orchestrator_config['max_concurrent_scans']):
            asyncio.create_task(self._scan_processor_worker(f"worker_{i}"))
        
        # Start cleanup worker
        asyncio.create_task(self._cleanup_worker())
    
    async def _scan_processor_worker(self, worker_id: str):
        """Background worker to process scan requests."""
        
        logger.info(f"Starting scan processor worker: {worker_id}")
        
        while True:
            try:
                # Get scan request from queue
                scan_request = await self.scan_queue.get()
                
                # Process scan
                task = asyncio.create_task(self._execute_scan(scan_request))
                self.active_scans[scan_request.request_id] = task
                
                # Wait for completion
                await task
                
                # Remove from active scans
                if scan_request.request_id in self.active_scans:
                    del self.active_scans[scan_request.request_id]
                
                # Mark task as done
                self.scan_queue.task_done()
                
            except asyncio.CancelledError:
                logger.info(f"Scan processor worker {worker_id} cancelled")
                break
            except Exception as e:
                logger.error(f"Error in scan processor worker {worker_id}: {str(e)}")
                await asyncio.sleep(5)
    
    async def _execute_scan(self, scan_request: CIScanRequest) -> CIScanResult:
        """Execute a complete CI/CD scan."""
        
        start_time = time.time()
        scan_id = f"ci_scan_{scan_request.request_id}_{int(start_time)}"
        
        logger.info(f"Executing CI/CD scan: {scan_id}")
        
        # Initialize result
        result = CIScanResult(
            request_id=scan_request.request_id,
            scan_id=scan_id,
            start_time=start_time,
            end_time=0.0,
            duration=0.0,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
            info_findings=0,
            quality_gate_passed=False,
            security_score=0.0,
            risk_level="unknown"
        )
        
        try:
            # 1. Prepare scan environment
            scan_context = await self._prepare_scan_environment(scan_request)
            
            # 2. Execute security scan
            scan_data = await self._execute_security_scan(scan_request, scan_context)
            
            # 3. Process scan results
            result = await self._process_scan_results(scan_data, result, scan_request)
            
            # 4. Generate reports and artifacts
            await self._generate_ci_artifacts(result, scan_request, scan_data)
            
            # 5. Run quality gates
            quality_gate_result = await self.quality_gate_engine.evaluate(
                scan_data, scan_request.repository, scan_request.branch
            )
            result.quality_gate_passed = quality_gate_result['passed']
            result.quality_gate_details = quality_gate_result
            
            # 6. Compare with baseline (if enabled)
            if scan_request.custom_parameters.get('baseline_comparison', True):
                await self._perform_baseline_comparison(result, scan_request, scan_data)
            
            # 7. Post-process integrations
            await self._post_process_integrations(result, scan_request, scan_data)
            
            # Mark as successful
            result.scan_success = True
            self.stats['successful_scans'] += 1
            
            if result.quality_gate_passed:
                self.stats['quality_gates_passed'] += 1
            else:
                self.stats['quality_gates_failed'] += 1
            
            logger.info(f"CI/CD scan completed successfully: {scan_id} "
                       f"({result.total_findings} findings, "
                       f"quality gate: {'PASSED' if result.quality_gate_passed else 'FAILED'})")
            
        except Exception as e:
            result.scan_success = False
            result.error_messages.append(str(e))
            self.stats['failed_scans'] += 1
            
            logger.error(f"CI/CD scan failed: {scan_id} - {str(e)}")
        
        finally:
            # Finalize result
            result.end_time = time.time()
            result.duration = result.end_time - result.start_time
            
            # Store result
            self.scan_results[scan_request.request_id] = result
            
            # Update statistics
            self.stats['total_scan_time'] += result.duration
        
        return result
    
    async def _prepare_scan_environment(self, scan_request: CIScanRequest) -> Dict[str, Any]:
        """Prepare scan environment and context."""
        
        logger.debug(f"Preparing scan environment for {scan_request.request_id}")
        
        # Get platform integration
        platform_integration = self.platform_integrations.get(
            self._get_platform_from_request(scan_request)
        )
        
        if platform_integration:
            return await platform_integration.prepare_scan_environment(scan_request)
        else:
            return {
                'repository': scan_request.repository,
                'branch': scan_request.branch,
                'commit_sha': scan_request.commit_sha,
                'target_paths': scan_request.target_paths or ['.'],
                'exclude_paths': scan_request.exclude_paths or []
            }
    
    async def _execute_security_scan(self, scan_request: CIScanRequest, 
                                    scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the actual security scan."""
        
        logger.debug(f"Executing security scan for {scan_request.request_id}")
        
        # This would integrate with the main NjordScan scanning engine
        # For now, return mock data
        
        return {
            'scan_id': f"scan_{scan_request.request_id}",
            'findings': [],
            'summary': {
                'total_findings': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0,
                'info_findings': 0
            },
            'security_score': 85.0,
            'risk_level': 'medium'
        }
    
    async def _process_scan_results(self, scan_data: Dict[str, Any], 
                                   result: CIScanResult, 
                                   scan_request: CIScanRequest) -> CIScanResult:
        """Process and enrich scan results."""
        
        summary = scan_data.get('summary', {})
        
        result.total_findings = summary.get('total_findings', 0)
        result.critical_findings = summary.get('critical_findings', 0)
        result.high_findings = summary.get('high_findings', 0)
        result.medium_findings = summary.get('medium_findings', 0)
        result.low_findings = summary.get('low_findings', 0)
        result.info_findings = summary.get('info_findings', 0)
        result.security_score = scan_data.get('security_score', 0.0)
        result.risk_level = scan_data.get('risk_level', 'unknown')
        
        return result
    
    async def _generate_ci_artifacts(self, result: CIScanResult, 
                                    scan_request: CIScanRequest, 
                                    scan_data: Dict[str, Any]):
        """Generate CI/CD artifacts (reports, SARIF, etc.)."""
        
        logger.debug(f"Generating CI artifacts for {scan_request.request_id}")
        
        artifacts_dir = Path(self.orchestrator_config['artifacts_directory'])
        scan_dir = artifacts_dir / scan_request.request_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate SARIF report
        if scan_request.custom_parameters.get('generate_sarif', True):
            sarif_path = scan_dir / "results.sarif"
            await self._generate_sarif_report(scan_data, sarif_path)
            result.sarif_report_path = str(sarif_path)
        
        # Generate HTML report
        html_path = scan_dir / "report.html"
        await self._generate_html_report(scan_data, html_path)
        result.html_report_path = str(html_path)
        
        # Generate JSON report
        json_path = scan_dir / "results.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(scan_data, f, indent=2, default=str)
        result.json_report_path = str(json_path)
    
    async def _perform_baseline_comparison(self, result: CIScanResult, 
                                          scan_request: CIScanRequest, 
                                          scan_data: Dict[str, Any]):
        """Perform baseline comparison to identify new/fixed findings."""
        
        baseline_key = f"{scan_request.repository}_{scan_request.base_branch or 'main'}"
        baseline = self.baselines.get(baseline_key)
        
        if baseline:
            # Compare findings
            current_findings = set(f.get('id', '') for f in scan_data.get('findings', []))
            baseline_findings = set(f.get('id', '') for f in baseline.get('findings', []))
            
            result.new_findings = len(current_findings - baseline_findings)
            result.fixed_findings = len(baseline_findings - current_findings)
        
        # Update baseline for main branches
        if scan_request.branch in ['main', 'master', 'develop']:
            self.baselines[baseline_key] = scan_data
    
    async def _post_process_integrations(self, result: CIScanResult, 
                                        scan_request: CIScanRequest, 
                                        scan_data: Dict[str, Any]):
        """Post-process integrations (comments, notifications, etc.)."""
        
        # Get platform integration
        platform_integration = self.platform_integrations.get(
            self._get_platform_from_request(scan_request)
        )
        
        if platform_integration:
            # Post PR comment
            if (scan_request.pull_request_id and 
                scan_request.custom_parameters.get('comment_on_pr', True)):
                
                comment_posted = await platform_integration.post_pr_comment(
                    scan_request, result, scan_data
                )
                result.pr_comment_posted = comment_posted
                
                if comment_posted:
                    self.stats['pull_requests_commented'] += 1
            
            # Create security alerts
            if scan_request.custom_parameters.get('create_security_alerts', True):
                alerts_created = await platform_integration.create_security_alerts(
                    scan_request, result, scan_data
                )
                result.security_alerts_created = alerts_created
        
        # Send notifications
        if scan_request.custom_parameters.get('send_notifications', True):
            notifications_sent = await self.notification_manager.send_scan_notifications(
                scan_request, result, scan_data
            )
            result.notifications_sent = notifications_sent
            
            if notifications_sent:
                self.stats['notifications_sent'] += 1
    
    def _get_platform_from_request(self, scan_request: CIScanRequest) -> CIPlatform:
        """Get platform from scan request."""
        return scan_request.platform
    
    async def _validate_scan_request(self, scan_request: CIScanRequest) -> bool:
        """Validate scan request."""
        
        # Basic validation
        if not scan_request.repository or not scan_request.branch:
            return False
        
        # Check if platform integration is available
        if scan_request.platform not in self.platform_integrations:
            return False
        
        return True
    
    async def _is_duplicate_scan(self, scan_request: CIScanRequest) -> bool:
        """Check if this is a duplicate scan."""
        
        # Simple duplicate detection based on repo, branch, and commit
        scan_key = f"{scan_request.repository}_{scan_request.branch}_{scan_request.commit_sha}"
        
        # Check active scans
        for active_request_id, task in self.active_scans.items():
            if not task.done():
                # Would check if this matches the current request
                pass
        
        return False
    
    async def _verify_webhook_signature(self, platform: CIPlatform, 
                                       payload: Dict[str, Any], 
                                       headers: Dict[str, str]) -> bool:
        """Verify webhook signature."""
        
        # This would implement platform-specific signature verification
        return True
    
    async def _generate_sarif_report(self, scan_data: Dict[str, Any], output_path: Path):
        """Generate SARIF report for CI integration."""
        
        # This would use the report generator to create SARIF format
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "NjordScan",
                            "version": "1.0.0"
                        }
                    },
                    "results": []
                }
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2)
    
    async def _generate_html_report(self, scan_data: Dict[str, Any], output_path: Path):
        """Generate HTML report for CI artifacts."""
        
        # Simple HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NjordScan CI/CD Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .summary {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
                .findings {{ margin-top: 20px; }}
            </style>
        </head>
        <body>
            <h1>NjordScan Security Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Total Findings: {scan_data.get('summary', {}).get('total_findings', 0)}</p>
                <p>Security Score: {scan_data.get('security_score', 0)}</p>
                <p>Risk Level: {scan_data.get('risk_level', 'unknown').title()}</p>
            </div>
            <div class="findings">
                <h2>Findings</h2>
                <!-- Findings would be rendered here -->
            </div>
        </body>
        </html>
        """
        
        output_path.write_text(html_content, encoding='utf-8')
    
    async def _cleanup_worker(self):
        """Background worker for cleanup tasks."""
        
        while True:
            try:
                # Clean up old scan results
                current_time = time.time()
                cutoff_time = current_time - (24 * 3600)  # 24 hours
                
                expired_results = [
                    request_id for request_id, result in self.scan_results.items()
                    if result.start_time < cutoff_time
                ]
                
                for request_id in expired_results:
                    del self.scan_results[request_id]
                
                if expired_results:
                    logger.debug(f"Cleaned up {len(expired_results)} expired scan results")
                
                # Sleep for 1 hour
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error in cleanup worker: {str(e)}")
                await asyncio.sleep(3600)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get CI/CD orchestrator statistics."""
        
        stats = dict(self.stats)
        stats['uptime'] = time.time() - self.start_time
        stats['active_scans'] = len(self.active_scans)
        stats['queued_scans'] = self.scan_queue.qsize()
        stats['cached_results'] = len(self.scan_results)
        stats['registered_platforms'] = len(self.platform_integrations)
        
        return stats
    
    async def shutdown(self):
        """Shutdown the CI/CD orchestrator."""
        
        logger.info("Shutting down CI/CD Orchestrator")
        
        # Cancel all active scans
        for task in self.active_scans.values():
            task.cancel()
        
        # Shutdown platform integrations
        for integration in self.platform_integrations.values():
            await integration.shutdown()
        
        # Shutdown quality gate engine
        await self.quality_gate_engine.shutdown()
        
        # Shutdown notification manager
        await self.notification_manager.shutdown()
        
        logger.info("CI/CD Orchestrator shutdown completed")
