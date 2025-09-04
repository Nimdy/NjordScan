"""
GitHub Actions Integration

Comprehensive GitHub integration including:
- GitHub Actions workflow generation
- Pull request automation and comments
- Security alerts and code scanning integration
- SARIF upload for GitHub Security tab
- Status checks and deployment gates
- GitHub App and webhook support
"""

import json
import time
import base64
import hmac
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import logging
import aiohttp
from pathlib import Path

from .ci_orchestrator import CIScanRequest, CIScanResult, TriggerEvent, CIPlatform, ScanScope

logger = logging.getLogger(__name__)

@dataclass
class GitHubConfiguration:
    """GitHub integration configuration."""
    
    # Authentication
    github_token: str
    app_id: Optional[int] = None
    app_private_key: Optional[str] = None
    webhook_secret: Optional[str] = None
    
    # API settings
    github_api_url: str = "https://api.github.com"
    github_upload_url: str = "https://uploads.github.com"
    
    # Integration features
    enable_pr_comments: bool = True
    enable_status_checks: bool = True
    enable_security_alerts: bool = True
    enable_sarif_upload: bool = True
    enable_deployments: bool = True
    
    # Comment settings
    comment_template: Optional[str] = None
    update_existing_comments: bool = True
    collapse_previous_comments: bool = True
    
    # Security settings
    create_security_advisories: bool = False
    auto_dismiss_alerts: bool = False
    
    # Workflow settings
    workflow_file_path: str = ".github/workflows/njordscan.yml"
    workflow_name: str = "NjordScan Security Analysis"

class GitHubIntegration:
    """GitHub Actions and API integration."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = GitHubConfiguration(**config)
        
        # HTTP session for API calls
        self.session: Optional[aiohttp.ClientSession] = None
        
        # GitHub App JWT token cache
        self.jwt_token: Optional[str] = None
        self.jwt_expires_at: float = 0
        
        # API rate limiting
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = time.time() + 3600
        
        # Comment tracking
        self.existing_comments: Dict[str, int] = {}  # pr_key -> comment_id
        
        # Statistics
        self.stats = {
            'api_calls_made': 0,
            'pr_comments_posted': 0,
            'status_checks_created': 0,
            'sarif_uploads': 0,
            'security_alerts_created': 0,
            'webhooks_processed': 0
        }
    
    async def initialize(self):
        """Initialize GitHub integration."""
        
        logger.info("Initializing GitHub integration")
        
        # Create HTTP session
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'NjordScan/1.0.0',
                'Accept': 'application/vnd.github.v3+json'
            }
        )
        
        # Test authentication
        await self._test_authentication()
        
        logger.info("GitHub integration initialized successfully")
    
    async def register_repository(self, repo_id: str, ci_config) -> bool:
        """Register repository for GitHub integration."""
        
        logger.info(f"Registering GitHub repository: {repo_id}")
        
        try:
            # Generate GitHub Actions workflow
            workflow_content = self._generate_github_workflow(ci_config)
            
            # Create or update workflow file
            success = await self._create_or_update_workflow(repo_id, workflow_content)
            
            if success:
                # Setup webhooks if configured
                if self.config.webhook_secret:
                    await self._setup_webhooks(repo_id)
                
                logger.info(f"GitHub repository registered successfully: {repo_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to register GitHub repository {repo_id}: {str(e)}")
            return False
    
    async def process_webhook(self, payload: Dict[str, Any], 
                            headers: Dict[str, str]) -> Optional[CIScanRequest]:
        """Process GitHub webhook payload."""
        
        logger.debug("Processing GitHub webhook")
        
        try:
            self.stats['webhooks_processed'] += 1
            
            # Determine event type
            event_type = headers.get('X-GitHub-Event')
            if not event_type:
                logger.warning("No event type in GitHub webhook")
                return None
            
            # Process based on event type
            if event_type == 'push':
                return await self._process_push_event(payload)
            elif event_type == 'pull_request':
                return await self._process_pull_request_event(payload)
            elif event_type == 'schedule':
                return await self._process_schedule_event(payload)
            elif event_type == 'release':
                return await self._process_release_event(payload)
            else:
                logger.debug(f"Unhandled GitHub event type: {event_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error processing GitHub webhook: {str(e)}")
            return None
    
    async def prepare_scan_environment(self, scan_request: CIScanRequest) -> Dict[str, Any]:
        """Prepare scan environment for GitHub repository."""
        
        logger.debug(f"Preparing GitHub scan environment for {scan_request.repository}")
        
        try:
            # Get repository information
            repo_info = await self._get_repository_info(scan_request.repository)
            
            # Get commit information
            commit_info = await self._get_commit_info(scan_request.repository, scan_request.commit_sha)
            
            # Get changed files for PR scans
            changed_files = []
            if scan_request.pull_request_id:
                changed_files = await self._get_pr_changed_files(
                    scan_request.repository, scan_request.pull_request_id
                )
            
            return {
                'repository': scan_request.repository,
                'branch': scan_request.branch,
                'commit_sha': scan_request.commit_sha,
                'repository_info': repo_info,
                'commit_info': commit_info,
                'changed_files': changed_files,
                'clone_url': repo_info.get('clone_url'),
                'default_branch': repo_info.get('default_branch'),
                'target_paths': changed_files if scan_request.scan_scope == ScanScope.CHANGED_FILES_ONLY else ['.']
            }
            
        except Exception as e:
            logger.error(f"Failed to prepare GitHub scan environment: {str(e)}")
            return {
                'repository': scan_request.repository,
                'branch': scan_request.branch,
                'commit_sha': scan_request.commit_sha,
                'target_paths': ['.']
            }
    
    async def post_pr_comment(self, scan_request: CIScanRequest, 
                            result: CIScanResult, scan_data: Dict[str, Any]) -> bool:
        """Post security scan results as PR comment."""
        
        if not scan_request.pull_request_id or not self.config.enable_pr_comments:
            return False
        
        logger.info(f"Posting PR comment for {scan_request.repository}#{scan_request.pull_request_id}")
        
        try:
            # Generate comment content
            comment_content = await self._generate_pr_comment(scan_request, result, scan_data)
            
            # Check for existing comment
            pr_key = f"{scan_request.repository}#{scan_request.pull_request_id}"
            existing_comment_id = self.existing_comments.get(pr_key)
            
            if existing_comment_id and self.config.update_existing_comments:
                # Update existing comment
                success = await self._update_pr_comment(
                    scan_request.repository, existing_comment_id, comment_content
                )
            else:
                # Create new comment
                comment_id = await self._create_pr_comment(
                    scan_request.repository, scan_request.pull_request_id, comment_content
                )
                success = comment_id is not None
                
                if success:
                    self.existing_comments[pr_key] = comment_id
                    
                    # Collapse previous comments if configured
                    if self.config.collapse_previous_comments:
                        await self._collapse_previous_comments(scan_request.repository, scan_request.pull_request_id)
            
            if success:
                self.stats['pr_comments_posted'] += 1
                logger.info(f"PR comment posted successfully for {pr_key}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to post PR comment: {str(e)}")
            return False
    
    async def create_status_check(self, scan_request: CIScanRequest, 
                                result: CIScanResult) -> bool:
        """Create GitHub status check for scan result."""
        
        if not self.config.enable_status_checks:
            return False
        
        logger.debug(f"Creating GitHub status check for {scan_request.repository}@{scan_request.commit_sha}")
        
        try:
            # Determine status
            if result.scan_success and result.quality_gate_passed:
                state = "success"
                description = f"Security scan passed ({result.total_findings} findings)"
            elif result.scan_success and not result.quality_gate_passed:
                state = "failure"
                description = f"Quality gate failed ({result.critical_findings} critical, {result.high_findings} high)"
            else:
                state = "error"
                description = "Security scan failed"
            
            # Create status check
            status_data = {
                "state": state,
                "target_url": self._get_report_url(result),
                "description": description,
                "context": "security/njordscan"
            }
            
            success = await self._create_commit_status(
                scan_request.repository, scan_request.commit_sha, status_data
            )
            
            if success:
                self.stats['status_checks_created'] += 1
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to create status check: {str(e)}")
            return False
    
    async def upload_sarif(self, scan_request: CIScanRequest, 
                         result: CIScanResult, sarif_path: str) -> bool:
        """Upload SARIF results to GitHub Code Scanning."""
        
        if not self.config.enable_sarif_upload or not result.sarif_report_path:
            return False
        
        logger.info(f"Uploading SARIF to GitHub Code Scanning for {scan_request.repository}")
        
        try:
            # Read SARIF file
            with open(result.sarif_report_path, 'r', encoding='utf-8') as f:
                sarif_content = f.read()
            
            # Encode SARIF content
            sarif_b64 = base64.b64encode(sarif_content.encode()).decode()
            
            # Upload SARIF
            upload_data = {
                "commit_sha": scan_request.commit_sha,
                "ref": f"refs/heads/{scan_request.branch}",
                "sarif": sarif_b64,
                "checkout_uri": f"https://github.com/{scan_request.repository}",
                "started_at": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(result.start_time)),
                "tool_name": "NjordScan"
            }
            
            success = await self._upload_sarif_data(scan_request.repository, upload_data)
            
            if success:
                self.stats['sarif_uploads'] += 1
                logger.info(f"SARIF uploaded successfully for {scan_request.repository}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to upload SARIF: {str(e)}")
            return False
    
    async def create_security_alerts(self, scan_request: CIScanRequest, 
                                   result: CIScanResult, scan_data: Dict[str, Any]) -> bool:
        """Create GitHub security alerts for critical findings."""
        
        if not self.config.enable_security_alerts:
            return False
        
        # Only create alerts for critical findings
        critical_findings = [
            f for f in scan_data.get('findings', [])
            if f.get('severity') == 'critical'
        ]
        
        if not critical_findings:
            return True
        
        logger.info(f"Creating {len(critical_findings)} security alerts for {scan_request.repository}")
        
        try:
            alerts_created = 0
            
            for finding in critical_findings[:10]:  # Limit to prevent spam
                alert_created = await self._create_security_alert(scan_request.repository, finding)
                if alert_created:
                    alerts_created += 1
            
            if alerts_created > 0:
                self.stats['security_alerts_created'] += alerts_created
                logger.info(f"Created {alerts_created} security alerts for {scan_request.repository}")
            
            return alerts_created > 0
            
        except Exception as e:
            logger.error(f"Failed to create security alerts: {str(e)}")
            return False
    
    # Private methods
    
    async def _test_authentication(self):
        """Test GitHub API authentication."""
        
        try:
            headers = await self._get_auth_headers()
            
            async with self.session.get(
                f"{self.config.github_api_url}/user",
                headers=headers
            ) as response:
                if response.status == 200:
                    user_data = await response.json()
                    logger.info(f"GitHub authentication successful for user: {user_data.get('login')}")
                else:
                    logger.error(f"GitHub authentication failed: {response.status}")
                    raise Exception(f"GitHub auth failed with status {response.status}")
                    
        except Exception as e:
            logger.error(f"GitHub authentication test failed: {str(e)}")
            raise
    
    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for GitHub API."""
        
        headers = {
            'Authorization': f'token {self.config.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        return headers
    
    def _generate_github_workflow(self, ci_config) -> str:
        """Generate GitHub Actions workflow YAML."""
        
        workflow_yaml = f'''
name: {self.config.workflow_name}

on:
  push:
    branches: {ci_config.branch_patterns}
  pull_request:
    branches: {ci_config.branch_patterns}
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday at 2 AM

jobs:
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install NjordScan
        run: |
          pip install njordscan
      
      - name: Run Security Scan
        run: |
          njordscan scan . \\
            --format sarif \\
            --output-file results.sarif \\
            --timeout {ci_config.timeout_minutes} \\
            {'--fail-on-critical' if ci_config.fail_on_critical else ''} \\
            {'--fail-on-high' if ci_config.fail_on_high else ''}
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
      
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: njordscan-results
          path: |
            results.sarif
            *.html
            *.json
'''
        
        return workflow_yaml.strip()
    
    async def _create_or_update_workflow(self, repo_id: str, workflow_content: str) -> bool:
        """Create or update GitHub Actions workflow file."""
        
        try:
            headers = await self._get_auth_headers()
            
            # Check if workflow file exists
            workflow_url = f"{self.config.github_api_url}/repos/{repo_id}/contents/{self.config.workflow_file_path}"
            
            async with self.session.get(workflow_url, headers=headers) as response:
                if response.status == 200:
                    # File exists, update it
                    existing_file = await response.json()
                    
                    update_data = {
                        "message": "Update NjordScan workflow",
                        "content": base64.b64encode(workflow_content.encode()).decode(),
                        "sha": existing_file["sha"]
                    }
                    
                    async with self.session.put(workflow_url, headers=headers, json=update_data) as update_response:
                        return update_response.status == 200
                        
                elif response.status == 404:
                    # File doesn't exist, create it
                    create_data = {
                        "message": "Add NjordScan workflow",
                        "content": base64.b64encode(workflow_content.encode()).decode()
                    }
                    
                    async with self.session.put(workflow_url, headers=headers, json=create_data) as create_response:
                        return create_response.status == 201
                        
                else:
                    logger.error(f"Unexpected response when checking workflow file: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to create/update workflow: {str(e)}")
            return False
    
    async def _process_push_event(self, payload: Dict[str, Any]) -> Optional[CIScanRequest]:
        """Process GitHub push event."""
        
        repository = payload.get('repository', {}).get('full_name')
        ref = payload.get('ref', '')
        
        if not ref.startswith('refs/heads/'):
            return None
        
        branch = ref.replace('refs/heads/', '')
        commit_sha = payload.get('after')
        
        if not repository or not branch or not commit_sha:
            return None
        
        return CIScanRequest(
            request_id=f"github_push_{repository}_{commit_sha}_{int(time.time())}",
            platform=CIPlatform.GITHUB_ACTIONS,
            repository=repository,
            branch=branch,
            commit_sha=commit_sha,
            trigger_event=TriggerEvent.PUSH,
            triggered_by=payload.get('pusher', {}).get('name', 'unknown'),
            trigger_timestamp=time.time(),
            scan_scope=ScanScope.FULL_SCAN
        )
    
    async def _process_pull_request_event(self, payload: Dict[str, Any]) -> Optional[CIScanRequest]:
        """Process GitHub pull request event."""
        
        action = payload.get('action')
        if action not in ['opened', 'synchronize', 'reopened']:
            return None
        
        pr = payload.get('pull_request', {})
        repository = payload.get('repository', {}).get('full_name')
        
        if not pr or not repository:
            return None
        
        return CIScanRequest(
            request_id=f"github_pr_{repository}_{pr.get('number')}_{int(time.time())}",
            platform=CIPlatform.GITHUB_ACTIONS,
            repository=repository,
            branch=pr.get('head', {}).get('ref'),
            commit_sha=pr.get('head', {}).get('sha'),
            trigger_event=TriggerEvent.PULL_REQUEST,
            triggered_by=pr.get('user', {}).get('login', 'unknown'),
            trigger_timestamp=time.time(),
            scan_scope=ScanScope.CHANGED_FILES_ONLY,
            pull_request_id=pr.get('number'),
            base_branch=pr.get('base', {}).get('ref')
        )
    
    async def _get_repository_info(self, repo_id: str) -> Dict[str, Any]:
        """Get repository information from GitHub API."""
        
        try:
            headers = await self._get_auth_headers()
            
            async with self.session.get(
                f"{self.config.github_api_url}/repos/{repo_id}",
                headers=headers
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.warning(f"Failed to get repository info: {response.status}")
                    return {}
                    
        except Exception as e:
            logger.error(f"Error getting repository info: {str(e)}")
            return {}
    
    async def _generate_pr_comment(self, scan_request: CIScanRequest, 
                                 result: CIScanResult, scan_data: Dict[str, Any]) -> str:
        """Generate PR comment content."""
        
        # Use custom template if provided
        if self.config.comment_template:
            # Would implement template rendering
            pass
        
        # Generate default comment
        status_emoji = "✅" if result.quality_gate_passed else "❌"
        risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(result.risk_level, "⚪")
        
        comment = f"""## {status_emoji} NjordScan Security Analysis

**Security Score:** {result.security_score:.1f}/100 {risk_emoji}
**Quality Gate:** {'PASSED' if result.quality_gate_passed else 'FAILED'}

### 📊 Summary
| Severity | Count |
|----------|-------|
| Critical | {result.critical_findings} |
| High | {result.high_findings} |
| Medium | {result.medium_findings} |
| Low | {result.low_findings} |
| Info | {result.info_findings} |
| **Total** | **{result.total_findings}** |

"""
        
        # Add new findings if this is a PR
        if result.new_findings > 0:
            comment += f"### 🆕 New Issues: {result.new_findings}\n"
        
        if result.fixed_findings > 0:
            comment += f"### ✅ Fixed Issues: {result.fixed_findings}\n"
        
        # Add links to reports
        if result.html_report_path:
            comment += f"\n📋 [View Detailed Report]({self._get_report_url(result)})\n"
        
        comment += f"\n---\n*Scan completed in {result.duration:.1f}s*"
        
        return comment
    
    async def _create_pr_comment(self, repo_id: str, pr_number: int, content: str) -> Optional[int]:
        """Create PR comment."""
        
        try:
            headers = await self._get_auth_headers()
            
            comment_data = {"body": content}
            
            async with self.session.post(
                f"{self.config.github_api_url}/repos/{repo_id}/issues/{pr_number}/comments",
                headers=headers,
                json=comment_data
            ) as response:
                if response.status == 201:
                    comment = await response.json()
                    return comment.get('id')
                else:
                    logger.error(f"Failed to create PR comment: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error creating PR comment: {str(e)}")
            return None
    
    def _get_report_url(self, result: CIScanResult) -> str:
        """Get URL for HTML report."""
        
        # This would return the actual URL where reports are hosted
        return f"https://reports.njordscan.com/scan/{result.scan_id}"
    
    async def _upload_sarif_data(self, repo_id: str, sarif_data: Dict[str, Any]) -> bool:
        """Upload SARIF data to GitHub Code Scanning."""
        
        try:
            headers = await self._get_auth_headers()
            headers['Accept'] = 'application/vnd.github.v3+json'
            
            async with self.session.post(
                f"{self.config.github_api_url}/repos/{repo_id}/code-scanning/sarifs",
                headers=headers,
                json=sarif_data
            ) as response:
                return response.status == 202
                
        except Exception as e:
            logger.error(f"Error uploading SARIF: {str(e)}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get GitHub integration statistics."""
        
        return dict(self.stats)
    
    async def shutdown(self):
        """Shutdown GitHub integration."""
        
        logger.info("Shutting down GitHub integration")
        
        if self.session:
            await self.session.close()
        
        logger.info("GitHub integration shutdown completed")
