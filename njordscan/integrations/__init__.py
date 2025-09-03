"""
CI/CD Integration & Automation Module for NjordScan.

This module provides comprehensive CI/CD pipeline integration including:
- GitHub Actions, GitLab CI, Jenkins, Azure DevOps integration
- Quality gates and security policies
- Automated scanning triggers
- Pull request automation
- SARIF reporting for code scanning alerts
- Slack, Teams, and email notifications
"""

from .ci_orchestrator import CIOrchestrator
from .github_integration import GitHubIntegration
from .gitlab_integration import GitLabIntegration
from .jenkins_integration import JenkinsIntegration
from .azure_devops_integration import AzureDevOpsIntegration
from .quality_gates import QualityGateEngine
from .notification_manager import NotificationManager

__all__ = [
    'CIOrchestrator',
    'GitHubIntegration',
    'GitLabIntegration',
    'JenkinsIntegration',
    'AzureDevOpsIntegration',
    'QualityGateEngine',
    'NotificationManager'
]
