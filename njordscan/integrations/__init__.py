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
# from .gitlab_integration import GitLabIntegration  # Module not implemented yet
# from .jenkins_integration import JenkinsIntegration  # Module not implemented yet
# from .azure_devops_integration import AzureDevOpsIntegration  # Module not implemented yet
from .quality_gates import QualityGateEngine
# from .notification_manager import NotificationManager  # Module not implemented yet

__all__ = [
    'CIOrchestrator',
    'GitHubIntegration',
    # 'GitLabIntegration',  # Module not implemented yet
    # 'JenkinsIntegration',  # Module not implemented yet
    # 'AzureDevOpsIntegration',  # Module not implemented yet
    'QualityGateEngine',
    # 'NotificationManager'  # Module not implemented yet
]
