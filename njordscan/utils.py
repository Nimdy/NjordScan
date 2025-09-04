"""
🛡️ Enhanced Utility Functions for NjordScan v1.0.0

Core utility functions with enhanced framework detection, scoring,
and integration with advanced orchestrators.
"""

import os
import json
import requests
import hashlib
from pathlib import Path
from typing import Tuple, Optional, List, Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from .vulnerability import Vulnerability, Severity

def validate_target(target: str) -> Tuple[bool, str]:
    """Validate if target is a valid URL or directory path."""
    if target.startswith(('http://', 'https://')):
        # URL validation
        try:
            response = requests.head(target, timeout=5)
            return True, f"Valid URL (Status: {response.status_code})"
        except requests.RequestException as e:
            return False, f"URL not accessible: {str(e)}"
    else:
        # Directory validation
        path = Path(target)
        if path.exists() and path.is_dir():
            return True, f"Valid directory: {path.absolute()}"
        else:
            return False, f"Directory not found: {path.absolute()}"

def detect_framework(target: str) -> str:
    """Detect the framework used in the target."""
    if target.startswith(('http://', 'https://')):
        return detect_framework_from_url(target)
    else:
        return detect_framework_from_directory(target)

def detect_framework_from_directory(directory: str) -> str:
    """Detect framework from directory structure."""
    path = Path(directory)
    
    # Check for Next.js
    if (path / "next.config.js").exists() or (path / "next.config.ts").exists():
        return "nextjs"
    
    # Check for package.json
    package_json = path / "package.json"
    if package_json.exists():
        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
                dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                
                if 'next' in dependencies:
                    return "nextjs"
                elif 'vite' in dependencies:
                    return "vite"
                elif 'react' in dependencies:
                    return "react"
        except (json.JSONDecodeError, KeyError):
            pass
    
    # Check for Vite config
    if (path / "vite.config.js").exists() or (path / "vite.config.ts").exists():
        return "vite"
    
    return "unknown"

def detect_framework_from_url(url: str) -> str:
    """Detect framework from URL responses."""
    try:
        response = requests.get(url, timeout=10)
        html_content = response.text.lower()
        
        # Check for Next.js indicators
        if '_next/' in html_content or 'next.js' in html_content:
            return "nextjs"
        
        # Check for Vite indicators
        if 'vite' in html_content or '@vite' in html_content:
            return "vite"
        
        # Check for React indicators
        if 'react' in html_content or 'reactdom' in html_content:
            return "react"
        
    except requests.RequestException:
        pass
    
    return "unknown"

def display_banner(console: Console):
    """Display enhanced NjordScan banner."""
    banner_text = Text()
    banner_text.append("╔═══════════════════════════════════════════════════════════╗\n", style="cyan")
    banner_text.append("║                                                           ║\n", style="cyan")
    banner_text.append("║  ", style="cyan")
    banner_text.append("███╗   ██╗     ██╗ ██████╗ ██████╗ ██████╗ ███████╗", style="bold blue")
    banner_text.append("  ║\n", style="cyan")
    banner_text.append("║  ", style="cyan")
    banner_text.append("████╗  ██║     ██║██╔═══██╗██╔══██╗██╔══██╗██╔════╝", style="bold blue")
    banner_text.append("  ║\n", style="cyan")
    banner_text.append("║  ", style="cyan")
    banner_text.append("██╔██╗ ██║     ██║██║   ██║██████╔╝██║  ██║███████╗", style="bold blue")
    banner_text.append("  ║\n", style="cyan")
    banner_text.append("║  ", style="cyan")
    banner_text.append("██║╚██╗██║██   ██║██║   ██║██╔══██╗██║  ██║╚════██║", style="bold blue")
    banner_text.append("  ║\n", style="cyan")
    banner_text.append("║  ", style="cyan")
    banner_text.append("██║ ╚████║╚█████╔╝╚██████╔╝██║  ██║██████╔╝███████║", style="bold blue")
    banner_text.append("  ║\n", style="cyan")
    banner_text.append("║  ", style="cyan")
    banner_text.append("╚═╝  ╚═══╝ ╚════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝", style="bold blue")
    banner_text.append("  ║\n", style="cyan")
    banner_text.append("║                                                           ║\n", style="cyan")
    banner_text.append("║        Professional Security Scanner for Modern Web      ║\n", style="cyan")
    banner_text.append("║              Next.js • React • Vite                      ║\n", style="cyan")
    banner_text.append("║                                                           ║\n", style="cyan")
    banner_text.append("╚═══════════════════════════════════════════════════════════╝", style="cyan")
    
    console.print(banner_text)
    console.print()

def explain_vulnerability(vuln_type: str, console: Console):
    """Enhanced vulnerability explanation system."""
    explanations = {
        'xss': {
            'title': 'Cross-Site Scripting (XSS)',
            'description': 'XSS vulnerabilities occur when user input is not properly sanitized before being rendered in the browser.',
            'severity': 'High',
            'examples': [
                'dangerouslySetInnerHTML in React without sanitization',
                'Unescaped template variables in dynamic content',
                'Direct DOM manipulation with user input'
            ],
            'fixes': [
                'Use proper React JSX escaping (automatic in most cases)',
                'Implement Content Security Policy (CSP) headers',
                'Sanitize user input with libraries like DOMPurify',
                'Avoid dangerouslySetInnerHTML when possible',
                'Use textContent instead of innerHTML for text'
            ],
            'references': [
                'https://owasp.org/www-community/attacks/xss/',
                'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'
            ]
        },
        'ssrf': {
            'title': 'Server-Side Request Forgery (SSRF)',
            'description': 'SSRF vulnerabilities allow attackers to make requests from the server to unintended destinations.',
            'severity': 'High',
            'examples': [
                'Unvalidated URLs in Next.js image optimization',
                'User-controlled proxy configurations in Vite',
                'API routes making external requests with user input'
            ],
            'fixes': [
                'Validate and whitelist allowed URLs and domains',
                'Use proper proxy configurations with restricted access',
                'Implement network-level restrictions',
                'Monitor and log outbound requests',
                'Use URL parsing libraries to validate destinations'
            ],
            'references': [
                'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
                'https://portswigger.net/web-security/ssrf'
            ]
        },
        'secrets': {
            'title': 'Hardcoded Secrets',
            'description': 'Secrets hardcoded in source code can be exposed to attackers with access to the codebase.',
            'severity': 'Critical',
            'examples': [
                'API keys in NEXT_PUBLIC_ environment variables',
                'Database credentials in configuration files',
                'JWT secrets in source code'
            ],
            'fixes': [
                'Use environment variables for sensitive data',
                'Implement proper secret management (AWS Secrets Manager, etc.)',
                'Remove secrets from version control history',
                'Use .env files with proper .gitignore rules',
                'Rotate exposed secrets immediately'
            ],
            'references': [
                'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials',
                'https://docs.github.com/en/code-security/secret-scanning'
            ]
        }
    }
    
    if vuln_type.lower() in explanations:
        vuln_info = explanations[vuln_type.lower()]
        
        # Create detailed explanation
        content = Text()
        content.append(f"{vuln_info['description']}\n\n", style="white")
        content.append(f"Severity: {vuln_info['severity']}\n\n", style="bold red")
        
        content.append("Common Examples:\n", style="bold yellow")
        for example in vuln_info['examples']:
            content.append(f"• {example}\n", style="yellow")
        
        content.append("\nHow to Fix:\n", style="bold green")
        for fix in vuln_info['fixes']:
            content.append(f"• {fix}\n", style="green")
        
        content.append("\nReferences:\n", style="bold blue")
        for ref in vuln_info['references']:
            content.append(f"• {ref}\n", style="blue")
        
        panel = Panel(content, title=vuln_info['title'], border_style="blue")
        console.print(panel)
    else:
        console.print(f"[red]Unknown vulnerability type: {vuln_type}[/red]")
        console.print("[yellow]Available types: xss, ssrf, secrets[/yellow]")

class NjordScore:
    """Enhanced NjordScore calculation system."""
    
    def calculate_score(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Calculate security score based on findings."""
        if not vulnerabilities:
            return self._perfect_score()
        
        # Weight vulnerabilities by severity
        severity_weights = {
            Severity.CRITICAL: 50,
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 1
        }
        
        total_deduction = sum(severity_weights.get(vuln.severity, 5) for vuln in vulnerabilities)
        score = max(0, 100 - total_deduction)
        
        return {
            'score': score,
            'grade': self._calculate_grade(score),
            'total_issues': len(vulnerabilities),
            'severity_breakdown': self._get_severity_breakdown(vulnerabilities),
            'recommendation': self._get_recommendation(score),
            'next_steps': self._get_next_steps(vulnerabilities)
        }
    
    def _perfect_score(self) -> Dict[str, Any]:
        """Return perfect score when no vulnerabilities found."""
        return {
            'score': 100,
            'grade': 'A+',
            'total_issues': 0,
            'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'recommendation': 'Excellent security posture! Keep up the good work.',
            'next_steps': ['Continue regular security scanning', 'Stay updated with latest security practices']
        }
    
    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade from score."""
        if score >= 95: return "A+"
        elif score >= 90: return "A"
        elif score >= 85: return "B+"
        elif score >= 80: return "B"
        elif score >= 70: return "C"
        elif score >= 60: return "D"
        else: return "F"
    
    def _get_severity_breakdown(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by severity."""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    def _get_recommendation(self, score: int) -> str:
        """Get recommendation based on score."""
        if score >= 95:
            return "Excellent security posture! Keep up the good work."
        elif score >= 85:
            return "Good security posture with minor improvements needed."
        elif score >= 75:
            return "Moderate security posture. Address identified issues."
        elif score >= 65:
            return "Security improvements needed. Review all findings."
        else:
            return "Critical security issues found. Immediate action required."
    
    def _get_next_steps(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Get next steps based on vulnerabilities found."""
        if not vulnerabilities:
            return ['Continue regular security scanning', 'Stay updated with latest security practices']
        
        steps = []
        critical_count = sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL)
        high_count = sum(1 for v in vulnerabilities if v.severity == Severity.HIGH)
        
        if critical_count > 0:
            steps.append(f"URGENT: Fix {critical_count} critical vulnerabilities immediately")
        
        if high_count > 0:
            steps.append(f"Fix {high_count} high-severity vulnerabilities within 24 hours")
        
        steps.extend([
            "Review all security findings in detail",
            "Implement recommended fixes",
            "Re-scan after fixes to verify resolution",
            "Consider security training for the development team"
        ])
        
        return steps