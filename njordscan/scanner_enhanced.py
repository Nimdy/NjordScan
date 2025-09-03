#!/usr/bin/env python3
"""
🚀 Enhanced NjordScan Scanner
Integrates advanced vulnerability detection, false positive filtering, custom rules, and trend analysis.
"""

import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

from .modules.vulnerability_detector import VulnerabilityDetector
from .modules.headers import HeadersModule
from .modules.runtime import RuntimeModule
from .intelligence.false_positive_filter import FalsePositiveFilter, FalsePositiveConfig
from .rules.custom_rules import CustomRuleManager
from .analytics.trend_analyzer import TrendAnalyzer
from .vulnerability import Vulnerability
from .config import Config

class EnhancedScanner:
    """Enhanced security scanner with advanced features."""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)
        
        # Create vulnerability ID generator
        from .vulnerability import VulnerabilityIdGenerator
        vuln_id_generator = VulnerabilityIdGenerator()
        
        # Initialize advanced modules
        self.vulnerability_detector = VulnerabilityDetector(self.config, vuln_id_generator)
        self.headers_module = HeadersModule(self.config, vuln_id_generator)
        self.runtime_module = RuntimeModule(self.config, vuln_id_generator)
        self.false_positive_filter = FalsePositiveFilter()
        self.custom_rule_manager = CustomRuleManager()
        self.trend_analyzer = TrendAnalyzer()
        
        # Scan results storage
        self.scan_results = {}
        self.current_scan_id = None

    async def scan_target(self, target: str, mode: str = 'standard', 
                         options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform a comprehensive security scan."""
        if options is None:
            options = {}
            
        # Generate scan ID
        self.current_scan_id = f"enhanced_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.logger.info(f"Starting enhanced scan {self.current_scan_id} on {target}")
        
        try:
            # Initialize results
            scan_results = {
                'scan_id': self.current_scan_id,
                'target': target,
                'mode': mode,
                'options': options,
                'start_time': datetime.now().isoformat(),
                'vulnerabilities': [],
                'summary': {},
                'trends': {},
                'false_positives': [],
                'custom_rule_matches': []
            }
            
            # Determine target type and scan accordingly
            if self._is_url(target):
                vulnerabilities = await self._scan_url(target, mode, options)
            else:
                vulnerabilities = await self._scan_directory(target, mode, options)
            
            # Apply false positive filtering
            if options.get('enable_filtering', False):  # Disabled by default
                true_positives, false_positives = self.false_positive_filter.filter_vulnerabilities(vulnerabilities)
                scan_results['vulnerabilities'] = [v.to_dict() for v in true_positives]
                scan_results['false_positives'] = [v.to_dict() for v in false_positives]
            else:
                scan_results['vulnerabilities'] = [v.to_dict() for v in vulnerabilities]
            
            # Generate summary
            scan_results['summary'] = self._generate_scan_summary(scan_results)
            
            # Record for trend analysis
            if options.get('enable_trends', True):
                self.trend_analyzer.record_scan_results(
                    self.current_scan_id, target, mode, vulnerabilities
                )
                scan_results['trends'] = self._get_trend_insights()
            
            # Store results
            self.scan_results[self.current_scan_id] = scan_results
            
            scan_results['end_time'] = datetime.now().isoformat()
            scan_results['duration'] = self._calculate_duration(
                scan_results['start_time'], scan_results['end_time']
            )
            
            self.logger.info(f"Enhanced scan {self.current_scan_id} completed successfully")
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Error during enhanced scan: {e}")
            return {
                'scan_id': self.current_scan_id,
                'target': target,
                'mode': mode,
                'error': str(e),
                'success': False
            }

    async def _scan_url(self, url: str, mode: str, options: Dict[str, Any]) -> List[Vulnerability]:
        """Scan a URL for vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Headers security scan
            if mode in ['standard', 'deep', 'enterprise']:
                headers_vulns = await self.headers_module.scan(url)
                vulnerabilities.extend(headers_vulns)
            
            # Runtime security testing
            if mode in ['standard', 'deep', 'enterprise']:
                runtime_vulns = await self.runtime_module.scan(url)
                vulnerabilities.extend(runtime_vulns)
            
            # Advanced vulnerability detection
            if mode in ['deep', 'enterprise']:
                detector_vulns = self.vulnerability_detector.scan_url(url)
                vulnerabilities.extend(detector_vulns)
            
            # Custom rules for URLs
            if options.get('enable_custom_rules', True):
                custom_vulns = self._apply_custom_rules_to_url(url)
                vulnerabilities.extend(custom_vulns)
                
        except Exception as e:
            self.logger.error(f"Error scanning URL {url}: {e}")
            
        return vulnerabilities

    async def _scan_directory(self, directory: str, mode: str, options: Dict[str, Any]) -> List[Vulnerability]:
        """Scan a directory for vulnerabilities."""
        vulnerabilities = []
        target_path = Path(directory)
        
        if not target_path.exists():
            self.logger.error(f"Target directory does not exist: {directory}")
            return vulnerabilities
            
        try:
            # Get file list based on mode
            files_to_scan = self._get_files_to_scan(target_path, mode, options)
            
            for file_path in files_to_scan:
                try:
                    # Basic vulnerability detection
                    file_vulns = self.vulnerability_detector.scan_file(file_path)
                    vulnerabilities.extend(file_vulns)
                    
                    # Custom rules
                    if options.get('enable_custom_rules', True):
                        custom_vulns = self.custom_rule_manager.scan_file_with_custom_rules(file_path)
                        vulnerabilities.extend(custom_vulns)
                        
                except Exception as e:
                    self.logger.error(f"Error scanning file {file_path}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
            
        return vulnerabilities

    def _get_files_to_scan(self, target_path: Path, mode: str, options: Dict[str, Any]) -> List[Path]:
        """Get list of files to scan based on mode and options."""
        files_to_scan = []
        
        # File extensions to scan
        extensions = {
            'quick': ['.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.java'],
            'standard': ['.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.java', '.html', '.css'],
            'deep': ['.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.java', '.html', '.css', 
                    '.xml', '.json', '.yaml', '.yml', '.conf', '.config'],
            'enterprise': ['.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.java', '.html', '.css',
                          '.xml', '.json', '.yaml', '.yml', '.conf', '.config', '.sql', '.sh', '.bat']
        }
        
        target_extensions = extensions.get(mode, extensions['standard'])
        
        # Scan files
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in target_extensions:
                # Skip certain directories
                if any(skip_dir in str(file_path) for skip_dir in ['node_modules', '.git', '__pycache__', '.venv']):
                    continue
                    
                files_to_scan.append(file_path)
                
                # Limit files for quick mode
                if mode == 'quick' and len(files_to_scan) >= 100:
                    break
                    
        return files_to_scan

    def _apply_custom_rules_to_url(self, url: str) -> List[Vulnerability]:
        """Apply custom rules to URL scanning."""
        vulnerabilities = []
        
        try:
            # Get enabled custom rules
            enabled_rules = self.custom_rule_manager.get_enabled_rules()
            
            for rule in enabled_rules:
                # Check if rule applies to URLs
                if 'url' in rule.tags or 'web' in rule.tags:
                    # Simple URL pattern matching
                    for pattern in rule.patterns:
                        if pattern in url:
                            vulnerability = Vulnerability(
                                title=f"Custom Rule: {rule.name}",
                                description=rule.description,
                                severity=rule.severity,
                                vuln_type=rule.vuln_type,
                                location=url,
                                fix=rule.fix_guide,
                                reference=rule.reference
                            )
                            vulnerabilities.append(vulnerability)
                            
        except Exception as e:
            self.logger.error(f"Error applying custom rules to URL: {e}")
            
        return vulnerabilities

    def _generate_scan_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive scan summary."""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        false_positives = scan_results.get('false_positives', [])
        
        # Count by severity
        severity_counts = {}
        vuln_type_counts = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown') if isinstance(vuln, dict) else vuln.severity
            vuln_type = vuln.get('vuln_type', 'unknown') if isinstance(vuln, dict) else vuln.vuln_type
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1
        
        # Calculate security score
        total_issues = len(vulnerabilities)
        high_severity = severity_counts.get('high', 0)
        medium_severity = severity_counts.get('medium', 0)
        
        # Base score: 100 - (high * 20) - (medium * 10) - (low * 5)
        security_score = max(0, 100 - (high_severity * 20) - (medium_severity * 10) - (severity_counts.get('low', 0) * 5))
        
        # Determine risk level
        if security_score >= 80:
            risk_level = 'Low'
        elif security_score >= 60:
            risk_level = 'Medium'
        elif security_score >= 40:
            risk_level = 'High'
        else:
            risk_level = 'Critical'
        
        return {
            'total_vulnerabilities': total_issues,
            'false_positives': len(false_positives),
            'security_score': security_score,
            'risk_level': risk_level,
            'severity_distribution': severity_counts,
            'vulnerability_types': vuln_type_counts,
            'scan_coverage': self._calculate_scan_coverage(scan_results),
            'recommendations': self._generate_recommendations(scan_results)
        }

    def _calculate_scan_coverage(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate scan coverage metrics."""
        target = scan_results.get('target', '')
        mode = scan_results.get('mode', 'standard')
        
        coverage = {
            'target_type': 'url' if self._is_url(target) else 'directory',
            'scan_mode': mode,
            'scan_depth': self._get_scan_depth(mode),
            'modules_used': self._get_modules_used(mode),
            'custom_rules_enabled': scan_results.get('options', {}).get('enable_custom_rules', True),
            'false_positive_filtering': scan_results.get('options', {}).get('enable_filtering', True),
            'trend_analysis': scan_results.get('options', {}).get('enable_trends', True)
        }
        
        return coverage

    def _get_scan_depth(self, mode: str) -> str:
        """Get scan depth description."""
        depths = {
            'quick': 'Basic - Essential security checks only',
            'standard': 'Standard - Comprehensive security analysis',
            'deep': 'Deep - Thorough examination with advanced detection',
            'enterprise': 'Enterprise - Maximum coverage and analysis'
        }
        return depths.get(mode, 'Unknown')

    def _get_modules_used(self, mode: str) -> List[str]:
        """Get list of modules used for the scan mode."""
        modules = ['VulnerabilityDetector', 'HeadersModule', 'FalsePositiveFilter', 'CustomRuleManager']
        
        if mode in ['deep', 'enterprise']:
            modules.append('TrendAnalyzer')
            
        return modules

    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate actionable security recommendations."""
        recommendations = []
        summary = scan_results.get('summary', {})
        
        # Security score recommendations
        security_score = summary.get('security_score', 100)
        if security_score < 50:
            recommendations.append("🚨 Critical security issues detected. Immediate action required.")
        elif security_score < 70:
            recommendations.append("⚠️ Significant security vulnerabilities found. Prioritize fixes.")
        elif security_score < 85:
            recommendations.append("🔍 Some security issues detected. Review and address promptly.")
        else:
            recommendations.append("✅ Good security posture. Continue monitoring and best practices.")
        
        # Severity-based recommendations
        high_severity = summary.get('severity_distribution', {}).get('high', 0)
        if high_severity > 0:
            recommendations.append(f"🔥 {high_severity} high-severity vulnerabilities require immediate attention.")
        
        # False positive recommendations
        false_positives = summary.get('false_positives', 0)
        if false_positives > 0:
            recommendations.append(f"🔍 {false_positives} potential false positives identified. Review and adjust rules if needed.")
        
        # Trend-based recommendations
        trends = scan_results.get('trends', {})
        if trends.get('trend_direction') == 'worsening':
            recommendations.append("📈 Security posture is declining. Review recent changes and implement additional measures.")
        
        # General recommendations
        recommendations.extend([
            "📚 Review OWASP Top 10 for comprehensive security guidance",
            "🔄 Implement regular security scanning in your development workflow",
            "🔧 Consider using custom rules for project-specific security requirements",
            "📊 Monitor trends to track security improvements over time"
        ])
        
        return recommendations

    def _get_trend_insights(self) -> Dict[str, Any]:
        """Get trend analysis insights."""
        try:
            # Get 30-day trend analysis
            analysis = self.trend_analyzer.analyze_trends(30)
            
            return {
                'trend_direction': analysis.summary.get('trend_direction', 'stable'),
                'change_percentage': analysis.summary.get('change_percentage', 0),
                'total_scans': analysis.summary.get('total_scans', 0),
                'avg_vulns_per_scan': analysis.summary.get('avg_vulns_per_scan', 0),
                'recommendations': analysis.recommendations[:3]  # Top 3 recommendations
            }
        except Exception as e:
            self.logger.error(f"Error getting trend insights: {e}")
            return {}

    def _calculate_duration(self, start_time: str, end_time: str) -> str:
        """Calculate scan duration."""
        try:
            start = datetime.fromisoformat(start_time)
            end = datetime.fromisoformat(end_time)
            duration = end - start
            
            if duration.total_seconds() < 60:
                return f"{duration.total_seconds():.1f} seconds"
            elif duration.total_seconds() < 3600:
                return f"{duration.total_seconds() / 60:.1f} minutes"
            else:
                return f"{duration.total_seconds() / 3600:.1f} hours"
        except:
            return "Unknown"

    def _is_url(self, target: str) -> bool:
        """Check if target is a URL."""
        return target.startswith(('http://', 'https://', 'ftp://'))

    def get_scan_results(self, scan_id: str = None) -> Optional[Dict[str, Any]]:
        """Get scan results by ID or current scan."""
        if scan_id is None:
            scan_id = self.current_scan_id
            
        return self.scan_results.get(scan_id)

    def get_all_scan_results(self) -> Dict[str, Any]:
        """Get all scan results."""
        return self.scan_results

    def export_scan_results(self, scan_id: str, output_path: Path, format: str = 'json') -> bool:
        """Export scan results to file."""
        try:
            scan_results = self.get_scan_results(scan_id)
            if not scan_results:
                return False
                
            if format.lower() == 'json':
                with open(output_path, 'w') as f:
                    json.dump(scan_results, f, indent=2)
            else:
                # Add support for other formats
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting scan results: {e}")
            return False

    def generate_trend_report(self, days: int = 30, output_path: Path = None) -> str:
        """Generate trend analysis report."""
        try:
            return self.trend_analyzer.generate_trend_report(days, output_path)
        except Exception as e:
            self.logger.error(f"Error generating trend report: {e}")
            return f"Error generating report: {e}"

    def get_custom_rules(self) -> List[Any]:
        """Get all custom rules."""
        return self.custom_rule_manager.get_all_rules()

    def create_custom_rule(self, rule_data: Dict[str, Any]) -> bool:
        """Create a new custom rule."""
        try:
            from .rules.custom_rules import CustomRule
            rule = CustomRule(**rule_data)
            return self.custom_rule_manager.create_rule(rule)
        except Exception as e:
            self.logger.error(f"Error creating custom rule: {e}")
            return False

    def get_false_positive_stats(self) -> Dict[str, Any]:
        """Get false positive filtering statistics."""
        return self.false_positive_filter.get_filtering_statistics()

    def train_filter(self, vuln: Vulnerability, is_false_positive: bool, confidence: float = 1.0):
        """Train the false positive filter with user feedback."""
        self.false_positive_filter.train_on_feedback(vuln, is_false_positive, confidence)
