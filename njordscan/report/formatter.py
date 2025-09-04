"""
Enhanced Report Formatter for NjordScan

Handles formatting and display of scan results in various formats with improved styling and features.
"""

import json
import html
import os
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn
from rich.tree import Tree
from rich.markdown import Markdown
from rich.layout import Layout
from rich.columns import Columns
from rich import box

class ReportFormatter:
    """Enhanced formatter for displaying scan results."""
    
    def __init__(self, config):
        self.config = config
        self.console = Console()
        
        self.severity_colors = {
            'critical': 'bright_red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'cyan'
        }
        
        self.severity_icons = {
            'critical': '🔴',
            'high': '🟠', 
            'medium': '🟡',
            'low': '🔵',
            'info': 'ℹ️'
        }
        
        self.severity_weights = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
    
    def display_terminal_report(self, results: Dict[str, Any]):
        """Display comprehensive scan results in terminal using Rich."""
        
        # Clear screen for better presentation
        self.console.clear()
        
        # Display header with scan info
        self._display_enhanced_header(results)
        
        # Display executive summary
        self._display_executive_summary(results)
        
        # Display NjordScore prominently
        self._display_njord_score_panel(results)
        
        # Display vulnerability breakdown
        self._display_vulnerability_breakdown(results)
        
        # Display detailed findings by module
        self._display_detailed_findings(results)
        
        # Display recommendations if requested
        if self.config.suggest_fixes:
            self._display_security_recommendations(results)
        
        # Display footer with next steps
        self._display_footer(results)
    
    def _display_enhanced_header(self, results: Dict[str, Any]):
        """Display enhanced header with scan information."""
        
        # Create layout for header
        header_layout = Layout()
        header_layout.split_column(
            Layout(name="title", size=3),
            Layout(name="info", size=4)
        )
        
        # Title section
        title_text = Text()
        title_text.append("🔍 NjordScan Security Report\n", style="bold bright_cyan")
        title_text.append("Professional Web Application Security Scanner", style="italic cyan")
        header_layout["title"].update(Panel(title_text, style="cyan"))
        
        # Info section
        info_table = Table.grid(expand=True)
        info_table.add_column(style="bold white")
        info_table.add_column(style="green")
        info_table.add_column(style="bold white")
        info_table.add_column(style="green")
        
        info_table.add_row(
            "🎯 Target:", results['target'],
            "⚡ Framework:", results['framework'].title()
        )
        info_table.add_row(
            "🔧 Mode:", results['scan_mode'].title(),
            "⏱️  Duration:", f"{results['scan_duration']:.2f}s"
        )
        info_table.add_row(
            "📅 Timestamp:", datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "🔍 Modules:", f"{len(results['modules_run'])} active"
        )
        
        header_layout["info"].update(Panel(info_table, title="Scan Details", style="blue"))
        
        self.console.print(header_layout)
        self.console.print()
    
    def _display_executive_summary(self, results: Dict[str, Any]):
        """Display executive summary with key metrics."""
        summary = results['summary']
        
        # Create metrics table
        metrics_table = Table(show_header=False, expand=True, box=box.SIMPLE)
        metrics_table.add_column(style="bold")
        metrics_table.add_column(justify="center", style="bold")
        
        # Add severity breakdown
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = summary['severity_breakdown'].get(severity, 0)
            if count > 0:
                icon = self.severity_icons[severity]
                color = self.severity_colors[severity]
                metrics_table.add_row(
                    f"{icon} {severity.title()} Issues",
                    f"[{color}]{count}[/{color}]"
                )
        
        metrics_table.add_row("", "")  # Spacer
        metrics_table.add_row("📊 Total Issues", str(summary['total_issues']))
        metrics_table.add_row("🎯 Modules with Findings", str(summary['modules_with_findings']))
        
        self.console.print(Panel(metrics_table, title="📈 Executive Summary", style="green"))
        self.console.print()
    
    def _display_njord_score_panel(self, results: Dict[str, Any]):
        """Display NjordScore in a prominent panel."""
        njord_score = results['njord_score']
        
        # Create score display
        score_text = Text()
        score_text.append("🏆 Security Score: ", style="bold cyan")
        
        # Color based on grade
        grade_colors = {
            'A+': 'bright_green', 'A': 'green', 'B+': 'yellow',
            'B': 'yellow', 'C': 'orange', 'D': 'red', 'F': 'bright_red'
        }
        
        grade_color = grade_colors.get(njord_score['grade'], 'white')
        score_text.append(f"{njord_score['score']}/100", style=f"bold {grade_color} on black")
        score_text.append(f" ({njord_score['grade']})\n\n", style=f"bold {grade_color}")
        
        score_text.append("💬 ", style="cyan")
        score_text.append(njord_score['recommendation'], style="italic white")
        
        # Add next steps if available
        if 'next_steps' in njord_score and njord_score['next_steps']:
            score_text.append("\n\n🎯 Priority Actions:\n", style="bold yellow")
            for i, step in enumerate(njord_score['next_steps'][:3], 1):
                score_text.append(f"{i}. {step}\n", style="white")
        
        panel_style = grade_color if njord_score['score'] >= 80 else "red"
        self.console.print(Panel(score_text, title="🏆 NjordScore Assessment", style=panel_style))
        self.console.print()
    
    def _display_vulnerability_breakdown(self, results: Dict[str, Any]):
        """Display vulnerability breakdown by module."""
        vulnerabilities = results['vulnerabilities']
        
        if not any(vulnerabilities.values()):
            success_text = Text()
            success_text.append("🎉 No security vulnerabilities detected!\n", style="bold green")
            success_text.append("Your application follows security best practices.", style="green")
            self.console.print(Panel(success_text, title="✅ Security Status", style="green"))
            return
        
        # Create breakdown table
        breakdown_table = Table(title="🔍 Vulnerability Breakdown by Module")
        breakdown_table.add_column("Module", style="cyan", width=15)
        breakdown_table.add_column("Critical", justify="center", style="bright_red")
        breakdown_table.add_column("High", justify="center", style="red")
        breakdown_table.add_column("Medium", justify="center", style="yellow")
        breakdown_table.add_column("Low", justify="center", style="blue")
        breakdown_table.add_column("Info", justify="center", style="cyan")
        breakdown_table.add_column("Total", justify="center", style="bold white")
        
        for module_name, module_vulns in vulnerabilities.items():
            if not module_vulns:
                continue
            
            # Count by severity
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for vuln in module_vulns:
                severity = vuln.get('severity', 'info')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            total_count = len(module_vulns)
            
            breakdown_table.add_row(
                module_name.title(),
                str(severity_counts['critical']) if severity_counts['critical'] > 0 else "-",
                str(severity_counts['high']) if severity_counts['high'] > 0 else "-",
                str(severity_counts['medium']) if severity_counts['medium'] > 0 else "-",
                str(severity_counts['low']) if severity_counts['low'] > 0 else "-",
                str(severity_counts['info']) if severity_counts['info'] > 0 else "-",
                str(total_count)
            )
        
        self.console.print(breakdown_table)
        self.console.print()
    
    def _display_detailed_findings(self, results: Dict[str, Any]):
        """Display detailed vulnerability findings."""
        vulnerabilities = results['vulnerabilities']
        
        for module_name, module_vulns in vulnerabilities.items():
            if not module_vulns:
                continue
            
            # Sort vulnerabilities by severity
            sorted_vulns = sorted(
                module_vulns, 
                key=lambda x: self.severity_weights.get(x.get('severity', 'info'), 0),
                reverse=True
            )
            
            # Create module tree
            module_tree = Tree(f"🔧 {module_name.upper()} MODULE", style="bold cyan")
            
            current_severity = None
            severity_branch = None
            
            for vuln in sorted_vulns:
                severity = vuln.get('severity', 'info')
                
                # Create new severity branch if needed
                if severity != current_severity:
                    current_severity = severity
                    severity_branch = module_tree.add(
                        f"{self.severity_icons[severity]} {severity.upper()} SEVERITY",
                        style=f"bold {self.severity_colors[severity]}"
                    )
                
                # Add vulnerability to branch
                vuln_title = f"[{self.severity_colors[severity]}]{vuln['title']}[/{self.severity_colors[severity]}]"
                vuln_branch = severity_branch.add(vuln_title)
                
                # Add vulnerability details
                if vuln.get('file_path'):
                    vuln_branch.add(f"📁 File: {vuln['file_path']}")
                if vuln.get('line_number'):
                    vuln_branch.add(f"📍 Line: {vuln['line_number']}")
                if vuln.get('description'):
                    vuln_branch.add(f"📝 {vuln['description']}")
                if vuln.get('fix'):
                    vuln_branch.add(f"💡 Fix: {vuln['fix']}", style="green")
                if vuln.get('code_snippet'):
                    vuln_branch.add(f"💻 Code: {vuln['code_snippet'][:80]}{'...' if len(vuln['code_snippet']) > 80 else ''}")
            
            self.console.print(module_tree)
            self.console.print()
    
    def _display_security_recommendations(self, results: Dict[str, Any]):
        """Display security recommendations."""
        vulnerabilities = results['vulnerabilities']
        
        # Collect all unique recommendations
        recommendations = set()
        priority_fixes = []
        
        for module_vulns in vulnerabilities.values():
            for vuln in module_vulns:
                if vuln.get('fix'):
                    recommendations.add(vuln['fix'])
                
                # Collect critical/high severity for priority
                if vuln.get('severity') in ['critical', 'high']:
                    priority_fixes.append({
                        'title': vuln['title'],
                        'severity': vuln['severity'],
                        'fix': vuln.get('fix', 'Review and address this issue')
                    })
        
        if not recommendations:
            return
        
        # Display priority fixes first
        if priority_fixes:
            priority_text = Text()
            priority_text.append("🚨 Priority Fixes (Critical/High):\n\n", style="bold red")
            
            for i, fix in enumerate(priority_fixes[:5], 1):  # Top 5 priority fixes
                severity_color = self.severity_colors[fix['severity']]
                priority_text.append(f"{i}. ", style="bold white")
                priority_text.append(f"[{fix['severity'].upper()}] ", style=f"bold {severity_color}")
                priority_text.append(f"{fix['title']}\n", style="white")
                priority_text.append(f"   💡 {fix['fix']}\n\n", style="green")
            
            self.console.print(Panel(priority_text, title="🔥 Immediate Action Required", style="red"))
        
        # Display general recommendations
        if recommendations:
            rec_text = Text()
            rec_text.append("Security Improvement Recommendations:\n\n", style="bold yellow")
            
            for i, rec in enumerate(sorted(recommendations)[:10], 1):  # Top 10 recommendations
                rec_text.append(f"{i}. {rec}\n", style="white")
            
            self.console.print(Panel(rec_text, title="🔧 General Recommendations", style="yellow"))
        
        self.console.print()
    
    def _display_footer(self, results: Dict[str, Any]):
        """Display footer with additional information."""
        footer_text = Text()
        footer_text.append("📚 Resources:\n", style="bold cyan")
        footer_text.append("• OWASP Top 10: https://owasp.org/www-project-top-ten/\n", style="blue")
        footer_text.append("• Security Headers: https://securityheaders.com/\n", style="blue")
        footer_text.append("• NjordScan Documentation: https://github.com/njordscan/docs\n", style="blue")
        
        footer_text.append("\n🤝 Need Help?\n", style="bold green")
        footer_text.append("Run 'njordscan explain <vulnerability_type>' for detailed guidance\n", style="green")
        
        self.console.print(Panel(footer_text, title="📖 Additional Resources", style="cyan"))
    
    def save_report(self, results: Dict[str, Any], output_file: str):
        """Save report to file in specified format."""
        output_path = Path(output_file)
        
        if self.config.report_format == 'json':
            self._save_json_report(results, output_path)
        elif self.config.report_format == 'html':
            self._save_html_report(results, output_path)
        elif self.config.report_format == 'sarif':
            self._save_sarif_report(results, output_path)
        else:  # text
            self._save_text_report(results, output_path)
    
    def _save_json_report(self, results: Dict[str, Any], output_path: Path):
        """Save report as enhanced JSON."""
        # Add metadata
        report_data = {
            'metadata': {
                'tool': 'NjordScan',
                'version': '0.1.0',
                'timestamp': datetime.now().isoformat(),
                'report_format': 'json',
                'scan_config': {
                    'mode': self.config.mode,
                    'framework': self.config.framework,
                    'pentest_mode': self.config.pentest_mode
                }
            },
            'scan_results': results,
            'statistics': {
                'total_vulnerabilities': results['summary']['total_issues'],
                'severity_distribution': results['summary']['severity_breakdown'],
                'modules_executed': len(results['modules_run']),
                'scan_efficiency': f"{results['summary']['total_issues']}/{results['scan_duration']:.1f} issues/second"
            }
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
    
    def _save_html_report(self, results: Dict[str, Any], output_path: Path):
        """Save report as enhanced HTML with modern styling."""
        html_template = self._get_enhanced_html_template()
        
        # Prepare vulnerability data for HTML
        vulnerabilities_html = self._format_vulnerabilities_for_html(results['vulnerabilities'])
        
        # Calculate additional metrics
        severity_breakdown = results['summary']['severity_breakdown']
        total_issues = results['summary']['total_issues']
        
        # Create severity chart data
        chart_data = []
        for severity, count in severity_breakdown.items():
            if count > 0:
                chart_data.append(f"['{severity.title()}', {count}]")
        
        # Calculate grade and recommendation based on score
        njord_score = results.get('njord_score', 0)
        if njord_score >= 90:
            grade = 'A+'
            recommendation = 'Excellent security posture! Keep up the great work.'
        elif njord_score >= 80:
            grade = 'A'
            recommendation = 'Good security posture with minor improvements needed.'
        elif njord_score >= 70:
            grade = 'B'
            recommendation = 'Moderate security posture. Address medium-priority issues.'
        elif njord_score >= 60:
            grade = 'C'
            recommendation = 'Below average security. Focus on high-priority vulnerabilities.'
        else:
            grade = 'D'
            recommendation = 'Poor security posture. Immediate action required.'
        
        template_data = {
            'title': 'NjordScan Security Report',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target': html.escape(results.get('target', '.')),
            'framework': results.get('framework', 'Unknown').title(),
            'scan_mode': results.get('mode', 'standard').title(),
            'duration': f"{results.get('scan_duration', 0):.2f}s",
            'total_issues': total_issues,
            'njord_score': njord_score,
            'njord_score_grade': grade,
            'njord_score_recommendation': recommendation,
            'vulnerabilities_html': vulnerabilities_html,
            'chart_data': ','.join(chart_data),
            'severity_breakdown': severity_breakdown,
            'modules_run': ', '.join(results['modules_run'])
        }
        
        # Simple template rendering
        html_content = html_template.format(**template_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _save_sarif_report(self, results: Dict[str, Any], output_path: Path):
        """Save report in SARIF format for integration with security tools."""
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "NjordScan",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/njordscan/njordscan",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        # Convert vulnerabilities to SARIF format
        for module_name, module_vulns in results['vulnerabilities'].items():
            for vuln in module_vulns:
                sarif_result = {
                    "ruleId": vuln.get('id', f"{module_name}_unknown"),
                    "level": self._map_severity_to_sarif(vuln.get('severity', 'info')),
                    "message": {
                        "text": vuln.get('description', vuln.get('title', 'Security issue detected'))
                    },
                    "locations": []
                }
                
                # Add location if available
                if vuln.get('file_path'):
                    location = {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": vuln['file_path']
                            }
                        }
                    }
                    
                    if vuln.get('line_number'):
                        location["physicalLocation"]["region"] = {
                            "startLine": vuln['line_number']
                        }
                    
                    sarif_result["locations"].append(location)
                
                sarif_report["runs"][0]["results"].append(sarif_result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_report, f, indent=2)
    
    def _save_text_report(self, results: Dict[str, Any], output_path: Path):
        """Save report as enhanced plain text."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("NJORDSCAN SECURITY REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            # Header information
            f.write(f"Target: {results.get('target', '.')}\n")
            f.write(f"Framework: {results.get('framework', 'Unknown')}\n")
            f.write(f"Scan Mode: {results.get('mode', 'standard')}\n")
            f.write(f"Duration: {results.get('scan_duration', 0):.2f}s\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Issues: {results['summary']['total_issues']}\n")
            f.write(f"Modules with Findings: {results['summary'].get('modules_with_findings', 0)}\n\n")
            
            # Severity breakdown
            for severity, count in results['summary']['severity_breakdown'].items():
                if count > 0:
                    f.write(f"{severity.title()}: {count}\n")
            
            # NjordScore
            njord_score = results.get('njord_score', 0)
            if njord_score >= 90:
                grade = 'A+'
                recommendation = 'Excellent security posture! Keep up the great work.'
            elif njord_score >= 80:
                grade = 'A'
                recommendation = 'Good security posture with minor improvements needed.'
            elif njord_score >= 70:
                grade = 'B'
                recommendation = 'Moderate security posture. Address medium-priority issues.'
            elif njord_score >= 60:
                grade = 'C'
                recommendation = 'Below average security. Focus on high-priority vulnerabilities.'
            else:
                grade = 'D'
                recommendation = 'Poor security posture. Immediate action required.'
            
            f.write(f"\nNjordScore: {njord_score}/100 ({grade})\n")
            f.write(f"Recommendation: {recommendation}\n\n")
            
            # Detailed vulnerabilities
            f.write("DETAILED FINDINGS\n")
            f.write("-" * 20 + "\n\n")
            
            vulnerabilities = results['vulnerabilities']
            
            # Handle both list and dict formats
            if isinstance(vulnerabilities, list):
                # Convert list to dict format for processing
                vuln_dict = {'General': vulnerabilities}
            else:
                vuln_dict = vulnerabilities
            
            for module_name, module_vulns in vuln_dict.items():
                if module_vulns:
                    f.write(f"{module_name.upper()} MODULE\n")
                    f.write("-" * len(module_name) + "\n")
                    
                    for vuln in module_vulns:
                        f.write(f"[{vuln['severity'].upper()}] {vuln['title']}\n")
                        f.write(f"Description: {vuln['description']}\n")
                        if vuln.get('file_path'):
                            f.write(f"File: {vuln['file_path']}\n")
                        elif vuln.get('file'):
                            f.write(f"File: {vuln['file']}\n")
                        if vuln.get('line_number'):
                            f.write(f"Line: {vuln['line_number']}\n")
                        elif vuln.get('line'):
                            f.write(f"Line: {vuln['line']}\n")
                        if vuln.get('fix'):
                            f.write(f"Fix: {vuln['fix']}\n")
                        f.write("\n")
    
    def _format_vulnerabilities_for_html(self, vulnerabilities) -> str:
        """Format vulnerabilities for HTML display."""
        html_parts = []
        
        # Handle both list and dict formats
        if isinstance(vulnerabilities, list):
            # Convert list to dict format for processing
            vuln_dict = {'General': vulnerabilities}
        else:
            vuln_dict = vulnerabilities
        
        for module_name, module_vulns in vuln_dict.items():
            if not module_vulns:
                continue
            
            html_parts.append(f'<div class="module-section">')
            html_parts.append(f'<h3 class="module-title">{module_name.title()} Module</h3>')
            
            for vuln in module_vulns:
                severity = vuln.get('severity', 'info')
                html_parts.append(f'<div class="vulnerability {severity}">')
                html_parts.append(f'<h4 class="vuln-title">{html.escape(vuln["title"])}</h4>')
                html_parts.append(f'<p class="vuln-description">{html.escape(vuln["description"])}</p>')
                
                if vuln.get('file_path'):
                    html_parts.append(f'<p class="vuln-file"><strong>File:</strong> {html.escape(vuln["file_path"])}</p>')
                elif vuln.get('file'):
                    html_parts.append(f'<p class="vuln-file"><strong>File:</strong> {html.escape(vuln["file"])}</p>')
                if vuln.get('fix'):
                    html_parts.append(f'<p class="vuln-fix"><strong>Fix:</strong> {html.escape(vuln["fix"])}</p>')
                
                html_parts.append('</div>')
            
            html_parts.append('</div>')
        
        return '\n'.join(html_parts)
    
    def _map_severity_to_sarif(self, severity: str) -> str:
        """Map our severity levels to SARIF levels."""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return mapping.get(severity.lower(), 'note')

    def _get_enhanced_html_template(self) -> str:
        """Get enhanced HTML report template with modern styling."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: white;
            margin-top: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .info-card {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
        }}
        
        .njord-score {{
            text-align: center;
            padding: 30px;
            margin: 20px 0;
            border-radius: 10px;
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
        }}
        
        .score-number {{
            font-size: 4em;
            font-weight: bold;
            display: block;
        }}
        
        .score-grade {{
            font-size: 2em;
            margin-top: 10px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin: 30px 0;
        }}
        
        .chart-container {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #e9ecef;
        }}
        
        .vulnerability {{
            margin: 20px 0;
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #ccc;
        }}
        
        .vulnerability.critical {{
            background: #fff5f5;
            border-left-color: #dc3545;
        }}
        
        .vulnerability.high {{
            background: #fff8f0;
            border-left-color: #fd7e14;
        }}
        
        .vulnerability.medium {{
            background: #fffbf0;
            border-left-color: #ffc107;
        }}
        
        .vulnerability.low {{
            background: #f0f8ff;
            border-left-color: #17a2b8;
        }}
        
        .vulnerability.info {{
            background: #f8f9fa;
            border-left-color: #6c757d;
        }}
        
        .vuln-title {{
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        
        .vuln-description {{
            color: #666;
            margin-bottom: 15px;
        }}
        
        .vuln-fix {{
            color: #28a745;
            font-weight: 500;
        }}
        
        .module-section {{
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }}
        
        .module-title {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid #eee;
            margin-top: 40px;
        }}
        
        @media (max-width: 768px) {{
            .container {{ margin: 10px; padding: 15px; }}
            .summary-grid {{ grid-template-columns: 1fr; }}
            .scan-info {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 {title}</h1>
            <p>Professional Web Application Security Assessment</p>
            
            <div class="scan-info">
                <div class="info-card">
                    <strong>🎯 Target:</strong><br>{target}
                </div>
                <div class="info-card">
                    <strong>⚡ Framework:</strong><br>{framework}
                </div>
                <div class="info-card">
                    <strong>🔧 Scan Mode:</strong><br>{scan_mode}
                </div>
                <div class="info-card">
                    <strong>⏱️ Duration:</strong><br>{duration}
                </div>
                <div class="info-card">
                    <strong>📅 Timestamp:</strong><br>{timestamp}
                </div>
                <div class="info-card">
                    <strong>🔍 Modules:</strong><br>{modules_run}
                </div>
            </div>
        </div>
        
        <div class="njord-score">
            <h2>🏆 NjordScore Security Assessment</h2>
            <span class="score-number">{njord_score}/100</span>
            <div class="score-grade">Grade: {njord_score_grade}</div>
            <p style="margin-top: 15px; font-size: 1.1em;">{njord_score_recommendation}</p>
        </div>
        
        <div class="summary-grid">
            <div class="chart-container">
                <h3>📊 Vulnerability Distribution</h3>
                <canvas id="severityChart" width="400" height="300"></canvas>
            </div>
            
            <div class="chart-container">
                <h3>📈 Security Metrics</h3>
                <table style="width: 100%; margin-top: 20px;">
                    <tr><td><strong>Total Issues:</strong></td><td>{total_issues}</td></tr>
                    <tr><td><strong>Critical:</strong></td><td style="color: #dc3545;">{severity_breakdown[critical]}</td></tr>
                    <tr><td><strong>High:</strong></td><td style="color: #fd7e14;">{severity_breakdown[high]}</td></tr>
                    <tr><td><strong>Medium:</strong></td><td style="color: #ffc107;">{severity_breakdown[medium]}</td></tr>
                    <tr><td><strong>Low:</strong></td><td style="color: #17a2b8;">{severity_breakdown[low]}</td></tr>
                    <tr><td><strong>Info:</strong></td><td style="color: #6c757d;">{severity_breakdown[info]}</td></tr>
                </table>
            </div>
        </div>
        
        <h2>🔍 Detailed Security Findings</h2>
        {vulnerabilities_html}
        
        <div class="footer">
            <p>Generated by NjordScan v0.1.0 | Professional Web Application Security Scanner</p>
            <p>For support and documentation, visit: <a href="https://github.com/njordscan">https://github.com/njordscan</a></p>
        </div>
    </div>
    
    <script>
        // Create severity distribution chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        const chart = new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{severity_breakdown[critical]}, {severity_breakdown[high]}, {severity_breakdown[medium]}, {severity_breakdown[low]}, {severity_breakdown[info]}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 20,
                            usePointStyle: true
                        }}
                    }},
                    title: {{
                        display: true,
                        text: 'Security Issues by Severity'
                    }}
                }},
                cutout: '50%',
                animation: {{
                    animateRotate: true,
                    duration: 1000
                }}
            }}
        }});
        
        // Add hover effects and tooltips
        chart.options.plugins.tooltip = {{
            callbacks: {{
                label: function(context) {{
                    const label = context.label || '';
                    const value = context.parsed;
                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                    const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                    return `${{label}}: ${{value}} (${{percentage}}%)`;
                }}
            }}
        }};
        
        // Update chart with new options
        chart.update();
    </script>
</body>
</html>'''