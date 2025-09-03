"""
Template Reporter Plugin

This is a template for creating custom report format plugins for NjordScan.
Copy this template and modify it to create your own report formats.
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any
from pathlib import Path
import sys
import os

# Add the plugins directory to the path
current_dir = Path(__file__).parent
plugins_dir = current_dir.parent.parent
sys.path.insert(0, str(plugins_dir))

from core.reporter_plugin import ReporterPlugin

class TemplateReporter(ReporterPlugin):
    """Template reporter plugin - modify this class for your needs."""
    
    def get_name(self) -> str:
        return "template_reporter"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def is_compatible(self, njordscan_version: str) -> bool:
        """Check compatibility with NjordScan version."""
        return njordscan_version >= "0.1.0"
    
    def get_format_name(self) -> str:
        """Return the format name for CLI usage."""
        return "template"
    
    def get_file_extension(self) -> str:
        """Return the file extension for this format."""
        return ".template"
    
    async def generate_report(self, results: Dict[str, Any], output_path: str) -> bool:
        """Generate report in custom format."""
        try:
            # Choose your format implementation
            report_content = self._generate_text_format(results)
            # report_content = self._generate_json_format(results)  
            # report_content = self._generate_xml_format(results)
            # report_content = self._generate_csv_format(results)
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return True
            
        except Exception as e:
            print(f"Error generating {self.get_format_name()} report: {e}")
            return False
    
    def _generate_text_format(self, results: Dict[str, Any]) -> str:
        """Generate a simple text format report."""
        lines = []
        
        # Header
        lines.append("=" * 60)
        lines.append("NJORDSCAN SECURITY REPORT")
        lines.append("=" * 60)
        
        if self._get_config_value('include_timestamps', True):
            lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        lines.append(f"Target: {results.get('target', 'Unknown')}")
        lines.append(f"Framework: {results.get('framework', 'Unknown')}")
        lines.append(f"Scan Mode: {results.get('scan_mode', 'Unknown')}")
        lines.append(f"Duration: {results.get('scan_duration', 0):.2f}s")
        lines.append("")
        
        # Summary
        summary = results.get('summary', {})
        lines.append("SUMMARY")
        lines.append("-" * 20)
        lines.append(f"Total Issues: {summary.get('total_issues', 0)}")
        
        severity_breakdown = summary.get('severity_breakdown', {})
        for severity, count in severity_breakdown.items():
            if count > 0:
                lines.append(f"{severity.title()}: {count}")
        lines.append("")
        
        # NjordScore
        njord_score = results.get('njord_score', {})
        lines.append("SECURITY SCORE")
        lines.append("-" * 20)
        lines.append(f"Score: {njord_score.get('score', 0)}/100")
        lines.append(f"Grade: {njord_score.get('grade', 'N/A')}")
        lines.append(f"Recommendation: {njord_score.get('recommendation', 'N/A')}")
        lines.append("")
        
        # Detailed findings
        vulnerabilities = results.get('vulnerabilities', {})
        if vulnerabilities:
            lines.append("DETAILED FINDINGS")
            lines.append("-" * 20)
            
            for module_name, module_vulns in vulnerabilities.items():
                if module_vulns:
                    lines.append(f"\n{module_name.upper()} MODULE:")
                    
                    for i, vuln in enumerate(module_vulns, 1):
                        lines.append(f"  {i}. [{vuln['severity'].upper()}] {vuln['title']}")
                        lines.append(f"     Description: {vuln['description']}")
                        
                        if vuln.get('file_path'):
                            location = vuln['file_path']
                            if vuln.get('line_number'):
                                location += f":{vuln['line_number']}"
                            lines.append(f"     Location: {location}")
                        
                        if vuln.get('fix'):
                            lines.append(f"     Fix: {vuln['fix']}")
                        lines.append("")
        
        return "\n".join(lines)
    
    def _generate_json_format(self, results: Dict[str, Any]) -> str:
        """Generate a JSON format report."""
        report_data = {
            "metadata": {
                "tool": "NjordScan",
                "format": "template_json",
                "generated_at": datetime.now().isoformat(),
                "version": self.get_version()
            },
            "scan_info": {
                "target": results.get('target'),
                "framework": results.get('framework'),
                "mode": results.get('scan_mode'),
                "duration": results.get('scan_duration'),
                "modules": results.get('modules_run', [])
            },
            "summary": results.get('summary', {}),
            "score": results.get('njord_score', {}),
            "vulnerabilities": results.get('vulnerabilities', {}),
            "config": {
                "include_timestamps": self._get_config_value('include_timestamps', True),
                "compress_output": self._get_config_value('compress_output', False)
            }
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_xml_format(self, results: Dict[str, Any]) -> str:
        """Generate an XML format report."""
        root = ET.Element("njordscan_report")
        
        # Metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "tool").text = "NjordScan"
        ET.SubElement(metadata, "format").text = "template_xml"
        if self._get_config_value('include_timestamps', True):
            ET.SubElement(metadata, "generated_at").text = datetime.now().isoformat()
        
        # Scan info
        scan_info = ET.SubElement(root, "scan_info")
        ET.SubElement(scan_info, "target").text = results.get('target', '')
        ET.SubElement(scan_info, "framework").text = results.get('framework', '')
        ET.SubElement(scan_info, "mode").text = results.get('scan_mode', '')
        ET.SubElement(scan_info, "duration").text = str(results.get('scan_duration', 0))
        
        # Summary
        summary = results.get('summary', {})
        summary_elem = ET.SubElement(root, "summary")
        ET.SubElement(summary_elem, "total_issues").text = str(summary.get('total_issues', 0))
        
        severity_elem = ET.SubElement(summary_elem, "severity_breakdown")
        for severity, count in summary.get('severity_breakdown', {}).items():
            sev_elem = ET.SubElement(severity_elem, severity)
            sev_elem.text = str(count)
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, "vulnerabilities")
        for module_name, module_vulns in results.get('vulnerabilities', {}).items():
            module_elem = ET.SubElement(vulns_elem, "module", name=module_name)
            
            for vuln in module_vulns:
                vuln_elem = ET.SubElement(module_elem, "vulnerability")
                vuln_elem.set("severity", vuln['severity'])
                
                ET.SubElement(vuln_elem, "title").text = vuln['title']
                ET.SubElement(vuln_elem, "description").text = vuln['description']
                
                if vuln.get('file_path'):
                    ET.SubElement(vuln_elem, "file_path").text = vuln['file_path']
                if vuln.get('line_number'):
                    ET.SubElement(vuln_elem, "line_number").text = str(vuln['line_number'])
                if vuln.get('fix'):
                    ET.SubElement(vuln_elem, "fix").text = vuln['fix']
        
        return ET.tostring(root, encoding='unicode', xml_declaration=True)
    
    def _generate_csv_format(self, results: Dict[str, Any]) -> str:
        """Generate a CSV format report."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # CSV Header
        writer.writerow([
            'Module', 'Severity', 'Title', 'Description', 
            'File Path', 'Line Number', 'Fix'
        ])
        
        # Write vulnerabilities
        for module_name, module_vulns in results.get('vulnerabilities', {}).items():
            for vuln in module_vulns:
                writer.writerow([
                    module_name,
                    vuln['severity'],
                    vuln['title'],
                    vuln['description'],
                    vuln.get('file_path', ''),
                    vuln.get('line_number', ''),
                    vuln.get('fix', '')
                ])
        
        return output.getvalue()
    
    def _get_config_value(self, key: str, default=None):
        """Get plugin configuration value."""
        plugin_config = getattr(self.config, 'plugins', {}).get('template_reporter', {})
        return plugin_config.get('config', {}).get(key, default)