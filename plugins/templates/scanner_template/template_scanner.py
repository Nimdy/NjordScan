"""
Template Scanner Plugin

This is a template for creating custom scanner plugins for NjordScan.
Copy this template and modify it to create your own security scanners.
"""

import re
from pathlib import Path
from typing import List, Dict, Any
import sys
import os

# Add the plugins directory to the path
current_dir = Path(__file__).parent
plugins_dir = current_dir.parent.parent
sys.path.insert(0, str(plugins_dir))

from core.scanner_plugin import ScannerPlugin

class TemplateScanner(ScannerPlugin):
    """Template scanner plugin - modify this class for your needs."""
    
    def get_name(self) -> str:
        return "template_scanner"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def is_compatible(self, njordscan_version: str) -> bool:
        """Check compatibility with NjordScan version."""
        # Simple version check - you might want more sophisticated logic
        return njordscan_version >= "0.1.0"
    
    def should_run(self, mode: str) -> bool:
        """Determine when this plugin should run."""
        # Run in static and full modes
        return mode in ['static', 'full']
    
    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Main scanning method - implement your security checks here."""
        vulnerabilities = []
        
        # Only scan local directories in this template
        if target.startswith(('http://', 'https://')):
            return vulnerabilities
        
        target_path = Path(target)
        if not target_path.exists():
            return vulnerabilities
        
        # Example scanning methods
        vulnerabilities.extend(await self._scan_for_patterns(target_path))
        vulnerabilities.extend(await self._scan_config_files(target_path))
        vulnerabilities.extend(await self._scan_source_files(target_path))
        
        return vulnerabilities
    
    async def _scan_for_patterns(self, target_path: Path) -> List[Dict[str, Any]]:
        """Example: Scan for dangerous patterns in files."""
        vulnerabilities = []
        
        # Define patterns to look for
        dangerous_patterns = [
            {
                'pattern': r'eval\s*\(',
                'severity': 'high',
                'title': 'Use of eval() function',
                'description': 'eval() can execute arbitrary code and should be avoided'
            },
            {
                'pattern': r'document\.write\s*\(',
                'severity': 'medium', 
                'title': 'Use of document.write()',
                'description': 'document.write() can lead to XSS vulnerabilities'
            }
        ]
        
        # Find relevant files
        file_patterns = ['*.js', '*.ts', '*.jsx', '*.tsx']
        files_to_scan = []
        
        for pattern in file_patterns:
            files_to_scan.extend(target_path.rglob(pattern))
        
        # Scan each file
        for file_path in files_to_scan:
            if self.should_skip_file(file_path):
                continue
            
            file_vulns = await self._scan_file_for_patterns(file_path, dangerous_patterns)
            vulnerabilities.extend(file_vulns)
        
        return vulnerabilities
    
    async def _scan_file_for_patterns(self, file_path: Path, patterns: List[Dict]) -> List[Dict[str, Any]]:
        """Scan a file for specific patterns."""
        vulnerabilities = []
        
        try:
            content = self.get_file_content(str(file_path))
            if not content:
                return vulnerabilities
            
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                for pattern_info in patterns:
                    if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                        vulnerabilities.append(self.create_vulnerability(
                            title=pattern_info['title'],
                            description=pattern_info['description'],
                            severity=pattern_info['severity'],
                            vuln_type='pattern_match',
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            fix=f"Remove or replace the dangerous pattern: {pattern_info['pattern']}"
                        ))
        
        except Exception as e:
            if getattr(self.config, 'verbose', False):
                print(f"Error scanning {file_path}: {e}")
        
        return vulnerabilities
    
    async def _scan_config_files(self, target_path: Path) -> List[Dict[str, Any]]:
        """Example: Scan configuration files for issues."""
        vulnerabilities = []
        
        # Look for common config files
        config_files = [
            'package.json',
            '.env',
            'next.config.js',
            'vite.config.js',
            'webpack.config.js'
        ]
        
        for config_name in config_files:
            config_file = target_path / config_name
            if config_file.exists():
                file_vulns = await self._analyze_config_file(config_file)
                vulnerabilities.extend(file_vulns)
        
        return vulnerabilities
    
    async def _analyze_config_file(self, config_file: Path) -> List[Dict[str, Any]]:
        """Analyze a configuration file."""
        vulnerabilities = []
        
        try:
            content = self.get_file_content(str(config_file))
            if not content:
                return vulnerabilities
            
            # Example: Look for development settings in production
            if 'development' in content.lower() and 'production' not in content.lower():
                vulnerabilities.append(self.create_vulnerability(
                    title="Development Configuration in Production",
                    description=f"Configuration file {config_file.name} contains development settings",
                    severity="medium",
                    vuln_type="dev_config",
                    file_path=str(config_file),
                    fix="Ensure production configurations are used for production deployments"
                ))
        
        except Exception as e:
            if getattr(self.config, 'verbose', False):
                print(f"Error analyzing config {config_file}: {e}")
        
        return vulnerabilities
    
    async def _scan_source_files(self, target_path: Path) -> List[Dict[str, Any]]:
        """Example: Scan source files for framework-specific issues."""
        vulnerabilities = []
        
        # Framework-specific scanning
        framework = getattr(self.config, 'framework', 'auto')
        if framework == 'nextjs':
            vulnerabilities.extend(await self._scan_nextjs_specific(target_path))
        elif framework == 'react':
            vulnerabilities.extend(await self._scan_react_specific(target_path))
        elif framework == 'vite':
            vulnerabilities.extend(await self._scan_vite_specific(target_path))
        
        return vulnerabilities
    
    async def _scan_nextjs_specific(self, target_path: Path) -> List[Dict[str, Any]]:
        """Scan for Next.js specific issues."""
        vulnerabilities = []
        
        # Example: Look for API routes without authentication
        api_routes = list(target_path.glob('pages/api/**/*.js')) + list(target_path.glob('pages/api/**/*.ts'))
        
        for api_file in api_routes:
            if self.should_skip_file(api_file):
                continue
            content = self.get_file_content(str(api_file))
            if content and 'auth' not in content.lower():
                vulnerabilities.append(self.create_vulnerability(
                    title="API Route Without Authentication Check",
                    description="API route may lack authentication verification",
                    severity="medium",
                    vuln_type="missing_auth",
                    file_path=str(api_file),
                    fix="Add authentication checks to API routes"
                ))
        
        return vulnerabilities
    
    async def _scan_react_specific(self, target_path: Path) -> List[Dict[str, Any]]:
        """Scan for React specific issues."""
        vulnerabilities = []
        
        # Example: Look for dangerous props
        react_files = list(target_path.rglob('*.jsx')) + list(target_path.rglob('*.tsx'))
        
        for react_file in react_files:
            if self.should_skip_file(react_file):
                continue
            
            content = self.get_file_content(str(react_file))
            if content and 'dangerouslySetInnerHTML' in content:
                vulnerabilities.append(self.create_vulnerability(
                    title="Dangerous HTML Injection",
                    description="Use of dangerouslySetInnerHTML may lead to XSS",
                    severity="high",
                    vuln_type="dangerous_html",
                    file_path=str(react_file),
                    fix="Sanitize HTML content or use safer alternatives"
                ))
        
        return vulnerabilities
    
    async def _scan_vite_specific(self, target_path: Path) -> List[Dict[str, Any]]:
        """Scan for Vite specific issues."""
        vulnerabilities = []
        
        # Example: Check Vite config for dev server exposure
        vite_config = target_path / 'vite.config.js'
        if not vite_config.exists():
            vite_config = target_path / 'vite.config.ts'
        
        if vite_config.exists():
            content = self.get_file_content(str(vite_config))
            if content and 'host: true' in content:
                vulnerabilities.append(self.create_vulnerability(
                    title="Vite Dev Server Network Exposure",
                    description="Vite development server is exposed to network",
                    severity="low",
                    vuln_type="dev_exposure",
                    file_path=str(vite_config),
                    fix="Remove network exposure in production builds"
                ))
        
        return vulnerabilities
    
    def _get_config_value(self, key: str, default=None):
        """Get plugin configuration value."""
        plugin_config = getattr(self.config, 'plugins', {}).get('template_scanner', {})
        return plugin_config.get('config', {}).get(key, default)