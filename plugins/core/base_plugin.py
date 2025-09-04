"""
Base Plugin Interface for NjordScan

All plugins must inherit from BasePlugin and implement required methods.
"""

import os
import json
import yaml
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

@dataclass
class PluginMetadata:
    """Plugin metadata structure."""
    name: str
    version: str
    author: str
    description: str
    compatibility_version: str
    frameworks: List[str]
    categories: List[str]
    tags: List[str]
    dependencies: List[str]
    permissions: List[str]

class BasePlugin(ABC):
    """Base class for all NjordScan plugins."""
    
    def __init__(self, config, vuln_id_generator):
        self.config = config
        self.vuln_id_generator = vuln_id_generator
        self.metadata = None
        self._plugin_dir = self._find_plugin_directory()
        if self._plugin_dir:
            self.metadata = self._load_metadata()
    
    @abstractmethod
    def get_name(self) -> str:
        """Return plugin name."""
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """Return plugin version."""
        pass
    
    @abstractmethod
    def is_compatible(self, njordscan_version: str) -> bool:
        """Check if plugin is compatible with NjordScan version."""
        pass
    
    def _find_plugin_directory(self) -> Optional[Path]:
        """Find the plugin directory based on the current file location."""
        current_file = Path(__file__)
        
        # Look for plugin directory structure
        for parent in current_file.parents:
            if parent.name in ['plugins', 'community', 'frameworks', 'libraries']:
                # Look for config.yaml in plugin subdirectories
                for subdir in parent.iterdir():
                    if subdir.is_dir() and (subdir / 'config.yaml').exists():
                        # Check if this plugin class is in this directory
                        plugin_files = list(subdir.glob('*.py'))
                        for plugin_file in plugin_files:
                            try:
                                content = plugin_file.read_text(encoding='utf-8')
                                if self.__class__.__name__ in content:
                                    return subdir
                            except:
                                continue
        return None
    
    def _load_metadata(self) -> Optional[PluginMetadata]:
        """Load plugin metadata from config file."""
        if not self._plugin_dir:
            return None
            
        config_file = self._plugin_dir / 'config.yaml'
        
        if not config_file.exists():
            return None
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            return PluginMetadata(
                name=config_data.get('name', self.get_name()),
                version=config_data.get('version', self.get_version()),
                author=config_data.get('author', 'Unknown'),
                description=config_data.get('description', 'No description'),
                compatibility_version=config_data.get('compatibility', {}).get('njordscan_version', '>=0.1.0'),
                frameworks=config_data.get('compatibility', {}).get('frameworks', []),
                categories=config_data.get('categories', []),
                tags=config_data.get('tags', []),
                dependencies=config_data.get('dependencies', []),
                permissions=config_data.get('permissions', [])
            )
        except Exception:
            return None
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return plugin metadata as dictionary."""
        if not self.metadata:
            return {
                'name': self.get_name(),
                'version': self.get_version(),
                'author': 'Unknown',
                'description': 'No description',
                'compatibility_version': '>=0.1.0',
                'frameworks': [],
                'categories': [],
                'tags': [],
                'dependencies': [],
                'permissions': []
            }
        
        return {
            'name': self.metadata.name,
            'version': self.metadata.version,
            'author': self.metadata.author,
            'description': self.metadata.description,
            'compatibility_version': self.metadata.compatibility_version,
            'frameworks': self.metadata.frameworks,
            'categories': self.metadata.categories,
            'tags': self.metadata.tags,
            'dependencies': self.metadata.dependencies,
            'permissions': self.metadata.permissions
        }
    
    def supports_framework(self, framework: str) -> bool:
        """Check if plugin supports the given framework."""
        if not self.metadata:
            return True
        return framework in self.metadata.frameworks or 'all' in self.metadata.frameworks
    
    def requires_permission(self, permission: str) -> bool:
        """Check if plugin requires specific permission."""
        if not self.metadata:
            return False
        return permission in self.metadata.permissions
    
    def pre_scan_setup(self) -> bool:
        """Setup tasks before scanning. Return True if successful."""
        return True
    
    def post_scan_cleanup(self):
        """Cleanup tasks after scanning."""
        pass
    
    def get_file_content(self, file_path: str) -> Optional[str]:
        """Safely read file content."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except (IOError, UnicodeDecodeError):
            return None
    
    def create_vulnerability(self, 
                           title: str,
                           description: str,
                           severity: str,
                           confidence: str = "medium",
                           vuln_type: str = "",
                           file_path: Optional[str] = None,
                           line_number: Optional[int] = None,
                           code_snippet: Optional[str] = None,
                           fix: Optional[str] = None,
                           reference: Optional[str] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a standardized vulnerability object as dictionary."""
        vuln_id = self.vuln_id_generator.generate_id(self.get_name(), vuln_type)
        
        return {
            'id': vuln_id,
            'title': title,
            'severity': severity.lower(),
            'confidence': confidence.lower(),
            'description': description,
            'fix': fix or self._get_default_fix(title),
            'reference': reference or self._get_default_reference(title),
            'file_path': file_path,
            'line_number': line_number,
            'code_snippet': code_snippet,
            'framework': getattr(self.config, 'framework', ''),
            'module': self.get_name(),
            'metadata': metadata or {}
        }
    
    def _get_default_fix(self, title: str) -> str:
        """Get default fix recommendation based on vulnerability title."""
        fixes = {
            'xss': 'Sanitize user input and use proper escaping mechanisms',
            'ssrf': 'Validate and whitelist allowed URLs and destinations',
            'secrets': 'Remove hardcoded secrets and use environment variables',
            'headers': 'Implement proper security headers',
            'csp': 'Implement Content Security Policy',
            'cors': 'Configure CORS properly to restrict origins',
            'sql': 'Use parameterized queries to prevent SQL injection',
            'command': 'Avoid dynamic command execution or properly sanitize inputs'
        }
        
        title_lower = title.lower()
        for key, fix in fixes.items():
            if key in title_lower:
                return fix
        
        return 'Review and fix the identified security issue'
    
    def _get_default_reference(self, title: str) -> str:
        """Get default reference based on vulnerability title."""
        references = {
            'xss': 'https://owasp.org/www-community/attacks/xss/',
            'ssrf': 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
            'sql': 'https://owasp.org/www-community/attacks/SQL_Injection',
            'csrf': 'https://owasp.org/www-community/attacks/csrf',
            'headers': 'https://owasp.org/www-project-secure-headers/',
            'csp': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
        }
        
        title_lower = title.lower()
        for key, ref in references.items():
            if key in title_lower:
                return ref
        
        return 'https://owasp.org/www-community/'