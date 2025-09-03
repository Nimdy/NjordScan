"""
Scanner Plugin Base Class

Base class for plugins that perform security scanning.
"""

from abc import abstractmethod
from typing import List, Dict, Any
from .base_plugin import BasePlugin

class ScannerPlugin(BasePlugin):
    """Base class for scanner plugins."""
    
    def __init__(self, config, vuln_id_generator):
        super().__init__(config, vuln_id_generator)
        self.name = self.get_name()
    
    @abstractmethod
    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Main scanning method that must be implemented."""
        pass
    
    def should_run(self, mode: str) -> bool:
        """Determine if plugin should run based on scan mode."""
        # Default implementation - can be overridden
        return mode in ['full']
    
    def is_framework_supported(self, framework: str) -> bool:
        """Check if plugin supports the framework."""
        return self.supports_framework(framework)
    
    async def pre_scan_validation(self, target: str) -> bool:
        """Validate target before scanning."""
        return True
    
    async def post_scan_processing(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process vulnerabilities after scanning."""
        return vulnerabilities
    
    def should_skip_file(self, file_path) -> bool:
        """Check if file should be skipped during scanning."""
        from pathlib import Path
        
        file_path = Path(file_path)
        skip_dirs = {'node_modules', '.git', '.next', 'dist', 'build', '__pycache__'}
        
        # Check if file is in a skip directory
        for part in file_path.parts:
            if part in skip_dirs:
                return True
        
        # Skip minified files
        if '.min.' in file_path.name:
            return True
        
        # Skip source maps
        if file_path.name.endswith('.map'):
            return True
        
        # Skip very large files
        try:
            if file_path.stat().st_size > 1024 * 1024:  # 1MB
                return True
        except OSError:
            return True
        
        return False