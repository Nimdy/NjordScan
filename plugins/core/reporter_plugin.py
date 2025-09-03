"""
Reporter Plugin Base Class

Base class for plugins that generate custom report formats.
"""

from abc import abstractmethod
from typing import Dict, Any
from .base_plugin import BasePlugin

class ReporterPlugin(BasePlugin):
    """Base class for reporter plugins."""
    
    @abstractmethod
    def get_format_name(self) -> str:
        """Return the format name (e.g., 'pdf', 'xml', 'slack')."""
        pass
    
    @abstractmethod
    async def generate_report(self, results: Dict[str, Any], output_path: str) -> bool:
        """Generate report in the plugin's format."""
        pass
    
    def supports_format(self, format_name: str) -> bool:
        """Check if plugin supports the given format."""
        return format_name.lower() == self.get_format_name().lower()
    
    def get_file_extension(self) -> str:
        """Return default file extension for this format."""
        return f".{self.get_format_name()}"
    
    def validate_output_path(self, output_path: str) -> bool:
        """Validate output path for this format."""
        return output_path.endswith(self.get_file_extension())