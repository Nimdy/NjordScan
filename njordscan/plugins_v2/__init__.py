"""
Advanced Plugin Ecosystem for NjordScan v2.

This module provides a comprehensive plugin architecture including:
- Dynamic plugin discovery and loading
- Plugin lifecycle management
- Dependency injection and service discovery
- Plugin marketplace and registry
- Hot-reload and runtime plugin management
- Plugin sandboxing and security
"""

from .plugin_manager import PluginManager
from .plugin_marketplace import PluginMarketplace
from .plugin_orchestrator import PluginOrchestrator

# Import PluginSecurityManager from plugin_orchestrator if available
try:
    from .plugin_orchestrator import PluginSecurityManager
except ImportError:
    PluginSecurityManager = None

__all__ = [
    'PluginManager',
    'PluginMarketplace',
    'PluginOrchestrator'
]

# Add PluginSecurityManager if available
if PluginSecurityManager:
    __all__.append('PluginSecurityManager')
