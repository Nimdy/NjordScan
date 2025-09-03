"""
🛡️ Legacy Plugin System for NjordScan v1.0.0

Basic plugin loading system - maintained for backward compatibility.
For advanced plugin features, use the plugins_v2 system.
"""

import os
import sys
import importlib.util
import importlib
from pathlib import Path
from typing import Dict, Any, Type, List, Optional
from rich.console import Console
from dataclasses import dataclass

@dataclass
class PluginInfo:
    """Plugin information structure."""
    name: str
    version: str
    author: str
    description: str
    plugin_class: Type
    file_path: str
    enabled: bool = True
    plugin_type: str = "scanner"  # scanner or reporter

class PluginManager:
    """Legacy plugin manager - maintained for backward compatibility.
    
    For advanced features, use plugins_v2.PluginManager instead.
    """
    
    def __init__(self, plugin_dirs: List[str] = None):
        self.console = Console()
        self.loaded_plugins: Dict[str, PluginInfo] = {}
        
        if plugin_dirs is None:
            # Default plugin directories
            base_dir = Path(__file__).parent.parent
            self.plugin_dirs = [
                base_dir / 'plugins' / 'frameworks',
                base_dir / 'plugins' / 'libraries', 
                base_dir / 'plugins' / 'community',
                base_dir / 'plugins' / 'official'
            ]
        else:
            self.plugin_dirs = [Path(d) for d in plugin_dirs]
        
        # Create missing directories
        for plugin_dir in self.plugin_dirs:
            plugin_dir.mkdir(parents=True, exist_ok=True)
    
    def discover_plugins(self) -> Dict[str, PluginInfo]:
        """Discover all available plugins."""
        discovered = {}
        
        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                continue
                
            # Look for plugin subdirectories
            for plugin_subdir in plugin_dir.iterdir():
                if not plugin_subdir.is_dir():
                    continue
                
                # Skip template directories
                if plugin_subdir.name.startswith('template'):
                    continue
                
                try:
                    plugin_info = self._load_plugin_from_directory(plugin_subdir)
                    if plugin_info:
                        discovered[plugin_info.name] = plugin_info
                        
                except Exception as e:
                    if os.getenv('NJORDSCAN_DEBUG'):
                        self.console.print(f"[red]Failed to discover plugin {plugin_subdir}: {e}[/red]")
        
        return discovered
    
    def _load_plugin_from_directory(self, plugin_dir: Path) -> Optional[PluginInfo]:
        """Load plugin from a directory containing config.yaml and plugin files."""
        config_file = plugin_dir / 'config.yaml'
        if not config_file.exists():
            return None
        
        # Find Python files in the directory
        python_files = list(plugin_dir.glob('*.py'))
        python_files = [f for f in python_files if not f.name.startswith('__')]
        
        for plugin_file in python_files:
            try:
                plugin_info = self._load_plugin_info(plugin_file)
                if plugin_info:
                    return plugin_info
            except Exception:
                continue
        
        return None
    
    def load_plugins(self, enabled_plugins: List[str] = None) -> Dict[str, Type]:
        """Load enabled plugins."""
        available_plugins = self.discover_plugins()
        loaded = {}
        
        for plugin_name, plugin_info in available_plugins.items():
            # Check if plugin should be loaded
            if enabled_plugins and plugin_name not in enabled_plugins:
                continue
                
            if not plugin_info.enabled:
                continue
            
            try:
                plugin_class = self._load_plugin_class(plugin_info)
                if plugin_class:
                    loaded[plugin_name] = plugin_class
                    self.loaded_plugins[plugin_name] = plugin_info
                    
            except Exception as e:
                if os.getenv('NJORDSCAN_DEBUG'):
                    self.console.print(f"[red]Failed to load plugin {plugin_name}: {e}[/red]")
        
        return loaded
    
    def _load_plugin_info(self, plugin_file: Path) -> Optional[PluginInfo]:
        """Load plugin information from file."""
        try:
            # Try to load the plugin module
            spec = importlib.util.spec_from_file_location("temp_plugin", plugin_file)
            if not spec or not spec.loader:
                return None
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin class using duck typing
            plugin_class = None
            plugin_type = "scanner"
            
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    hasattr(attr, 'scan') and 
                    hasattr(attr, 'get_name') and
                    attr_name != 'ScannerPlugin'):
                    plugin_class = attr
                    plugin_type = "scanner"
                    break
                elif (isinstance(attr, type) and 
                      hasattr(attr, 'generate_report') and 
                      hasattr(attr, 'get_format_name') and
                      attr_name != 'ReporterPlugin'):
                    plugin_class = attr
                    plugin_type = "reporter"
                    break
            
            if not plugin_class:
                return None
            
            # Create temporary instance to get metadata
            try:
                temp_instance = plugin_class.__new__(plugin_class)
                name = getattr(temp_instance, 'get_name', lambda: plugin_file.stem)()
                version = getattr(temp_instance, 'get_version', lambda: '1.0.0')()
                
                # Try to get additional metadata
                metadata = {}
                if hasattr(temp_instance, 'get_metadata'):
                    try:
                        metadata = temp_instance.get_metadata()
                    except:
                        pass
                
                return PluginInfo(
                    name=name,
                    version=version,
                    author=metadata.get('author', 'Unknown'),
                    description=metadata.get('description', 'No description'),
                    plugin_class=plugin_class,
                    file_path=str(plugin_file),
                    plugin_type=plugin_type
                )
            except:
                return None
            
        except Exception:
            return None
    
    def _load_plugin_class(self, plugin_info: PluginInfo) -> Optional[Type]:
        """Load plugin class from plugin info."""
        return plugin_info.plugin_class
    
    def get_plugin_info(self, plugin_name: str) -> Optional[PluginInfo]:
        """Get information about a specific plugin."""
        return self.loaded_plugins.get(plugin_name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins."""
        return [
            {
                'name': info.name,
                'version': info.version,
                'author': info.author,
                'description': info.description,
                'file_path': info.file_path,
                'enabled': info.enabled,
                'type': info.plugin_type
            }
            for info in self.loaded_plugins.values()
        ]
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin."""
        if plugin_name in self.loaded_plugins:
            self.loaded_plugins[plugin_name].enabled = True
            return True
        return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin."""
        if plugin_name in self.loaded_plugins:
            self.loaded_plugins[plugin_name].enabled = False
            return True
        return False

class PluginLoader:
    """Legacy plugin loader for backward compatibility."""
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.manager = PluginManager()
    
    def load_plugins(self) -> Dict[str, Type]:
        """Load plugins using the new plugin manager."""
        return self.manager.load_plugins()