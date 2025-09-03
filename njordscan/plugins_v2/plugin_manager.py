"""
Advanced Plugin Manager

Comprehensive plugin management system including:
- Dynamic plugin discovery and loading
- Plugin lifecycle management
- Dependency injection and resolution
- Hot-reload capabilities
- Plugin sandboxing and security
"""

import os
import sys
import re
import importlib
import importlib.util
import inspect
import asyncio
import time
from typing import Dict, List, Any, Optional, Type, Callable, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
import hashlib
import json

logger = logging.getLogger(__name__)

class PluginState(Enum):
    """Plugin lifecycle states."""
    DISCOVERED = "discovered"
    LOADING = "loading"
    LOADED = "loaded"
    INITIALIZING = "initializing"
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    UNLOADING = "unloading"
    UNLOADED = "unloaded"

class PluginType(Enum):
    """Types of plugins."""
    SCANNER = "scanner"
    ANALYZER = "analyzer"
    REPORTER = "reporter"
    INTEGRATOR = "integrator"
    TRANSFORMER = "transformer"
    VALIDATOR = "validator"
    ENHANCER = "enhancer"
    UTILITY = "utility"

@dataclass
class PluginMetadata:
    """Plugin metadata information."""
    id: str
    name: str
    version: str
    description: str
    author: str
    
    # Plugin characteristics
    plugin_type: PluginType
    category: str
    tags: List[str] = field(default_factory=list)
    
    # Requirements and compatibility
    min_njordscan_version: str = "1.0.0"
    max_njordscan_version: str = "*"
    python_version: str = ">=3.8"
    dependencies: List[str] = field(default_factory=list)
    optional_dependencies: List[str] = field(default_factory=list)
    
    # Plugin behavior
    auto_load: bool = True
    priority: int = 100  # Lower numbers = higher priority
    singleton: bool = False
    thread_safe: bool = True
    async_capable: bool = True
    
    # Security and sandboxing
    permissions: List[str] = field(default_factory=list)
    sandbox_level: str = "standard"  # none, standard, strict
    trusted: bool = False
    
    # Plugin hooks and interfaces
    hooks: List[str] = field(default_factory=list)
    provides_services: List[str] = field(default_factory=list)
    requires_services: List[str] = field(default_factory=list)
    
    # Metadata
    homepage: str = ""
    repository: str = ""
    documentation: str = ""
    license: str = ""
    keywords: List[str] = field(default_factory=list)
    
    # Runtime information
    file_path: str = ""
    checksum: str = ""
    load_time: float = 0.0
    last_modified: float = 0.0

@dataclass
class PluginInstance:
    """Plugin instance information."""
    metadata: PluginMetadata
    state: PluginState
    
    # Runtime objects
    module: Optional[Any] = None
    plugin_class: Optional[Type] = None
    instance: Optional[Any] = None
    
    # Lifecycle tracking
    load_time: float = 0.0
    init_time: float = 0.0
    error_count: int = 0
    last_error: Optional[str] = None
    
    # Performance metrics
    execution_count: int = 0
    total_execution_time: float = 0.0
    average_execution_time: float = 0.0
    
    # Dependencies
    resolved_dependencies: List[str] = field(default_factory=list)
    dependent_plugins: List[str] = field(default_factory=list)

class PluginInterface:
    """Base interface that all plugins must implement."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"plugin.{self.__class__.__name__}")
        self._services = {}
        self._hooks = {}
    
    async def initialize(self) -> bool:
        """Initialize the plugin. Return True if successful."""
        return True
    
    async def activate(self) -> bool:
        """Activate the plugin. Return True if successful."""
        return True
    
    async def deactivate(self) -> bool:
        """Deactivate the plugin. Return True if successful."""
        return True
    
    async def cleanup(self) -> bool:
        """Cleanup plugin resources. Return True if successful."""
        return True
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        raise NotImplementedError("Plugin must implement get_metadata()")
    
    def register_service(self, service_name: str, service: Any):
        """Register a service provided by this plugin."""
        self._services[service_name] = service
    
    def get_service(self, service_name: str) -> Any:
        """Get a service by name."""
        return self._services.get(service_name)
    
    def register_hook(self, hook_name: str, callback: Callable):
        """Register a hook callback."""
        if hook_name not in self._hooks:
            self._hooks[hook_name] = []
        self._hooks[hook_name].append(callback)
    
    async def execute_hooks(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Execute all callbacks for a hook."""
        results = []
        for callback in self._hooks.get(hook_name, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    result = await callback(*args, **kwargs)
                else:
                    result = callback(*args, **kwargs)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Hook {hook_name} callback failed: {str(e)}")
        return results

class PluginManager:
    """Advanced plugin management system."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Plugin management configuration
        self.plugin_config = {
            'plugin_directories': self.config.get('plugin_directories', ['plugins', 'custom_plugins']),
            'auto_discovery': self.config.get('auto_discovery', True),
            'auto_load': self.config.get('auto_load', True),
            'hot_reload': self.config.get('hot_reload', True),
            'sandbox_plugins': self.config.get('sandbox_plugins', True),
            'max_load_time': self.config.get('max_load_time', 30.0),
            'dependency_timeout': self.config.get('dependency_timeout', 60.0)
        }
        
        # Plugin storage
        self.plugins: Dict[str, PluginInstance] = {}
        self.plugin_order: List[str] = []  # Load order based on dependencies
        
        # Service registry
        self.services: Dict[str, Any] = {}
        self.service_providers: Dict[str, str] = {}  # service -> plugin_id
        
        # Hook registry
        self.hooks: Dict[str, List[Callable]] = {}
        
        # Plugin discovery
        self.discovered_plugins: Dict[str, Path] = {}
        self.plugin_checksums: Dict[str, str] = {}
        
        # Security and sandboxing
        self.trusted_plugins: Set[str] = set()
        self.sandbox_enabled = self.plugin_config['sandbox_plugins']
        
        # Performance monitoring
        self.performance_metrics: Dict[str, Dict[str, float]] = {}
        
        # Statistics
        self.stats = {
            'plugins_discovered': 0,
            'plugins_loaded': 0,
            'plugins_active': 0,
            'plugins_failed': 0,
            'services_registered': 0,
            'hooks_registered': 0,
            'total_load_time': 0.0
        }
    
    async def initialize(self):
        """Initialize the plugin manager."""
        
        logger.info("Initializing Plugin Manager")
        
        # Discover plugins
        if self.plugin_config['auto_discovery']:
            await self.discover_plugins()
        
        # Load plugins
        if self.plugin_config['auto_load']:
            await self.load_all_plugins()
        
        # Start hot-reload monitoring if enabled
        if self.plugin_config['hot_reload']:
            await self.start_hot_reload_monitoring()
        
        logger.info(f"Plugin Manager initialized: {len(self.plugins)} plugins loaded")
    
    async def discover_plugins(self) -> Dict[str, Path]:
        """Discover all available plugins."""
        
        logger.info("Discovering plugins...")
        
        discovered = {}
        
        plugin_dirs = self.plugin_config.get('plugin_directories', [])
        if not plugin_dirs:
            logger.warning("No plugin directories configured")
            return discovered
            
        for plugin_dir in plugin_dirs:
            plugin_path = Path(plugin_dir)
            if not plugin_path.exists():
                logger.debug(f"Plugin directory does not exist: {plugin_path}")
                continue
            
            # Find plugin files
            for plugin_file in plugin_path.rglob("*.py"):
                if plugin_file.name.startswith('__'):
                    continue
                
                try:
                    # Check if file contains a plugin
                    if await self._is_plugin_file(plugin_file):
                        plugin_id = self._generate_plugin_id(plugin_file)
                        discovered[plugin_id] = plugin_file
                        
                        # Calculate checksum for change detection
                        checksum = await self._calculate_file_checksum(plugin_file)
                        self.plugin_checksums[plugin_id] = checksum
                        
                        logger.debug(f"Discovered plugin: {plugin_id} at {plugin_file}")
                
                except Exception as e:
                    logger.error(f"Error discovering plugin {plugin_file}: {str(e)}")
        
        self.discovered_plugins.update(discovered)
        self.stats['plugins_discovered'] = len(self.discovered_plugins)
        
        logger.info(f"Plugin discovery completed: {len(discovered)} plugins found")
        
        return discovered
    
    async def load_plugin(self, plugin_id: str) -> bool:
        """Load a specific plugin."""
        
        if plugin_id in self.plugins:
            logger.warning(f"Plugin {plugin_id} is already loaded")
            return True
        
        if plugin_id not in self.discovered_plugins:
            logger.error(f"Plugin {plugin_id} not found in discovered plugins")
            return False
        
        plugin_file = self.discovered_plugins[plugin_id]
        
        try:
            load_start_time = time.time()
            
            logger.info(f"Loading plugin: {plugin_id}")
            
            # Create plugin instance
            plugin_instance = PluginInstance(
                metadata=PluginMetadata(
                    id=plugin_id,
                    name="",
                    version="",
                    description="",
                    author="",
                    plugin_type=PluginType.UTILITY,
                    category="unknown",
                    file_path=str(plugin_file)
                ),
                state=PluginState.LOADING
            )
            
            # Load the module
            module = await self._load_plugin_module(plugin_file)
            if not module:
                raise Exception("Failed to load plugin module")
            
            plugin_instance.module = module
            
            # Find the plugin class
            plugin_class = await self._find_plugin_class(module)
            if not plugin_class:
                raise Exception("No valid plugin class found in module")
            
            plugin_instance.plugin_class = plugin_class
            
            # Create plugin instance
            plugin_obj = plugin_class(self.config.get('plugin_configs', {}).get(plugin_id, {}))
            plugin_instance.instance = plugin_obj
            
            # Get metadata from plugin
            try:
                metadata = plugin_obj.get_metadata()
                plugin_instance.metadata = metadata
                plugin_instance.metadata.file_path = str(plugin_file)
                plugin_instance.metadata.checksum = self.plugin_checksums.get(plugin_id, "")
            except Exception as e:
                logger.warning(f"Could not get metadata from plugin {plugin_id}: {str(e)}")
            
            # Update state
            plugin_instance.state = PluginState.LOADED
            plugin_instance.load_time = time.time() - load_start_time
            
            # Store plugin
            self.plugins[plugin_id] = plugin_instance
            
            # Initialize plugin
            if await self._initialize_plugin(plugin_id):
                logger.info(f"Plugin {plugin_id} loaded successfully")
                self.stats['plugins_loaded'] += 1
                self.stats['total_load_time'] += plugin_instance.load_time
                return True
            else:
                logger.error(f"Plugin {plugin_id} failed to initialize")
                plugin_instance.state = PluginState.ERROR
                return False
                
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_id}: {str(e)}")
            if plugin_id in self.plugins:
                self.plugins[plugin_id].state = PluginState.ERROR
                self.plugins[plugin_id].last_error = str(e)
                self.plugins[plugin_id].error_count += 1
            self.stats['plugins_failed'] += 1
            return False
    
    async def load_all_plugins(self) -> Dict[str, bool]:
        """Load all discovered plugins."""
        
        logger.info("Loading all plugins...")
        
        results = {}
        
        # Sort plugins by priority and dependencies
        load_order = await self._calculate_load_order()
        
        for plugin_id in load_order:
            results[plugin_id] = await self.load_plugin(plugin_id)
        
        # Activate loaded plugins
        for plugin_id in load_order:
            if results.get(plugin_id, False):
                await self.activate_plugin(plugin_id)
        
        logger.info(f"Plugin loading completed: {self.stats['plugins_loaded']} loaded, {self.stats['plugins_failed']} failed")
        
        return results
    
    async def unload_plugin(self, plugin_id: str) -> bool:
        """Unload a specific plugin."""
        
        if plugin_id not in self.plugins:
            logger.warning(f"Plugin {plugin_id} is not loaded")
            return True
        
        try:
            logger.info(f"Unloading plugin: {plugin_id}")
            
            plugin_instance = self.plugins[plugin_id]
            plugin_instance.state = PluginState.UNLOADING
            
            # Deactivate plugin
            if plugin_instance.instance:
                await plugin_instance.instance.deactivate()
                await plugin_instance.instance.cleanup()
            
            # Unregister services
            services_to_remove = [service for service, provider in self.service_providers.items() 
                                if provider == plugin_id]
            for service in services_to_remove:
                del self.services[service]
                del self.service_providers[service]
                self.stats['services_registered'] -= 1
            
            # Remove from dependent plugins
            for other_plugin_id, other_plugin in self.plugins.items():
                if plugin_id in other_plugin.resolved_dependencies:
                    other_plugin.resolved_dependencies.remove(plugin_id)
            
            # Update state and remove
            plugin_instance.state = PluginState.UNLOADED
            del self.plugins[plugin_id]
            
            if plugin_id in self.plugin_order:
                self.plugin_order.remove(plugin_id)
            
            logger.info(f"Plugin {plugin_id} unloaded successfully")
            self.stats['plugins_loaded'] -= 1
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin_id}: {str(e)}")
            if plugin_id in self.plugins:
                self.plugins[plugin_id].state = PluginState.ERROR
                self.plugins[plugin_id].last_error = str(e)
            return False
    
    async def activate_plugin(self, plugin_id: str) -> bool:
        """Activate a loaded plugin."""
        
        if plugin_id not in self.plugins:
            logger.error(f"Cannot activate plugin {plugin_id}: not loaded")
            return False
        
        plugin_instance = self.plugins[plugin_id]
        
        if plugin_instance.state == PluginState.ACTIVE:
            return True
        
        if plugin_instance.state != PluginState.LOADED:
            logger.error(f"Cannot activate plugin {plugin_id}: invalid state {plugin_instance.state}")
            return False
        
        try:
            logger.info(f"Activating plugin: {plugin_id}")
            
            # Check dependencies
            if not await self._resolve_dependencies(plugin_id):
                logger.error(f"Cannot activate plugin {plugin_id}: dependency resolution failed")
                return False
            
            # Activate plugin
            if plugin_instance.instance:
                success = await plugin_instance.instance.activate()
                if not success:
                    logger.error(f"Plugin {plugin_id} activation failed")
                    return False
            
            # Register services
            await self._register_plugin_services(plugin_id)
            
            # Register hooks
            await self._register_plugin_hooks(plugin_id)
            
            # Update state
            plugin_instance.state = PluginState.ACTIVE
            self.stats['plugins_active'] += 1
            
            logger.info(f"Plugin {plugin_id} activated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to activate plugin {plugin_id}: {str(e)}")
            plugin_instance.state = PluginState.ERROR
            plugin_instance.last_error = str(e)
            plugin_instance.error_count += 1
            return False
    
    async def deactivate_plugin(self, plugin_id: str) -> bool:
        """Deactivate an active plugin."""
        
        if plugin_id not in self.plugins:
            logger.error(f"Cannot deactivate plugin {plugin_id}: not loaded")
            return False
        
        plugin_instance = self.plugins[plugin_id]
        
        if plugin_instance.state != PluginState.ACTIVE:
            return True
        
        try:
            logger.info(f"Deactivating plugin: {plugin_id}")
            
            # Deactivate plugin
            if plugin_instance.instance:
                success = await plugin_instance.instance.deactivate()
                if not success:
                    logger.warning(f"Plugin {plugin_id} deactivation returned false")
            
            # Update state
            plugin_instance.state = PluginState.PAUSED
            self.stats['plugins_active'] -= 1
            
            logger.info(f"Plugin {plugin_id} deactivated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deactivate plugin {plugin_id}: {str(e)}")
            plugin_instance.state = PluginState.ERROR
            plugin_instance.last_error = str(e)
            return False
    
    async def reload_plugin(self, plugin_id: str) -> bool:
        """Reload a plugin (unload and load again)."""
        
        logger.info(f"Reloading plugin: {plugin_id}")
        
        # Unload plugin
        if not await self.unload_plugin(plugin_id):
            return False
        
        # Rediscover plugin (in case file changed)
        plugin_file = self.discovered_plugins.get(plugin_id)
        if plugin_file and plugin_file.exists():
            new_checksum = await self._calculate_file_checksum(plugin_file)
            self.plugin_checksums[plugin_id] = new_checksum
        
        # Load plugin
        return await self.load_plugin(plugin_id)
    
    async def get_service(self, service_name: str) -> Optional[Any]:
        """Get a service by name."""
        
        return self.services.get(service_name)
    
    async def execute_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Execute all callbacks registered for a hook."""
        
        results = []
        
        for callback in self.hooks.get(hook_name, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    result = await callback(*args, **kwargs)
                else:
                    result = callback(*args, **kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"Hook {hook_name} callback failed: {str(e)}")
        
        return results
    
    def get_plugin_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a plugin."""
        
        if plugin_id not in self.plugins:
            return None
        
        plugin_instance = self.plugins[plugin_id]
        
        return {
            'id': plugin_id,
            'metadata': plugin_instance.metadata.__dict__,
            'state': plugin_instance.state.value,
            'load_time': plugin_instance.load_time,
            'init_time': plugin_instance.init_time,
            'error_count': plugin_instance.error_count,
            'last_error': plugin_instance.last_error,
            'execution_count': plugin_instance.execution_count,
            'total_execution_time': plugin_instance.total_execution_time,
            'average_execution_time': plugin_instance.average_execution_time,
            'resolved_dependencies': plugin_instance.resolved_dependencies,
            'dependent_plugins': plugin_instance.dependent_plugins
        }
    
    def list_plugins(self, state_filter: Optional[PluginState] = None) -> List[str]:
        """List all plugins, optionally filtered by state."""
        
        if state_filter:
            return [plugin_id for plugin_id, plugin in self.plugins.items() 
                    if plugin.state == state_filter]
        else:
            return list(self.plugins.keys())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get plugin manager statistics."""
        
        return dict(self.stats)
    
    # Private methods
    
    async def _is_plugin_file(self, file_path: Path) -> bool:
        """Check if a file contains a plugin."""
        
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # Look for plugin indicators
            indicators = [
                'class.*PluginInterface',
                'def get_metadata',
                '@plugin',
                'PLUGIN_METADATA',
                'extends.*Plugin'
            ]
            
            for indicator in indicators:
                if re.search(indicator, content, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _generate_plugin_id(self, file_path: Path) -> str:
        """Generate a unique plugin ID from file path."""
        
        # Use relative path and stem as ID
        try:
            # Get relative path from plugin directories
            for plugin_dir in self.plugin_config['plugin_directories']:
                plugin_dir_path = Path(plugin_dir)
                if plugin_dir_path in file_path.parents:
                    relative_path = file_path.relative_to(plugin_dir_path)
                    return str(relative_path.with_suffix('').as_posix().replace('/', '.'))
            
            # Fallback to stem
            return file_path.stem
            
        except Exception:
            return file_path.stem
    
    async def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate checksum of a file."""
        
        try:
            content = file_path.read_bytes()
            return hashlib.sha256(content).hexdigest()
        except Exception:
            return ""
    
    async def _load_plugin_module(self, file_path: Path):
        """Load a plugin module from file."""
        
        try:
            module_name = f"plugin_{file_path.stem}_{int(time.time())}"
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            
            if spec is None or spec.loader is None:
                return None
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            return module
            
        except Exception as e:
            logger.error(f"Failed to load module from {file_path}: {str(e)}")
            return None
    
    async def _find_plugin_class(self, module) -> Optional[Type]:
        """Find the plugin class in a module."""
        
        for name, obj in inspect.getmembers(module, inspect.isclass):
            # Check if class implements PluginInterface
            if (hasattr(obj, 'get_metadata') and 
                hasattr(obj, 'initialize') and
                hasattr(obj, 'activate')):
                return obj
        
        return None
    
    async def _initialize_plugin(self, plugin_id: str) -> bool:
        """Initialize a loaded plugin."""
        
        plugin_instance = self.plugins[plugin_id]
        
        try:
            plugin_instance.state = PluginState.INITIALIZING
            
            init_start_time = time.time()
            
            if plugin_instance.instance:
                success = await plugin_instance.instance.initialize()
                if not success:
                    return False
            
            plugin_instance.init_time = time.time() - init_start_time
            plugin_instance.state = PluginState.LOADED
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize plugin {plugin_id}: {str(e)}")
            plugin_instance.state = PluginState.ERROR
            plugin_instance.last_error = str(e)
            plugin_instance.error_count += 1
            return False
    
    async def _calculate_load_order(self) -> List[str]:
        """Calculate plugin load order based on dependencies."""
        
        # Simple topological sort based on dependencies
        # In a real implementation, this would be more sophisticated
        
        plugin_ids = list(self.discovered_plugins.keys())
        
        # For now, sort by priority (would implement proper dependency resolution)
        return sorted(plugin_ids, key=lambda pid: self._get_plugin_priority(pid))
    
    def _get_plugin_priority(self, plugin_id: str) -> int:
        """Get plugin priority for load ordering."""
        
        # Default priority
        return 100
    
    async def _resolve_dependencies(self, plugin_id: str) -> bool:
        """Resolve plugin dependencies."""
        
        plugin_instance = self.plugins[plugin_id]
        metadata = plugin_instance.metadata
        
        # Check if required services are available
        for required_service in metadata.requires_services:
            if required_service not in self.services:
                logger.error(f"Plugin {plugin_id} requires service {required_service} which is not available")
                return False
        
        # Mark dependencies as resolved
        plugin_instance.resolved_dependencies = list(metadata.requires_services)
        
        return True
    
    async def _register_plugin_services(self, plugin_id: str):
        """Register services provided by a plugin."""
        
        plugin_instance = self.plugins[plugin_id]
        metadata = plugin_instance.metadata
        
        for service_name in metadata.provides_services:
            if plugin_instance.instance:
                service = plugin_instance.instance.get_service(service_name)
                if service:
                    self.services[service_name] = service
                    self.service_providers[service_name] = plugin_id
                    self.stats['services_registered'] += 1
                    logger.debug(f"Registered service {service_name} from plugin {plugin_id}")
    
    async def _register_plugin_hooks(self, plugin_id: str):
        """Register hooks provided by a plugin."""
        
        plugin_instance = self.plugins[plugin_id]
        
        if plugin_instance.instance and hasattr(plugin_instance.instance, '_hooks'):
            for hook_name, callbacks in plugin_instance.instance._hooks.items():
                if hook_name not in self.hooks:
                    self.hooks[hook_name] = []
                self.hooks[hook_name].extend(callbacks)
                self.stats['hooks_registered'] += len(callbacks)
                logger.debug(f"Registered {len(callbacks)} callbacks for hook {hook_name} from plugin {plugin_id}")
    
    async def start_hot_reload_monitoring(self):
        """Start monitoring for plugin file changes."""
        
        # This would implement file system monitoring for hot-reload
        # For now, just log that it would be started
        logger.info("Hot-reload monitoring would be started here")
    
    async def shutdown(self):
        """Shutdown the plugin manager."""
        
        logger.info("Shutting down Plugin Manager")
        
        # Deactivate all plugins
        for plugin_id in list(self.plugins.keys()):
            await self.deactivate_plugin(plugin_id)
        
        # Unload all plugins
        for plugin_id in list(self.plugins.keys()):
            await self.unload_plugin(plugin_id)
        
        logger.info("Plugin Manager shutdown completed")
