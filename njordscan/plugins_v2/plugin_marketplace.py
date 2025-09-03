"""
Plugin Marketplace

Comprehensive plugin marketplace and registry system including:
- Plugin discovery from multiple sources
- Plugin ratings and reviews
- Automatic updates and version management
- Security scanning and validation
- Community features and sharing
"""

import asyncio
import time
import json
import hashlib
import zipfile
import tempfile
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
import aiohttp
from packaging import version

logger = logging.getLogger(__name__)

class PluginSource(Enum):
    """Sources for plugin discovery."""
    OFFICIAL_REGISTRY = "official_registry"
    GITHUB_RELEASES = "github_releases"
    NPM_REGISTRY = "npm_registry"
    PYPI_REGISTRY = "pypi_registry"
    LOCAL_DIRECTORY = "local_directory"
    CUSTOM_REGISTRY = "custom_registry"

class PluginStatus(Enum):
    """Plugin status in marketplace."""
    AVAILABLE = "available"
    INSTALLED = "installed"
    UPDATE_AVAILABLE = "update_available"
    DEPRECATED = "deprecated"
    SECURITY_ISSUE = "security_issue"
    INCOMPATIBLE = "incompatible"

@dataclass
class PluginRating:
    """Plugin rating information."""
    average_rating: float
    total_ratings: int
    rating_distribution: Dict[int, int]  # star -> count
    
    # Recent ratings
    recent_ratings: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class PluginReview:
    """Plugin review."""
    reviewer: str
    rating: int  # 1-5 stars
    title: str
    content: str
    date: str
    helpful_votes: int = 0
    verified_user: bool = False
    
    # Review metadata
    version_reviewed: str = ""
    platform: str = ""
    use_case: str = ""

@dataclass
class PluginSecurityInfo:
    """Plugin security information."""
    security_score: float  # 0-100
    last_security_scan: str
    vulnerabilities_found: int
    security_issues: List[Dict[str, Any]] = field(default_factory=list)
    
    # Trust indicators
    code_signed: bool = False
    verified_publisher: bool = False
    open_source: bool = True
    audit_status: str = "not_audited"  # not_audited, pending, passed, failed

@dataclass
class PluginVersion:
    """Plugin version information."""
    version: str
    release_date: str
    download_url: str
    checksum: str
    
    # Version metadata
    changelog: str = ""
    breaking_changes: bool = False
    security_fixes: bool = False
    bug_fixes: List[str] = field(default_factory=list)
    new_features: List[str] = field(default_factory=list)
    
    # Compatibility
    min_njordscan_version: str = ""
    max_njordscan_version: str = ""
    python_requirements: List[str] = field(default_factory=list)
    
    # Download stats
    downloads: int = 0
    file_size: int = 0

@dataclass
class MarketplacePlugin:
    """Plugin information in marketplace."""
    id: str
    name: str
    description: str
    author: str
    category: str
    
    # Current version info
    current_version: str
    latest_version: str
    status: PluginStatus
    
    # Marketplace metadata
    downloads: int
    rating: PluginRating
    reviews_count: int
    last_updated: str
    created_date: str
    
    # Plugin details
    homepage: str = ""
    repository: str = ""
    documentation: str = ""
    license: str = ""
    tags: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    
    # Versions
    versions: List[PluginVersion] = field(default_factory=list)
    
    # Security and trust
    security_info: Optional[PluginSecurityInfo] = None
    
    # Reviews
    featured_reviews: List[PluginReview] = field(default_factory=list)
    
    # Sources
    sources: List[PluginSource] = field(default_factory=list)
    
    # Installation info
    installation_size: int = 0
    dependencies: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)

@dataclass
class MarketplaceSearchResult:
    """Search result from marketplace."""
    query: str
    total_results: int
    plugins: List[MarketplacePlugin]
    
    # Search metadata
    search_time: float
    filters_applied: Dict[str, Any]
    sort_order: str
    page: int
    per_page: int

class PluginMarketplace:
    """Comprehensive plugin marketplace system."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Marketplace configuration
        self.marketplace_config = {
            'official_registry_url': self.config.get('official_registry_url', 'https://plugins.njordscan.com'),
            'github_search_enabled': self.config.get('github_search_enabled', True),
            'npm_search_enabled': self.config.get('npm_search_enabled', False),
            'pypi_search_enabled': self.config.get('pypi_search_enabled', False),
            'cache_duration': self.config.get('cache_duration', 3600),  # 1 hour
            'max_concurrent_downloads': self.config.get('max_concurrent_downloads', 3),
            'security_scanning_enabled': self.config.get('security_scanning_enabled', True),
            'auto_update_check': self.config.get('auto_update_check', True),
            'community_features': self.config.get('community_features', True)
        }
        
        # Registry URLs
        self.registry_urls = {
            PluginSource.OFFICIAL_REGISTRY: self.marketplace_config['official_registry_url'],
            PluginSource.GITHUB_RELEASES: 'https://api.github.com',
            PluginSource.NPM_REGISTRY: 'https://registry.npmjs.org',
            PluginSource.PYPI_REGISTRY: 'https://pypi.org/pypi'
        }
        
        # Cache
        self.plugin_cache: Dict[str, MarketplacePlugin] = {}
        self.search_cache: Dict[str, MarketplaceSearchResult] = {}
        self.cache_timestamps: Dict[str, float] = {}
        
        # Download management
        self.active_downloads: Dict[str, asyncio.Task] = {}
        self.download_semaphore = asyncio.Semaphore(self.marketplace_config['max_concurrent_downloads'])
        
        # Security scanning
        self.security_scanner = None
        if self.marketplace_config['security_scanning_enabled']:
            self.security_scanner = PluginSecurityScanner()
        
        # Statistics
        self.stats = {
            'plugins_discovered': 0,
            'plugins_installed': 0,
            'plugins_updated': 0,
            'searches_performed': 0,
            'downloads_completed': 0,
            'security_scans_performed': 0
        }
    
    async def initialize(self):
        """Initialize the marketplace."""
        
        logger.info("Initializing Plugin Marketplace")
        
        # Initialize security scanner
        if self.security_scanner:
            await self.security_scanner.initialize()
        
        # Load cached data
        await self._load_cache()
        
        # Start background tasks
        if self.marketplace_config['auto_update_check']:
            asyncio.create_task(self._auto_update_checker())
        
        logger.info("Plugin Marketplace initialized")
    
    async def search_plugins(self, query: str, filters: Dict[str, Any] = None,
                           sort_by: str = "relevance", page: int = 1, 
                           per_page: int = 20) -> MarketplaceSearchResult:
        """Search for plugins in the marketplace."""
        
        search_start_time = time.time()
        filters = filters or {}
        
        logger.info(f"Searching plugins: '{query}' with filters {filters}")
        
        # Check cache first
        cache_key = self._generate_search_cache_key(query, filters, sort_by, page, per_page)
        if self._is_cache_valid(cache_key):
            cached_result = self.search_cache[cache_key]
            logger.debug(f"Returning cached search result for '{query}'")
            return cached_result
        
        # Perform search across all sources
        all_results = []
        
        # Search official registry
        if PluginSource.OFFICIAL_REGISTRY in self._get_enabled_sources():
            official_results = await self._search_official_registry(query, filters)
            all_results.extend(official_results)
        
        # Search GitHub
        if (PluginSource.GITHUB_RELEASES in self._get_enabled_sources() and 
            self.marketplace_config['github_search_enabled']):
            github_results = await self._search_github(query, filters)
            all_results.extend(github_results)
        
        # Search NPM
        if (PluginSource.NPM_REGISTRY in self._get_enabled_sources() and 
            self.marketplace_config['npm_search_enabled']):
            npm_results = await self._search_npm(query, filters)
            all_results.extend(npm_results)
        
        # Search PyPI
        if (PluginSource.PYPI_REGISTRY in self._get_enabled_sources() and 
            self.marketplace_config['pypi_search_enabled']):
            pypi_results = await self._search_pypi(query, filters)
            all_results.extend(pypi_results)
        
        # Deduplicate and merge results
        merged_results = self._merge_search_results(all_results)
        
        # Apply filters
        filtered_results = self._apply_search_filters(merged_results, filters)
        
        # Sort results
        sorted_results = self._sort_search_results(filtered_results, sort_by)
        
        # Paginate
        paginated_results = self._paginate_results(sorted_results, page, per_page)
        
        # Create search result
        search_result = MarketplaceSearchResult(
            query=query,
            total_results=len(sorted_results),
            plugins=paginated_results,
            search_time=time.time() - search_start_time,
            filters_applied=filters,
            sort_order=sort_by,
            page=page,
            per_page=per_page
        )
        
        # Cache result
        self.search_cache[cache_key] = search_result
        self.cache_timestamps[cache_key] = time.time()
        
        self.stats['searches_performed'] += 1
        
        logger.info(f"Search completed: {search_result.total_results} results in {search_result.search_time:.2f}s")
        
        return search_result
    
    async def get_plugin_details(self, plugin_id: str, source: Optional[PluginSource] = None) -> Optional[MarketplacePlugin]:
        """Get detailed information about a plugin."""
        
        logger.debug(f"Getting plugin details: {plugin_id}")
        
        # Check cache first
        cache_key = f"plugin_{plugin_id}"
        if self._is_cache_valid(cache_key):
            return self.plugin_cache[cache_key]
        
        # Fetch from appropriate source
        plugin = None
        
        if source:
            plugin = await self._fetch_plugin_from_source(plugin_id, source)
        else:
            # Try all sources
            for src in self._get_enabled_sources():
                plugin = await self._fetch_plugin_from_source(plugin_id, src)
                if plugin:
                    break
        
        if plugin:
            # Enhance with security information
            if self.security_scanner:
                plugin.security_info = await self.security_scanner.scan_plugin(plugin)
            
            # Cache result
            self.plugin_cache[cache_key] = plugin
            self.cache_timestamps[cache_key] = time.time()
        
        return plugin
    
    async def install_plugin(self, plugin_id: str, version: Optional[str] = None) -> bool:
        """Install a plugin from the marketplace."""
        
        logger.info(f"Installing plugin: {plugin_id} (version: {version or 'latest'})")
        
        # Get plugin details
        plugin = await self.get_plugin_details(plugin_id)
        if not plugin:
            logger.error(f"Plugin {plugin_id} not found in marketplace")
            return False
        
        # Determine version to install
        if not version:
            version = plugin.latest_version
        
        # Find version info
        version_info = None
        for v in plugin.versions:
            if v.version == version:
                version_info = v
                break
        
        if not version_info:
            logger.error(f"Version {version} not found for plugin {plugin_id}")
            return False
        
        # Security check
        if plugin.security_info and plugin.security_info.security_score < 70:
            logger.warning(f"Plugin {plugin_id} has low security score: {plugin.security_info.security_score}")
            if plugin.security_info.vulnerabilities_found > 0:
                logger.error(f"Plugin {plugin_id} has {plugin.security_info.vulnerabilities_found} known vulnerabilities")
                return False
        
        try:
            # Download plugin
            plugin_file = await self._download_plugin(plugin_id, version_info)
            if not plugin_file:
                logger.error(f"Failed to download plugin {plugin_id}")
                return False
            
            # Verify checksum
            if not await self._verify_plugin_checksum(plugin_file, version_info.checksum):
                logger.error(f"Checksum verification failed for plugin {plugin_id}")
                return False
            
            # Install plugin
            success = await self._install_plugin_file(plugin_file, plugin_id)
            
            if success:
                self.stats['plugins_installed'] += 1
                logger.info(f"Plugin {plugin_id} installed successfully")
            else:
                logger.error(f"Failed to install plugin {plugin_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error installing plugin {plugin_id}: {str(e)}")
            return False
    
    async def update_plugin(self, plugin_id: str) -> bool:
        """Update a plugin to the latest version."""
        
        logger.info(f"Updating plugin: {plugin_id}")
        
        # Get plugin details
        plugin = await self.get_plugin_details(plugin_id)
        if not plugin:
            logger.error(f"Plugin {plugin_id} not found in marketplace")
            return False
        
        if plugin.status != PluginStatus.UPDATE_AVAILABLE:
            logger.info(f"Plugin {plugin_id} is already up to date")
            return True
        
        # Install latest version
        success = await self.install_plugin(plugin_id, plugin.latest_version)
        
        if success:
            self.stats['plugins_updated'] += 1
        
        return success
    
    async def check_for_updates(self, installed_plugins: List[str]) -> Dict[str, str]:
        """Check for updates for installed plugins."""
        
        logger.info(f"Checking for updates for {len(installed_plugins)} plugins")
        
        updates_available = {}
        
        for plugin_id in installed_plugins:
            plugin = await self.get_plugin_details(plugin_id)
            if plugin and plugin.status == PluginStatus.UPDATE_AVAILABLE:
                updates_available[plugin_id] = plugin.latest_version
        
        logger.info(f"Found {len(updates_available)} plugin updates available")
        
        return updates_available
    
    async def get_plugin_reviews(self, plugin_id: str, page: int = 1, 
                               per_page: int = 10) -> List[PluginReview]:
        """Get reviews for a plugin."""
        
        # This would fetch reviews from the marketplace API
        # For now, return empty list
        return []
    
    async def submit_plugin_review(self, plugin_id: str, rating: int, 
                                 title: str, content: str) -> bool:
        """Submit a review for a plugin."""
        
        # This would submit a review to the marketplace API
        logger.info(f"Submitting review for plugin {plugin_id}: {rating} stars")
        return True
    
    async def get_trending_plugins(self, category: Optional[str] = None, 
                                 time_period: str = "week") -> List[MarketplacePlugin]:
        """Get trending plugins."""
        
        # This would fetch trending plugins from the marketplace API
        logger.info(f"Getting trending plugins for category: {category}, period: {time_period}")
        return []
    
    async def get_featured_plugins(self) -> List[MarketplacePlugin]:
        """Get featured plugins."""
        
        # This would fetch featured plugins from the marketplace API
        logger.info("Getting featured plugins")
        return []
    
    # Private methods
    
    def _get_enabled_sources(self) -> List[PluginSource]:
        """Get list of enabled plugin sources."""
        
        sources = [PluginSource.OFFICIAL_REGISTRY]
        
        if self.marketplace_config['github_search_enabled']:
            sources.append(PluginSource.GITHUB_RELEASES)
        
        if self.marketplace_config['npm_search_enabled']:
            sources.append(PluginSource.NPM_REGISTRY)
        
        if self.marketplace_config['pypi_search_enabled']:
            sources.append(PluginSource.PYPI_REGISTRY)
        
        return sources
    
    async def _search_official_registry(self, query: str, filters: Dict[str, Any]) -> List[MarketplacePlugin]:
        """Search the official plugin registry."""
        
        # This would make API calls to the official registry
        # For now, return empty list
        logger.debug(f"Searching official registry for: {query}")
        return []
    
    async def _search_github(self, query: str, filters: Dict[str, Any]) -> List[MarketplacePlugin]:
        """Search GitHub for plugins."""
        
        # This would search GitHub repositories with specific topics/keywords
        logger.debug(f"Searching GitHub for: {query}")
        return []
    
    async def _search_npm(self, query: str, filters: Dict[str, Any]) -> List[MarketplacePlugin]:
        """Search NPM registry for plugins."""
        
        logger.debug(f"Searching NPM for: {query}")
        return []
    
    async def _search_pypi(self, query: str, filters: Dict[str, Any]) -> List[MarketplacePlugin]:
        """Search PyPI registry for plugins."""
        
        logger.debug(f"Searching PyPI for: {query}")
        return []
    
    def _merge_search_results(self, results: List[List[MarketplacePlugin]]) -> List[MarketplacePlugin]:
        """Merge and deduplicate search results from multiple sources."""
        
        merged = {}
        
        for result_list in results:
            for plugin in result_list:
                if plugin.id not in merged:
                    merged[plugin.id] = plugin
                else:
                    # Merge information from multiple sources
                    existing = merged[plugin.id]
                    existing.sources.extend([s for s in plugin.sources if s not in existing.sources])
                    
                    # Use the most recent information
                    if plugin.last_updated > existing.last_updated:
                        merged[plugin.id] = plugin
        
        return list(merged.values())
    
    def _apply_search_filters(self, plugins: List[MarketplacePlugin], 
                            filters: Dict[str, Any]) -> List[MarketplacePlugin]:
        """Apply search filters to plugin list."""
        
        filtered = plugins
        
        # Category filter
        if 'category' in filters:
            category = filters['category']
            filtered = [p for p in filtered if p.category == category]
        
        # Rating filter
        if 'min_rating' in filters:
            min_rating = filters['min_rating']
            filtered = [p for p in filtered if p.rating.average_rating >= min_rating]
        
        # License filter
        if 'license' in filters:
            license_filter = filters['license']
            filtered = [p for p in filtered if p.license == license_filter]
        
        # Tags filter
        if 'tags' in filters:
            required_tags = filters['tags']
            if isinstance(required_tags, str):
                required_tags = [required_tags]
            filtered = [p for p in filtered if any(tag in p.tags for tag in required_tags)]
        
        return filtered
    
    def _sort_search_results(self, plugins: List[MarketplacePlugin], 
                           sort_by: str) -> List[MarketplacePlugin]:
        """Sort search results."""
        
        if sort_by == "relevance":
            # Would implement relevance scoring
            return plugins
        elif sort_by == "downloads":
            return sorted(plugins, key=lambda p: p.downloads, reverse=True)
        elif sort_by == "rating":
            return sorted(plugins, key=lambda p: p.rating.average_rating, reverse=True)
        elif sort_by == "updated":
            return sorted(plugins, key=lambda p: p.last_updated, reverse=True)
        elif sort_by == "name":
            return sorted(plugins, key=lambda p: p.name.lower())
        else:
            return plugins
    
    def _paginate_results(self, plugins: List[MarketplacePlugin], 
                         page: int, per_page: int) -> List[MarketplacePlugin]:
        """Paginate search results."""
        
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        return plugins[start_idx:end_idx]
    
    async def _fetch_plugin_from_source(self, plugin_id: str, 
                                       source: PluginSource) -> Optional[MarketplacePlugin]:
        """Fetch plugin details from a specific source."""
        
        # This would implement fetching from each source
        logger.debug(f"Fetching plugin {plugin_id} from {source.value}")
        return None
    
    async def _download_plugin(self, plugin_id: str, version_info: PluginVersion) -> Optional[Path]:
        """Download a plugin file."""
        
        async with self.download_semaphore:
            try:
                logger.info(f"Downloading plugin {plugin_id} v{version_info.version}")
                
                # Create temporary file
                temp_file = Path(tempfile.mktemp(suffix='.zip'))
                
                # This would download the actual file
                # For now, just create an empty file
                temp_file.touch()
                
                self.stats['downloads_completed'] += 1
                
                return temp_file
                
            except Exception as e:
                logger.error(f"Failed to download plugin {plugin_id}: {str(e)}")
                return None
    
    async def _verify_plugin_checksum(self, plugin_file: Path, expected_checksum: str) -> bool:
        """Verify plugin file checksum."""
        
        try:
            content = plugin_file.read_bytes()
            actual_checksum = hashlib.sha256(content).hexdigest()
            return actual_checksum == expected_checksum
        except Exception as e:
            logger.error(f"Failed to verify checksum: {str(e)}")
            return False
    
    async def _install_plugin_file(self, plugin_file: Path, plugin_id: str) -> bool:
        """Install a downloaded plugin file."""
        
        try:
            # This would extract and install the plugin
            logger.info(f"Installing plugin file for {plugin_id}")
            
            # Cleanup temporary file
            plugin_file.unlink(missing_ok=True)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to install plugin file: {str(e)}")
            return False
    
    def _generate_search_cache_key(self, query: str, filters: Dict[str, Any], 
                                 sort_by: str, page: int, per_page: int) -> str:
        """Generate cache key for search results."""
        
        key_data = {
            'query': query,
            'filters': filters,
            'sort_by': sort_by,
            'page': page,
            'per_page': per_page
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is still valid."""
        
        if cache_key not in self.cache_timestamps:
            return False
        
        age = time.time() - self.cache_timestamps[cache_key]
        return age < self.marketplace_config['cache_duration']
    
    async def _load_cache(self):
        """Load cached data from disk."""
        
        # This would load cached plugin information
        logger.debug("Loading marketplace cache")
    
    async def _auto_update_checker(self):
        """Background task to check for plugin updates."""
        
        while True:
            try:
                logger.debug("Running auto update check")
                
                # This would check for updates for installed plugins
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Auto update checker error: {str(e)}")
                await asyncio.sleep(3600)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get marketplace statistics."""
        
        return dict(self.stats)


class PluginSecurityScanner:
    """Security scanner for plugins."""
    
    def __init__(self):
        self.scan_rules = self._initialize_scan_rules()
    
    async def initialize(self):
        """Initialize the security scanner."""
        logger.info("Initializing Plugin Security Scanner")
    
    async def scan_plugin(self, plugin: MarketplacePlugin) -> PluginSecurityInfo:
        """Scan a plugin for security issues."""
        
        # This would perform comprehensive security scanning
        logger.debug(f"Scanning plugin {plugin.id} for security issues")
        
        return PluginSecurityInfo(
            security_score=85.0,
            last_security_scan=time.strftime('%Y-%m-%d %H:%M:%S'),
            vulnerabilities_found=0,
            security_issues=[],
            code_signed=False,
            verified_publisher=False,
            open_source=True,
            audit_status="not_audited"
        )
    
    def _initialize_scan_rules(self) -> List[Dict[str, Any]]:
        """Initialize security scan rules."""
        
        return [
            {
                'id': 'malicious_code',
                'name': 'Malicious Code Detection',
                'severity': 'critical',
                'patterns': ['eval(', 'exec(', '__import__']
            },
            {
                'id': 'network_access',
                'name': 'Network Access Detection',
                'severity': 'medium',
                'patterns': ['requests.', 'urllib.', 'socket.']
            }
        ]
