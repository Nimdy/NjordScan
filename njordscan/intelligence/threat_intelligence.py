"""
Threat Intelligence Engine

Advanced threat intelligence system with:
- Real-time threat feed integration
- MITRE ATT&CK framework mapping
- Threat actor profiling and attribution
- Attack pattern recognition and prediction
- Threat landscape analysis
- IOC (Indicators of Compromise) detection
- Threat hunting capabilities
- Intelligence sharing and collaboration
"""

import asyncio
import time
import json
import aiohttp
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
from collections import defaultdict, deque
import hashlib
import re
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat severity levels."""
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(Enum):
    """Types of threats."""
    MALWARE = "malware"
    PHISHING = "phishing"
    INJECTION = "injection"
    XSS = "xss"
    CSRF = "csrf"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"
    ZERO_DAY = "zero_day"
    APT = "apt"  # Advanced Persistent Threat

class ThreatSource(Enum):
    """Sources of threat intelligence."""
    MITRE_ATTCK = "mitre_attack"
    NIST_CVE = "nist_cve"
    OWASP = "owasp"
    GITHUB_ADVISORIES = "github_advisories"
    SNYK = "snyk"
    NPM_AUDIT = "npm_audit"
    CUSTOM_FEEDS = "custom_feeds"
    COMMUNITY = "community"
    INTERNAL = "internal"

class IOCType(Enum):
    """Types of Indicators of Compromise."""
    HASH = "hash"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    PATTERN = "pattern"
    BEHAVIOR = "behavior"

@dataclass
class ThreatIndicator:
    """Indicator of Compromise (IOC)."""
    ioc_id: str
    ioc_type: IOCType
    value: str
    threat_types: Set[ThreatType] = field(default_factory=set)
    confidence: float = 0.5
    severity: ThreatLevel = ThreatLevel.MEDIUM
    
    # Attribution
    threat_actors: Set[str] = field(default_factory=set)
    campaigns: Set[str] = field(default_factory=set)
    
    # Context
    description: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: Set[str] = field(default_factory=set)
    
    # Sources
    sources: Set[ThreatSource] = field(default_factory=set)
    references: List[str] = field(default_factory=list)
    
    # MITRE ATT&CK mapping
    mitre_techniques: Set[str] = field(default_factory=set)
    mitre_tactics: Set[str] = field(default_factory=set)
    
    # Validation
    false_positive_rate: float = 0.0
    validated: bool = False
    
    @property
    def is_expired(self) -> bool:
        """Check if indicator is expired."""
        if not self.last_seen:
            return False
        return datetime.now() - self.last_seen > timedelta(days=90)
    
    @property
    def risk_score(self) -> float:
        """Calculate risk score."""
        base_score = self.confidence * self.severity_weight
        
        # Adjust for false positive rate
        adjusted_score = base_score * (1.0 - self.false_positive_rate)
        
        # Boost for recent activity
        if self.last_seen and datetime.now() - self.last_seen < timedelta(days=7):
            adjusted_score *= 1.2
        
        return min(1.0, adjusted_score)
    
    @property
    def severity_weight(self) -> float:
        """Get numeric weight for severity."""
        weights = {
            ThreatLevel.UNKNOWN: 0.1,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.MEDIUM: 0.6,
            ThreatLevel.HIGH: 0.8,
            ThreatLevel.CRITICAL: 1.0
        }
        return weights.get(self.severity, 0.5)

@dataclass
class ThreatActor:
    """Threat actor profile."""
    actor_id: str
    name: str
    aliases: Set[str] = field(default_factory=set)
    
    # Classification
    actor_type: str = "unknown"  # nation_state, cybercriminal, hacktivist, etc.
    sophistication_level: str = "unknown"  # low, medium, high, expert
    
    # Targeting
    target_sectors: Set[str] = field(default_factory=set)
    target_regions: Set[str] = field(default_factory=set)
    target_technologies: Set[str] = field(default_factory=set)
    
    # TTPs (Tactics, Techniques, Procedures)
    preferred_techniques: Set[str] = field(default_factory=set)
    attack_patterns: List[str] = field(default_factory=list)
    tools_used: Set[str] = field(default_factory=set)
    
    # Attribution confidence
    attribution_confidence: float = 0.5
    
    # Activity
    first_observed: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    active: bool = True
    
    # Intelligence
    description: str = ""
    motivations: Set[str] = field(default_factory=set)
    capabilities: Dict[str, str] = field(default_factory=dict)
    
    # Sources and references
    sources: Set[ThreatSource] = field(default_factory=set)
    references: List[str] = field(default_factory=list)

@dataclass
class AttackPattern:
    """MITRE ATT&CK pattern representation."""
    technique_id: str
    name: str
    description: str
    tactic: str
    
    # Implementation details
    platforms: Set[str] = field(default_factory=set)
    data_sources: Set[str] = field(default_factory=set)
    detection_methods: List[str] = field(default_factory=list)
    
    # Relationships
    sub_techniques: Set[str] = field(default_factory=set)
    mitigations: Set[str] = field(default_factory=set)
    
    # Prevalence and impact
    prevalence_score: float = 0.5
    impact_score: float = 0.5
    difficulty_score: float = 0.5  # How difficult to detect/prevent
    
    # Code patterns that might indicate this technique
    code_indicators: List[str] = field(default_factory=list)
    behavioral_indicators: List[str] = field(default_factory=list)

@dataclass
class ThreatCampaign:
    """Threat campaign information."""
    campaign_id: str
    name: str
    description: str
    
    # Attribution
    attributed_actors: Set[str] = field(default_factory=set)
    attribution_confidence: float = 0.5
    
    # Timeline
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    active: bool = True
    
    # Targeting
    target_sectors: Set[str] = field(default_factory=set)
    target_regions: Set[str] = field(default_factory=set)
    target_technologies: Set[str] = field(default_factory=set)
    
    # TTPs
    techniques_used: Set[str] = field(default_factory=set)
    tools_used: Set[str] = field(default_factory=set)
    indicators: Set[str] = field(default_factory=set)
    
    # Impact
    estimated_impact: str = "unknown"
    victim_count: int = 0
    
    # Intelligence
    tags: Set[str] = field(default_factory=set)
    references: List[str] = field(default_factory=list)

@dataclass
class ThreatIntelligenceConfig:
    """Configuration for threat intelligence engine."""
    
    # Feed sources
    enable_mitre_attck: bool = True
    enable_cve_feeds: bool = True
    enable_github_advisories: bool = True
    enable_custom_feeds: bool = True
    
    # Update intervals
    mitre_update_interval: int = 86400  # 24 hours
    cve_update_interval: int = 3600     # 1 hour
    custom_feed_update_interval: int = 1800  # 30 minutes
    
    # API endpoints
    mitre_attck_url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    cve_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    github_advisories_url: str = "https://api.github.com/advisories"
    
    # Custom feeds
    custom_feed_urls: List[str] = field(default_factory=list)
    custom_feed_formats: Dict[str, str] = field(default_factory=dict)  # url -> format
    
    # Storage and caching
    intelligence_cache_ttl: int = 3600
    max_indicators_cache: int = 100000
    enable_persistent_storage: bool = True
    storage_file: str = ".njordscan_threat_intelligence.json"
    
    # Analysis settings
    enable_correlation_analysis: bool = True
    correlation_threshold: float = 0.7
    enable_predictive_analysis: bool = True
    prediction_window_days: int = 30
    
    # IOC matching
    enable_fuzzy_ioc_matching: bool = True
    ioc_match_threshold: float = 0.8
    enable_regex_iocs: bool = True
    
    # Attribution
    enable_actor_attribution: bool = True
    attribution_confidence_threshold: float = 0.6
    
    # Performance
    max_concurrent_feeds: int = 10
    feed_timeout_seconds: int = 30
    enable_feed_caching: bool = True
    
    # Quality control
    min_confidence_threshold: float = 0.3
    enable_ioc_validation: bool = True
    false_positive_threshold: float = 0.5

class ThreatIntelligenceEngine:
    """Advanced threat intelligence engine."""
    
    def __init__(self, config: ThreatIntelligenceConfig = None):
        self.config = config or ThreatIntelligenceConfig()
        
        # Intelligence storage
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.threat_actors: Dict[str, ThreatActor] = {}
        self.attack_patterns: Dict[str, AttackPattern] = {}
        self.campaigns: Dict[str, ThreatCampaign] = {}
        
        # Indexing for fast lookups
        self.indicators_by_type: Dict[IOCType, Set[str]] = defaultdict(set)
        self.indicators_by_threat: Dict[ThreatType, Set[str]] = defaultdict(set)
        self.patterns_by_tactic: Dict[str, Set[str]] = defaultdict(set)
        
        # Feed management
        self.feed_managers: Dict[ThreatSource, 'ThreatFeedManager'] = {}
        self.feed_update_times: Dict[ThreatSource, datetime] = {}
        
        # Analysis engines
        self.correlation_engine = ThreatCorrelationEngine(self.config)
        self.attribution_engine = AttributionEngine(self.config)
        self.prediction_engine = ThreatPredictionEngine(self.config)
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # HTTP session for feed fetching
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Statistics
        self.stats = {
            'indicators_loaded': 0,
            'actors_loaded': 0,
            'patterns_loaded': 0,
            'campaigns_loaded': 0,
            'feeds_updated': 0,
            'correlations_found': 0,
            'attributions_made': 0,
            'predictions_generated': 0,
            'ioc_matches': 0,
            'false_positives_detected': 0
        }
        
        self.start_time = time.time()
    
    async def initialize(self):
        """Initialize threat intelligence engine."""
        
        logger.info("Initializing Threat Intelligence Engine")
        
        self.running = True
        
        # Create HTTP session
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.feed_timeout_seconds)
        )
        
        # Initialize analysis engines
        await self.correlation_engine.initialize()
        await self.attribution_engine.initialize()
        await self.prediction_engine.initialize()
        
        # Initialize feed managers
        await self._initialize_feed_managers()
        
        # Load persisted intelligence
        if self.config.enable_persistent_storage:
            await self._load_persisted_intelligence()
        
        # Initial feed updates (with error handling)
        try:
            await self._update_all_feeds()
        except Exception as e:
            logger.warning(f"Initial feed update failed: {str(e)}")
            # Continue initialization even if feed updates fail
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._feed_update_worker()),
            asyncio.create_task(self._correlation_worker()),
            asyncio.create_task(self._cleanup_worker())
        ]
        
        if self.config.enable_predictive_analysis:
            self.background_tasks.append(
                asyncio.create_task(self._prediction_worker())
            )
        
        logger.info(f"Threat Intelligence Engine initialized with {len(self.indicators)} indicators")
    
    async def check_indicators(self, content: str, file_path: str = "", 
                             context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Check content against threat indicators."""
        
        matches = []
        context = context or {}
        
        try:
            # Check different types of indicators
            for ioc_id, indicator in self.indicators.items():
                if await self._match_indicator(indicator, content, file_path, context):
                    match = {
                        'indicator_id': ioc_id,
                        'indicator_type': indicator.ioc_type.value,
                        'value': indicator.value,
                        'threat_types': [t.value for t in indicator.threat_types],
                        'severity': indicator.severity.value,
                        'confidence': indicator.confidence,
                        'risk_score': indicator.risk_score,
                        'description': indicator.description,
                        'mitre_techniques': list(indicator.mitre_techniques),
                        'threat_actors': list(indicator.threat_actors),
                        'campaigns': list(indicator.campaigns),
                        'file_path': file_path
                    }
                    matches.append(match)
            
            # Perform correlation analysis
            if matches and self.config.enable_correlation_analysis:
                correlations = await self.correlation_engine.analyze_matches(matches, context)
                for match in matches:
                    match['correlations'] = correlations.get(match['indicator_id'], [])
            
            # Attribution analysis
            if matches and self.config.enable_actor_attribution:
                attributions = await self.attribution_engine.analyze_matches(matches, context)
                for match in matches:
                    match['attributions'] = attributions.get(match['indicator_id'], [])
            
            self.stats['ioc_matches'] += len(matches)
            
            return matches
            
        except Exception as e:
            logger.error(f"Indicator checking error: {str(e)}")
            return []
    
    async def get_threat_landscape(self, timeframe_days: int = 30) -> Dict[str, Any]:
        """Get current threat landscape analysis."""
        
        try:
            cutoff_date = datetime.now() - timedelta(days=timeframe_days)
            
            # Active threats
            active_indicators = [
                indicator for indicator in self.indicators.values()
                if (not indicator.last_seen or indicator.last_seen >= cutoff_date)
            ]
            
            # Threat type distribution
            threat_types = defaultdict(int)
            severity_distribution = defaultdict(int)
            
            for indicator in active_indicators:
                for threat_type in indicator.threat_types:
                    threat_types[threat_type.value] += 1
                severity_distribution[indicator.severity.value] += 1
            
            # Top threat actors
            actor_activity = defaultdict(int)
            for indicator in active_indicators:
                for actor in indicator.threat_actors:
                    actor_activity[actor] += 1
            
            top_actors = sorted(actor_activity.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Active campaigns
            active_campaigns = [
                campaign for campaign in self.campaigns.values()
                if campaign.active and (not campaign.end_date or campaign.end_date >= cutoff_date)
            ]
            
            # MITRE ATT&CK technique prevalence
            technique_prevalence = defaultdict(int)
            for indicator in active_indicators:
                for technique in indicator.mitre_techniques:
                    technique_prevalence[technique] += 1
            
            top_techniques = sorted(technique_prevalence.items(), key=lambda x: x[1], reverse=True)[:15]
            
            # Emerging threats (recent indicators)
            recent_cutoff = datetime.now() - timedelta(days=7)
            emerging_threats = [
                indicator for indicator in active_indicators
                if indicator.first_seen and indicator.first_seen >= recent_cutoff
            ]
            
            landscape = {
                'timeframe_days': timeframe_days,
                'generated_at': datetime.now().isoformat(),
                'summary': {
                    'total_active_indicators': len(active_indicators),
                    'total_threat_actors': len(self.threat_actors),
                    'active_campaigns': len(active_campaigns),
                    'emerging_threats': len(emerging_threats)
                },
                'threat_distribution': {
                    'by_type': dict(threat_types),
                    'by_severity': dict(severity_distribution)
                },
                'top_threat_actors': [{'actor': actor, 'indicator_count': count} for actor, count in top_actors],
                'top_attack_techniques': [{'technique': tech, 'prevalence': count} for tech, count in top_techniques],
                'active_campaigns': [
                    {
                        'campaign_id': campaign.campaign_id,
                        'name': campaign.name,
                        'attributed_actors': list(campaign.attributed_actors),
                        'target_sectors': list(campaign.target_sectors),
                        'techniques_used': list(campaign.techniques_used)
                    }
                    for campaign in active_campaigns[:10]
                ],
                'emerging_threats': [
                    {
                        'indicator_id': indicator.ioc_id,
                        'type': indicator.ioc_type.value,
                        'threat_types': [t.value for t in indicator.threat_types],
                        'severity': indicator.severity.value,
                        'first_seen': indicator.first_seen.isoformat() if indicator.first_seen else None
                    }
                    for indicator in emerging_threats[:20]
                ]
            }
            
            # Add predictions if enabled
            if self.config.enable_predictive_analysis:
                predictions = await self.prediction_engine.generate_threat_predictions(
                    active_indicators, timeframe_days
                )
                landscape['predictions'] = predictions
            
            return landscape
            
        except Exception as e:
            logger.error(f"Threat landscape analysis error: {str(e)}")
            return {}
    
    async def add_custom_indicator(self, indicator: ThreatIndicator) -> bool:
        """Add custom threat indicator."""
        
        try:
            # Validate indicator
            if not await self._validate_indicator(indicator):
                logger.error(f"Indicator validation failed: {indicator.ioc_id}")
                return False
            
            # Add to storage
            self.indicators[indicator.ioc_id] = indicator
            
            # Update indexes
            self.indicators_by_type[indicator.ioc_type].add(indicator.ioc_id)
            for threat_type in indicator.threat_types:
                self.indicators_by_threat[threat_type].add(indicator.ioc_id)
            
            # Mark as custom source
            indicator.sources.add(ThreatSource.CUSTOM_FEEDS)
            
            logger.info(f"Added custom threat indicator: {indicator.ioc_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add custom indicator: {str(e)}")
            return False
    
    async def get_actor_profile(self, actor_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed threat actor profile."""
        
        if actor_id not in self.threat_actors:
            return None
        
        actor = self.threat_actors[actor_id]
        
        # Get associated indicators
        associated_indicators = [
            indicator for indicator in self.indicators.values()
            if actor_id in indicator.threat_actors
        ]
        
        # Get associated campaigns
        associated_campaigns = [
            campaign for campaign in self.campaigns.values()
            if actor_id in campaign.attributed_actors
        ]
        
        profile = {
            'actor_id': actor.actor_id,
            'name': actor.name,
            'aliases': list(actor.aliases),
            'type': actor.actor_type,
            'sophistication': actor.sophistication_level,
            'attribution_confidence': actor.attribution_confidence,
            'active': actor.active,
            'first_observed': actor.first_observed.isoformat() if actor.first_observed else None,
            'last_activity': actor.last_activity.isoformat() if actor.last_activity else None,
            'description': actor.description,
            'motivations': list(actor.motivations),
            'capabilities': actor.capabilities,
            'targeting': {
                'sectors': list(actor.target_sectors),
                'regions': list(actor.target_regions),
                'technologies': list(actor.target_technologies)
            },
            'ttps': {
                'preferred_techniques': list(actor.preferred_techniques),
                'attack_patterns': actor.attack_patterns,
                'tools_used': list(actor.tools_used)
            },
            'associated_indicators': len(associated_indicators),
            'associated_campaigns': len(associated_campaigns),
            'recent_campaigns': [
                {
                    'campaign_id': campaign.campaign_id,
                    'name': campaign.name,
                    'active': campaign.active,
                    'start_date': campaign.start_date.isoformat() if campaign.start_date else None
                }
                for campaign in sorted(associated_campaigns, 
                                     key=lambda c: c.start_date or datetime.min, 
                                     reverse=True)[:5]
            ],
            'sources': [source.value for source in actor.sources],
            'references': actor.references
        }
        
        return profile
    
    async def search_intelligence(self, query: str, 
                                search_types: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Search threat intelligence data."""
        
        search_types = search_types or ['indicators', 'actors', 'campaigns', 'patterns']
        results = {}
        
        try:
            query_lower = query.lower()
            
            # Search indicators
            if 'indicators' in search_types:
                indicator_matches = []
                for indicator in self.indicators.values():
                    if (query_lower in indicator.value.lower() or
                        query_lower in indicator.description.lower() or
                        any(query_lower in tag.lower() for tag in indicator.tags)):
                        indicator_matches.append({
                            'id': indicator.ioc_id,
                            'type': indicator.ioc_type.value,
                            'value': indicator.value,
                            'description': indicator.description,
                            'severity': indicator.severity.value,
                            'confidence': indicator.confidence
                        })
                results['indicators'] = indicator_matches[:50]  # Limit results
            
            # Search threat actors
            if 'actors' in search_types:
                actor_matches = []
                for actor in self.threat_actors.values():
                    if (query_lower in actor.name.lower() or
                        any(query_lower in alias.lower() for alias in actor.aliases) or
                        query_lower in actor.description.lower()):
                        actor_matches.append({
                            'id': actor.actor_id,
                            'name': actor.name,
                            'type': actor.actor_type,
                            'description': actor.description,
                            'active': actor.active
                        })
                results['actors'] = actor_matches[:20]
            
            # Search campaigns
            if 'campaigns' in search_types:
                campaign_matches = []
                for campaign in self.campaigns.values():
                    if (query_lower in campaign.name.lower() or
                        query_lower in campaign.description.lower() or
                        any(query_lower in tag.lower() for tag in campaign.tags)):
                        campaign_matches.append({
                            'id': campaign.campaign_id,
                            'name': campaign.name,
                            'description': campaign.description,
                            'active': campaign.active,
                            'attributed_actors': list(campaign.attributed_actors)
                        })
                results['campaigns'] = campaign_matches[:20]
            
            # Search attack patterns
            if 'patterns' in search_types:
                pattern_matches = []
                for pattern in self.attack_patterns.values():
                    if (query_lower in pattern.name.lower() or
                        query_lower in pattern.description.lower() or
                        query_lower in pattern.technique_id.lower()):
                        pattern_matches.append({
                            'id': pattern.technique_id,
                            'name': pattern.name,
                            'tactic': pattern.tactic,
                            'description': pattern.description,
                            'prevalence': pattern.prevalence_score
                        })
                results['patterns'] = pattern_matches[:30]
            
            return results
            
        except Exception as e:
            logger.error(f"Intelligence search error: {str(e)}")
            return {}
    
    # Private methods
    
    async def _initialize_feed_managers(self):
        """Initialize threat feed managers."""
        
        if self.config.enable_mitre_attck:
            self.feed_managers[ThreatSource.MITRE_ATTCK] = MitreAttckFeedManager(self.config, self.session)
        
        if self.config.enable_cve_feeds:
            self.feed_managers[ThreatSource.NIST_CVE] = CVEFeedManager(self.config, self.session)
        
        if self.config.enable_github_advisories:
            self.feed_managers[ThreatSource.GITHUB_ADVISORIES] = GitHubAdvisoriesFeedManager(self.config, self.session)
        
        if self.config.enable_custom_feeds:
            for url in self.config.custom_feed_urls:
                feed_format = self.config.custom_feed_formats.get(url, 'json')
                self.feed_managers[f"custom_{hash(url)}"] = CustomFeedManager(url, feed_format, self.config, self.session)
    
    async def _update_all_feeds(self):
        """Update all threat intelligence feeds."""
        
        logger.info("Updating threat intelligence feeds")
        
        update_tasks = []
        for source, manager in self.feed_managers.items():
            update_tasks.append(self._update_single_feed(source, manager))
        
        # Limit concurrent updates
        semaphore = asyncio.Semaphore(self.config.max_concurrent_feeds)
        
        async def limited_update(source, manager):
            async with semaphore:
                return await self._update_single_feed(source, manager)
        
        limited_tasks = [limited_update(source, manager) for source, manager in self.feed_managers.items()]
        results = await asyncio.gather(*limited_tasks, return_exceptions=True)
        
        # Process results
        successful_updates = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Feed update failed: {str(result)}")
            elif result:
                successful_updates += 1
        
        self.stats['feeds_updated'] += successful_updates
        logger.info(f"Updated {successful_updates}/{len(self.feed_managers)} threat intelligence feeds")
    
    async def _update_single_feed(self, source: ThreatSource, manager: 'ThreatFeedManager') -> bool:
        """Update a single threat intelligence feed with enhanced error handling."""
        
        try:
            logger.debug(f"Updating feed: {source}")
            
            # Check if update is needed
            last_update = self.feed_update_times.get(source)
            if last_update and datetime.now() - last_update < timedelta(seconds=manager.update_interval):
                logger.debug(f"Feed {source} is up to date, skipping update")
                return True
            
            # Add timeout for feed fetching
            try:
                feed_data = await asyncio.wait_for(manager.fetch_feed(), timeout=30.0)
            except asyncio.TimeoutError:
                logger.warning(f"Feed {source} fetch timeout after 30 seconds")
                return False
            except Exception as fetch_error:
                logger.warning(f"Feed {source} fetch error: {str(fetch_error)}")
                return False
            
            if not feed_data:
                logger.warning(f"Feed {source} returned no data")
                return False
            
            # Process the feed data with error handling
            try:
                indicators, actors, patterns, campaigns = await manager.process_feed_data(feed_data)
            except Exception as process_error:
                logger.error(f"Feed {source} processing error: {str(process_error)}")
                return False
            
            # Update storage with error handling
            try:
                for indicator in indicators:
                    self.indicators[indicator.ioc_id] = indicator
                    self.indicators_by_type[indicator.ioc_type].add(indicator.ioc_id)
                    for threat_type in indicator.threat_types:
                        self.indicators_by_threat[threat_type].add(indicator.ioc_id)
                
                for actor in actors:
                    self.threat_actors[actor.actor_id] = actor
                
                for pattern in patterns:
                    self.attack_patterns[pattern.technique_id] = pattern
                    self.patterns_by_tactic[pattern.tactic].add(pattern.technique_id)
                
                for campaign in campaigns:
                    self.campaigns[campaign.campaign_id] = campaign
                
                # Update statistics
                self.stats['indicators_loaded'] += len(indicators)
                self.stats['actors_loaded'] += len(actors)
                self.stats['patterns_loaded'] += len(patterns)
                self.stats['campaigns_loaded'] += len(campaigns)
                
                # Update timestamp
                self.feed_update_times[source] = datetime.now()
                
                logger.debug(f"Feed updated: {source} ({len(indicators)} indicators, {len(actors)} actors)")
                return True
                
            except Exception as storage_error:
                logger.error(f"Feed {source} storage update error: {str(storage_error)}")
                return False
            
        except Exception as e:
            logger.error(f"Feed update error for {source}: {str(e)}")
            # Don't let feed update failures crash the system
            return False
    
    async def _match_indicator(self, indicator: ThreatIndicator, content: str,
                             file_path: str, context: Dict[str, Any]) -> bool:
        """Check if content matches a threat indicator."""
        
        try:
            if indicator.ioc_type == IOCType.PATTERN:
                # Regex pattern matching
                try:
                    pattern = re.compile(indicator.value, re.IGNORECASE)
                    return bool(pattern.search(content))
                except re.error:
                    return False
            
            elif indicator.ioc_type == IOCType.HASH:
                # Hash matching (would need to compute file hashes)
                return False  # Placeholder
            
            elif indicator.ioc_type == IOCType.URL:
                # URL pattern matching
                return indicator.value.lower() in content.lower()
            
            elif indicator.ioc_type == IOCType.DOMAIN:
                # Domain matching
                return indicator.value.lower() in content.lower()
            
            elif indicator.ioc_type == IOCType.EMAIL:
                # Email pattern matching
                return indicator.value.lower() in content.lower()
            
            elif indicator.ioc_type == IOCType.FILE_PATH:
                # File path matching
                return indicator.value.lower() in file_path.lower()
            
            elif indicator.ioc_type == IOCType.BEHAVIOR:
                # Behavioral pattern matching (would need behavioral analysis)
                return False  # Placeholder
            
            else:
                # Generic string matching
                return indicator.value.lower() in content.lower()
                
        except Exception as e:
            logger.error(f"Indicator matching error: {str(e)}")
            return False
    
    async def _validate_indicator(self, indicator: ThreatIndicator) -> bool:
        """Validate threat indicator."""
        
        try:
            # Basic validation
            if not indicator.ioc_id or not indicator.value:
                return False
            
            # Confidence validation
            if not 0.0 <= indicator.confidence <= 1.0:
                return False
            
            # Pattern validation for regex indicators
            if indicator.ioc_type == IOCType.PATTERN:
                try:
                    re.compile(indicator.value)
                except re.error:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Indicator validation error: {str(e)}")
            return False
    
    async def _load_persisted_intelligence(self):
        """Load persisted threat intelligence data."""
        
        try:
            storage_file = Path(self.config.storage_file)
            if storage_file.exists():
                with open(storage_file, 'r') as f:
                    data = json.load(f)
                
                # Load indicators
                for indicator_data in data.get('indicators', []):
                    indicator = self._deserialize_indicator(indicator_data)
                    if indicator:
                        self.indicators[indicator.ioc_id] = indicator
                
                # Load actors
                for actor_data in data.get('actors', []):
                    actor = self._deserialize_actor(actor_data)
                    if actor:
                        self.threat_actors[actor.actor_id] = actor
                
                logger.info(f"Loaded persisted intelligence: {len(self.indicators)} indicators, {len(self.threat_actors)} actors")
                
        except Exception as e:
            logger.warning(f"Failed to load persisted intelligence: {str(e)}")
    
    async def _persist_intelligence(self):
        """Persist threat intelligence data."""
        
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'indicators': [self._serialize_indicator(indicator) for indicator in self.indicators.values()],
                'actors': [self._serialize_actor(actor) for actor in self.threat_actors.values()]
            }
            
            with open(self.config.storage_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to persist intelligence: {str(e)}")
    
    def _serialize_indicator(self, indicator: ThreatIndicator) -> Dict[str, Any]:
        """Serialize threat indicator for storage."""
        
        return {
            'ioc_id': indicator.ioc_id,
            'ioc_type': indicator.ioc_type.value,
            'value': indicator.value,
            'threat_types': [t.value for t in indicator.threat_types],
            'confidence': indicator.confidence,
            'severity': indicator.severity.value,
            'description': indicator.description,
            'first_seen': indicator.first_seen.isoformat() if indicator.first_seen else None,
            'last_seen': indicator.last_seen.isoformat() if indicator.last_seen else None,
            'tags': list(indicator.tags),
            'sources': [s.value for s in indicator.sources],
            'mitre_techniques': list(indicator.mitre_techniques),
            'threat_actors': list(indicator.threat_actors),
            'campaigns': list(indicator.campaigns)
        }
    
    def _deserialize_indicator(self, data: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Deserialize threat indicator from storage."""
        
        try:
            return ThreatIndicator(
                ioc_id=data['ioc_id'],
                ioc_type=IOCType(data['ioc_type']),
                value=data['value'],
                threat_types={ThreatType(t) for t in data.get('threat_types', [])},
                confidence=data.get('confidence', 0.5),
                severity=ThreatLevel(data.get('severity', 'medium')),
                description=data.get('description', ''),
                first_seen=datetime.fromisoformat(data['first_seen']) if data.get('first_seen') else None,
                last_seen=datetime.fromisoformat(data['last_seen']) if data.get('last_seen') else None,
                tags=set(data.get('tags', [])),
                sources={ThreatSource(s) for s in data.get('sources', [])},
                mitre_techniques=set(data.get('mitre_techniques', [])),
                threat_actors=set(data.get('threat_actors', [])),
                campaigns=set(data.get('campaigns', []))
            )
        except Exception as e:
            logger.error(f"Failed to deserialize indicator: {str(e)}")
            return None
    
    def _serialize_actor(self, actor: ThreatActor) -> Dict[str, Any]:
        """Serialize threat actor for storage."""
        
        return {
            'actor_id': actor.actor_id,
            'name': actor.name,
            'aliases': list(actor.aliases),
            'actor_type': actor.actor_type,
            'sophistication_level': actor.sophistication_level,
            'target_sectors': list(actor.target_sectors),
            'preferred_techniques': list(actor.preferred_techniques),
            'attribution_confidence': actor.attribution_confidence,
            'active': actor.active,
            'description': actor.description
        }
    
    def _deserialize_actor(self, data: Dict[str, Any]) -> Optional[ThreatActor]:
        """Deserialize threat actor from storage."""
        
        try:
            return ThreatActor(
                actor_id=data['actor_id'],
                name=data['name'],
                aliases=set(data.get('aliases', [])),
                actor_type=data.get('actor_type', 'unknown'),
                sophistication_level=data.get('sophistication_level', 'unknown'),
                target_sectors=set(data.get('target_sectors', [])),
                preferred_techniques=set(data.get('preferred_techniques', [])),
                attribution_confidence=data.get('attribution_confidence', 0.5),
                active=data.get('active', True),
                description=data.get('description', '')
            )
        except Exception as e:
            logger.error(f"Failed to deserialize actor: {str(e)}")
            return None
    
    # Background workers
    
    async def _feed_update_worker(self):
        """Background feed update worker."""
        
        while not self.shutdown_event.is_set():
            try:
                # Calculate next update time based on shortest interval
                min_interval = min(
                    self.config.mitre_update_interval,
                    self.config.cve_update_interval,
                    self.config.custom_feed_update_interval
                )
                
                await asyncio.sleep(min_interval)
                
                # Update feeds that are due
                await self._update_all_feeds()
                
            except Exception as e:
                logger.error(f"Feed update worker error: {str(e)}")
    
    async def _correlation_worker(self):
        """Background correlation analysis worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                if self.config.enable_correlation_analysis:
                    correlations = await self.correlation_engine.analyze_all_indicators(self.indicators)
                    self.stats['correlations_found'] += len(correlations)
                
            except Exception as e:
                logger.error(f"Correlation worker error: {str(e)}")
    
    async def _prediction_worker(self):
        """Background threat prediction worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(86400)  # Run daily
                
                if self.config.enable_predictive_analysis:
                    predictions = await self.prediction_engine.generate_predictions(
                        list(self.indicators.values())
                    )
                    self.stats['predictions_generated'] += len(predictions)
                
            except Exception as e:
                logger.error(f"Prediction worker error: {str(e)}")
    
    async def _cleanup_worker(self):
        """Background cleanup worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(86400)  # Run daily
                
                # Clean up expired indicators
                expired_indicators = [
                    ioc_id for ioc_id, indicator in self.indicators.items()
                    if indicator.is_expired
                ]
                
                for ioc_id in expired_indicators:
                    logger.info(f"Removing expired indicator: {ioc_id}")
                    del self.indicators[ioc_id]
                
                # Persist updated intelligence
                if self.config.enable_persistent_storage:
                    await self._persist_intelligence()
                
            except Exception as e:
                logger.error(f"Cleanup worker error: {str(e)}")
    
    async def shutdown(self):
        """Shutdown threat intelligence engine."""
        
        logger.info("Shutting down Threat Intelligence Engine")
        
        self.running = False
        self.shutdown_event.set()
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for background tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Persist intelligence data
        if self.config.enable_persistent_storage:
            await self._persist_intelligence()
        
        # Shutdown analysis engines
        await self.correlation_engine.shutdown()
        await self.attribution_engine.shutdown()
        await self.prediction_engine.shutdown()
        
        # Close HTTP session
        if self.session:
            await self.session.close()
        
        logger.info("Threat Intelligence Engine shutdown completed")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        
        stats = dict(self.stats)
        stats['uptime'] = time.time() - self.start_time
        stats['total_indicators'] = len(self.indicators)
        stats['total_actors'] = len(self.threat_actors)
        stats['total_patterns'] = len(self.attack_patterns)
        stats['total_campaigns'] = len(self.campaigns)
        stats['active_feeds'] = len(self.feed_managers)
        
        return stats


# Helper classes (stubs - would be implemented based on specific requirements)

class ThreatFeedManager:
    """Base class for threat feed managers."""
    
    def __init__(self, config: ThreatIntelligenceConfig, session: aiohttp.ClientSession):
        self.config = config
        self.session = session
        self.update_interval = 3600  # Default 1 hour
    
    async def fetch_feed(self) -> Optional[Any]:
        """Fetch feed data."""
        return None
    
    async def process_feed_data(self, data: Any) -> Tuple[List[ThreatIndicator], List[ThreatActor], 
                                                        List[AttackPattern], List[ThreatCampaign]]:
        """Process feed data into intelligence objects."""
        return [], [], [], []


class MitreAttckFeedManager(ThreatFeedManager):
    """MITRE ATT&CK feed manager."""
    
    def __init__(self, config: ThreatIntelligenceConfig, session: aiohttp.ClientSession):
        super().__init__(config, session)
        self.update_interval = config.mitre_update_interval
    
    async def fetch_feed(self) -> Optional[Dict[str, Any]]:
        """Fetch MITRE ATT&CK data with enhanced error handling."""
        try:
            async with self.session.get(self.config.mitre_attck_url) as response:
                if response.status == 200:
                    try:
                        # Check content type before parsing JSON
                        content_type = response.headers.get('content-type', '')
                        if 'application/json' not in content_type:
                            logger.warning(f"MITRE ATT&CK API returned non-JSON content: {content_type}")
                            return None
                        
                        return await response.json()
                    except Exception as json_error:
                        logger.error(f"MITRE ATT&CK API JSON parsing error: {str(json_error)}")
                        return None
                elif response.status == 403:
                    logger.warning("MITRE ATT&CK API access forbidden")
                    return None
                elif response.status == 404:
                    logger.warning("MITRE ATT&CK API endpoint not found")
                    return None
                elif response.status >= 500:
                    logger.warning(f"MITRE ATT&CK API server error: HTTP {response.status}")
                    return None
                else:
                    logger.warning(f"MITRE ATT&CK API error: HTTP {response.status}")
                    return None
        except Exception as e:
            logger.error(f"MITRE ATT&CK feed fetch error: {str(e)}")
        return None


class CVEFeedManager(ThreatFeedManager):
    """CVE feed manager."""
    
    def __init__(self, config: ThreatIntelligenceConfig, session: aiohttp.ClientSession):
        super().__init__(config, session)
        self.update_interval = config.cve_update_interval
        self.api_url = config.cve_api_url
    
    async def fetch_feed(self) -> Optional[Dict[str, Any]]:
        """Fetch CVE data from NIST API."""
        try:
            # NIST CVE API requires pagination for large datasets
            # We'll fetch recent CVEs (last 30 days)
            from datetime import datetime, timedelta
            
            # Calculate date range for recent CVEs
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            
            # Format dates for NIST API
            start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            
            # Build API URL with date range
            api_url = f"{self.api_url}?pubStartDate={start_date_str}&pubEndDate={end_date_str}"
            
            async with self.session.get(api_url) as response:
                if response.status == 200:
                    try:
                        # Check content type before parsing JSON
                        content_type = response.headers.get('content-type', '')
                        if 'application/json' not in content_type:
                            logger.warning(f"NIST CVE API returned non-JSON content: {content_type}")
                            return None
                        
                        data = await response.json()
                        return data
                    except Exception as json_error:
                        logger.error(f"NIST CVE API JSON parsing error: {str(json_error)}")
                        return None
                elif response.status == 403:
                    # Rate limited - NIST API has strict rate limits
                    logger.warning("NIST CVE API rate limited, will retry later")
                    return None
                elif response.status == 429:
                    # Too many requests
                    logger.warning("NIST CVE API too many requests, will retry later")
                    return None
                elif response.status >= 500:
                    # Server error
                    logger.warning(f"NIST CVE API server error: HTTP {response.status}")
                    return None
                else:
                    logger.warning(f"NIST CVE API error: HTTP {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"CVE feed fetch error: {str(e)}")
            return None
    
    async def process_feed_data(self, data: Any) -> Tuple[List[ThreatIndicator], List[ThreatActor], 
                                                        List[AttackPattern], List[ThreatCampaign]]:
        """Process CVE data into intelligence objects."""
        indicators = []
        actors = []
        patterns = []
        campaigns = []
        
        if not data or 'vulnerabilities' not in data:
            return indicators, actors, patterns, campaigns
        
        for vuln_data in data['vulnerabilities']:
            cve_info = vuln_data.get('cve', {})
            cve_id = cve_info.get('id', '')
            
            if not cve_id:
                continue
            
            # Extract description
            description = ""
            if 'descriptions' in cve_info:
                for desc in cve_info['descriptions']:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
            
            # Extract CVSS score and severity
            cvss_score = 0.0
            severity = 'unknown'
            if 'metrics' in vuln_data:
                if 'cvssMetricV31' in vuln_data['metrics']:
                    cvss_data = vuln_data['metrics']['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = self._cvss_to_severity(cvss_score)
                elif 'cvssMetricV30' in vuln_data['metrics']:
                    cvss_data = vuln_data['metrics']['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = self._cvss_to_severity(cvss_score)
                elif 'cvssMetricV2' in vuln_data['metrics']:
                    cvss_data = vuln_data['metrics']['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = self._cvss_to_severity(cvss_score)
            
            # Create threat indicator for CVE
            indicator = ThreatIndicator(
                ioc_id=cve_id,
                ioc_type='cve',
                ioc_value=cve_id,
                threat_types=['vulnerability'],
                confidence=0.9,  # High confidence for official CVE data
                severity=severity,
                description=description,
                source='nist_cve',
                first_seen=vuln_data.get('cve', {}).get('published', ''),
                last_seen=vuln_data.get('cve', {}).get('lastModified', ''),
                references=[ref.get('url', '') for ref in cve_info.get('references', []) if ref.get('url')],
                metadata={
                    'cvss_score': cvss_score,
                    'cwe': [weakness.get('value', '') for weakness in cve_info.get('weaknesses', [])],
                    'configurations': vuln_data.get('configurations', [])
                }
            )
            indicators.append(indicator)
        
        return indicators, actors, patterns, campaigns
    
    def _cvss_to_severity(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score >= 0.1:
            return 'low'
        else:
            return 'info'


class GitHubAdvisoriesFeedManager(ThreatFeedManager):
    """GitHub Security Advisories feed manager."""
    
    def __init__(self, config: ThreatIntelligenceConfig, session: aiohttp.ClientSession):
        super().__init__(config, session)
        self.update_interval = 3600  # 1 hour


class CustomFeedManager(ThreatFeedManager):
    """Custom threat feed manager."""
    
    def __init__(self, url: str, feed_format: str, config: ThreatIntelligenceConfig, 
                 session: aiohttp.ClientSession):
        super().__init__(config, session)
        self.url = url
        self.feed_format = feed_format
        self.update_interval = config.custom_feed_update_interval


class ThreatCorrelationEngine:
    """Threat correlation analysis engine."""
    
    def __init__(self, config: ThreatIntelligenceConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def analyze_matches(self, matches: List[Dict[str, Any]], 
                            context: Dict[str, Any]) -> Dict[str, List[str]]:
        return {}
    
    async def analyze_all_indicators(self, indicators: Dict[str, ThreatIndicator]) -> List[Dict[str, Any]]:
        return []
    
    async def shutdown(self):
        pass


class AttributionEngine:
    """Threat attribution engine."""
    
    def __init__(self, config: ThreatIntelligenceConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def analyze_matches(self, matches: List[Dict[str, Any]], 
                            context: Dict[str, Any]) -> Dict[str, List[str]]:
        return {}
    
    async def shutdown(self):
        pass


class ThreatPredictionEngine:
    """Threat prediction engine."""
    
    def __init__(self, config: ThreatIntelligenceConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def generate_threat_predictions(self, indicators: List[ThreatIndicator], 
                                        timeframe_days: int) -> Dict[str, Any]:
        return {}
    
    async def generate_predictions(self, indicators: List[ThreatIndicator]) -> List[Dict[str, Any]]:
        return []
    
    async def shutdown(self):
        pass
