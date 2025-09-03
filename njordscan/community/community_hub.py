"""
Community Hub

Central platform for community features and collaboration:
- Community-driven security rules and patterns
- Vulnerability sharing and threat intelligence
- Plugin marketplace and distribution
- Community challenges and leaderboards
- Knowledge sharing and best practices
- Collaborative security research
- Bug bounty and responsible disclosure
"""

import asyncio
import time
import json
import hashlib
import aiohttp
import logging
from typing import Dict, List, Any, Optional, Union, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from datetime import datetime, timedelta
import uuid

logger = logging.getLogger(__name__)

class ContributionType(Enum):
    """Types of community contributions."""
    SECURITY_RULE = "security_rule"
    VULNERABILITY_REPORT = "vulnerability_report"
    PLUGIN = "plugin"
    TEMPLATE = "template"
    DOCUMENTATION = "documentation"
    BUG_REPORT = "bug_report"
    FEATURE_REQUEST = "feature_request"
    THREAT_INTELLIGENCE = "threat_intelligence"

class ContributionStatus(Enum):
    """Status of community contributions."""
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    PUBLISHED = "published"

class ReputationLevel(Enum):
    """Community reputation levels."""
    NEWCOMER = "newcomer"
    CONTRIBUTOR = "contributor"
    TRUSTED = "trusted"
    EXPERT = "expert"
    MAINTAINER = "maintainer"
    GUARDIAN = "guardian"

@dataclass
class CommunityMember:
    """Community member profile."""
    member_id: str
    username: str
    email: str = ""
    
    # Reputation and stats
    reputation_score: int = 0
    reputation_level: ReputationLevel = ReputationLevel.NEWCOMER
    contributions_count: int = 0
    
    # Specializations
    specializations: Set[str] = field(default_factory=set)
    frameworks_expertise: Set[str] = field(default_factory=set)
    
    # Activity
    join_date: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    
    # Achievements
    badges: List[str] = field(default_factory=list)
    achievements: List[str] = field(default_factory=list)
    
    # Social
    followers: Set[str] = field(default_factory=set)
    following: Set[str] = field(default_factory=set)
    
    # Preferences
    public_profile: bool = True
    email_notifications: bool = True
    contribution_notifications: bool = True

@dataclass
class CommunityContribution:
    """Community contribution."""
    contribution_id: str
    contributor_id: str
    contribution_type: ContributionType
    title: str
    description: str
    
    # Content
    content: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    category: str = ""
    
    # Review and approval
    status: ContributionStatus = ContributionStatus.PENDING
    reviewers: List[str] = field(default_factory=list)
    review_comments: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metrics
    downloads: int = 0
    likes: int = 0
    reports: int = 0
    usage_count: int = 0
    
    # Quality metrics
    effectiveness_score: float = 0.0
    false_positive_rate: float = 0.0
    community_rating: float = 0.0
    
    # Metadata
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    published_at: Optional[float] = None
    
    # Versioning
    version: str = "1.0.0"
    changelog: List[str] = field(default_factory=list)

@dataclass
class Challenge:
    """Community challenge."""
    challenge_id: str
    title: str
    description: str
    
    # Challenge details
    challenge_type: str  # ctf, bug_hunt, optimization, research
    difficulty_level: str  # beginner, intermediate, advanced, expert
    category: str
    
    # Timing
    start_date: float
    end_date: float
    duration_days: int
    
    # Participation
    participants: Set[str] = field(default_factory=set)
    submissions: List[str] = field(default_factory=list)
    
    # Rewards
    rewards: Dict[str, Any] = field(default_factory=dict)
    winners: List[Dict[str, Any]] = field(default_factory=list)
    
    # Rules and criteria
    rules: List[str] = field(default_factory=list)
    judging_criteria: List[str] = field(default_factory=list)
    
    # Status
    is_active: bool = True
    is_public: bool = True

@dataclass
class CommunityHubConfig:
    """Configuration for community hub."""
    
    # API endpoints
    api_base_url: str = "https://api.njordscan.dev"
    community_api_url: str = "https://community.njordscan.dev/api"
    
    # Authentication
    api_key: Optional[str] = None
    enable_authentication: bool = True
    
    # Contribution settings
    enable_contributions: bool = True
    auto_sync_contributions: bool = True
    contribution_sync_interval: int = 3600  # 1 hour
    
    # Community features
    enable_leaderboards: bool = True
    enable_challenges: bool = True
    enable_social_features: bool = True
    
    # Content moderation
    enable_content_moderation: bool = True
    auto_approve_trusted_contributors: bool = True
    require_review_for_security_rules: bool = True
    
    # Privacy and security
    share_usage_statistics: bool = True
    share_anonymized_findings: bool = False
    enable_telemetry: bool = True
    
    # Caching and performance
    cache_community_data: bool = True
    cache_ttl_seconds: int = 3600
    max_concurrent_requests: int = 10

class CommunityHub:
    """Central community hub for collaboration and sharing."""
    
    def __init__(self, config: CommunityHubConfig = None):
        self.config = config or CommunityHubConfig()
        
        # Community data
        self.members: Dict[str, CommunityMember] = {}
        self.contributions: Dict[str, CommunityContribution] = {}
        self.challenges: Dict[str, Challenge] = {}
        
        # Local user
        self.current_user: Optional[CommunityMember] = None
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Cache
        self.cache: Dict[str, Any] = {}
        self.cache_timestamps: Dict[str, float] = {}
        
        # Statistics
        self.stats = {
            'contributions_shared': 0,
            'contributions_downloaded': 0,
            'challenges_participated': 0,
            'community_interactions': 0,
            'reputation_gained': 0,
            'api_requests': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        self.start_time = time.time()
    
    async def initialize(self):
        """Initialize community hub."""
        
        logger.info("Initializing Community Hub")
        
        self.running = True
        
        # Create HTTP session
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'NjordScan-Community/1.0.0',
                'Content-Type': 'application/json'
            }
        )
        
        # Load local user profile
        await self._load_user_profile()
        
        # Sync with community API
        if self.config.enable_contributions:
            await self._sync_community_data()
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._sync_worker()),
            asyncio.create_task(self._cache_cleanup_worker()),
            asyncio.create_task(self._activity_tracker())
        ]
        
        if self.config.enable_challenges:
            self.background_tasks.append(
                asyncio.create_task(self._challenges_worker())
            )
        
        logger.info(f"Community Hub initialized with {len(self.contributions)} contributions")
    
    async def register_user(self, username: str, email: str, 
                          profile_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Register new community member."""
        
        try:
            logger.info(f"Registering user: {username}")
            
            # Create member profile
            member = CommunityMember(
                member_id=str(uuid.uuid4()),
                username=username,
                email=email,
                specializations=set(profile_data.get('specializations', [])),
                frameworks_expertise=set(profile_data.get('frameworks', []))
            )
            
            # Register with community API
            registration_data = {
                'username': username,
                'email': email,
                'profile': profile_data or {}
            }
            
            response = await self._api_request('POST', '/members/register', registration_data)
            
            if response.get('success'):
                member.member_id = response['member_id']
                self.current_user = member
                self.members[member.member_id] = member
                
                # Save user profile locally
                await self._save_user_profile()
                
                return {
                    'success': True,
                    'member_id': member.member_id,
                    'username': username,
                    'reputation_level': member.reputation_level.value
                }
            else:
                return {'error': response.get('error', 'Registration failed')}
                
        except Exception as e:
            logger.error(f"User registration failed: {str(e)}")
            return {'error': str(e)}
    
    async def contribute_security_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Contribute a security rule to the community."""
        
        if not self.current_user:
            return {'error': 'User not authenticated'}
        
        try:
            logger.info("Contributing security rule to community")
            
            # Create contribution
            contribution = CommunityContribution(
                contribution_id=str(uuid.uuid4()),
                contributor_id=self.current_user.member_id,
                contribution_type=ContributionType.SECURITY_RULE,
                title=rule_data.get('name', 'Security Rule'),
                description=rule_data.get('description', ''),
                content=rule_data,
                tags=set(rule_data.get('tags', [])),
                category=rule_data.get('category', 'general')
            )
            
            # Submit to community API
            submission_data = {
                'contribution': self._serialize_contribution(contribution),
                'contributor_id': self.current_user.member_id
            }
            
            response = await self._api_request('POST', '/contributions/submit', submission_data)
            
            if response.get('success'):
                contribution.contribution_id = response['contribution_id']
                contribution.status = ContributionStatus(response.get('status', 'pending'))
                
                self.contributions[contribution.contribution_id] = contribution
                self.stats['contributions_shared'] += 1
                
                # Update user reputation
                await self._update_reputation(self.current_user.member_id, 'rule_contributed', 10)
                
                return {
                    'success': True,
                    'contribution_id': contribution.contribution_id,
                    'status': contribution.status.value,
                    'reputation_gained': 10
                }
            else:
                return {'error': response.get('error', 'Contribution failed')}
                
        except Exception as e:
            logger.error(f"Security rule contribution failed: {str(e)}")
            return {'error': str(e)}
    
    async def share_vulnerability_finding(self, finding_data: Dict[str, Any], 
                                        anonymize: bool = True) -> Dict[str, Any]:
        """Share vulnerability finding with community for threat intelligence."""
        
        if not self.current_user:
            return {'error': 'User not authenticated'}
        
        try:
            logger.info("Sharing vulnerability finding with community")
            
            # Anonymize sensitive data if requested
            if anonymize:
                finding_data = await self._anonymize_finding(finding_data)
            
            # Create contribution
            contribution = CommunityContribution(
                contribution_id=str(uuid.uuid4()),
                contributor_id=self.current_user.member_id,
                contribution_type=ContributionType.VULNERABILITY_REPORT,
                title=f"Vulnerability: {finding_data.get('type', 'Unknown')}",
                description=finding_data.get('description', ''),
                content=finding_data,
                tags=set(finding_data.get('tags', [])),
                category='vulnerability'
            )
            
            # Submit to community API
            submission_data = {
                'contribution': self._serialize_contribution(contribution),
                'anonymized': anonymize
            }
            
            response = await self._api_request('POST', '/threat-intel/share', submission_data)
            
            if response.get('success'):
                contribution.contribution_id = response['contribution_id']
                self.contributions[contribution.contribution_id] = contribution
                self.stats['contributions_shared'] += 1
                
                # Update reputation
                await self._update_reputation(self.current_user.member_id, 'vulnerability_shared', 15)
                
                return {
                    'success': True,
                    'contribution_id': contribution.contribution_id,
                    'anonymized': anonymize,
                    'reputation_gained': 15
                }
            else:
                return {'error': response.get('error', 'Sharing failed')}
                
        except Exception as e:
            logger.error(f"Vulnerability sharing failed: {str(e)}")
            return {'error': str(e)}
    
    async def download_community_rules(self, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Download security rules from community."""
        
        try:
            logger.info("Downloading community security rules")
            
            filters = filters or {}
            
            # Check cache first
            cache_key = f"community_rules_{hashlib.md5(json.dumps(filters, sort_keys=True).encode()).hexdigest()}"
            
            if self._is_cache_valid(cache_key):
                self.stats['cache_hits'] += 1
                return self.cache[cache_key]
            
            self.stats['cache_misses'] += 1
            
            # Fetch from API
            response = await self._api_request('GET', '/contributions/rules', params=filters)
            
            if response.get('success'):
                rules = response.get('rules', [])
                
                # Process and validate rules
                validated_rules = []
                for rule_data in rules:
                    if await self._validate_community_rule(rule_data):
                        validated_rules.append(rule_data)
                
                result = {
                    'success': True,
                    'rules': validated_rules,
                    'total_count': len(validated_rules),
                    'source': 'community'
                }
                
                # Cache result
                self._cache_data(cache_key, result)
                self.stats['contributions_downloaded'] += len(validated_rules)
                
                return result
            else:
                return {'error': response.get('error', 'Download failed')}
                
        except Exception as e:
            logger.error(f"Community rules download failed: {str(e)}")
            return {'error': str(e)}
    
    async def participate_in_challenge(self, challenge_id: str) -> Dict[str, Any]:
        """Participate in community challenge."""
        
        if not self.current_user:
            return {'error': 'User not authenticated'}
        
        try:
            logger.info(f"Participating in challenge: {challenge_id}")
            
            # Get challenge details
            challenge = await self._get_challenge(challenge_id)
            if not challenge:
                return {'error': 'Challenge not found'}
            
            # Check if already participating
            if self.current_user.member_id in challenge.participants:
                return {'error': 'Already participating in this challenge'}
            
            # Submit participation
            participation_data = {
                'challenge_id': challenge_id,
                'member_id': self.current_user.member_id
            }
            
            response = await self._api_request('POST', '/challenges/participate', participation_data)
            
            if response.get('success'):
                challenge.participants.add(self.current_user.member_id)
                self.stats['challenges_participated'] += 1
                
                return {
                    'success': True,
                    'challenge_id': challenge_id,
                    'challenge_title': challenge.title,
                    'end_date': challenge.end_date,
                    'participants_count': len(challenge.participants)
                }
            else:
                return {'error': response.get('error', 'Participation failed')}
                
        except Exception as e:
            logger.error(f"Challenge participation failed: {str(e)}")
            return {'error': str(e)}
    
    async def get_leaderboard(self, category: str = "overall", 
                            timeframe: str = "monthly") -> Dict[str, Any]:
        """Get community leaderboard."""
        
        try:
            logger.info(f"Fetching leaderboard: {category}/{timeframe}")
            
            # Check cache
            cache_key = f"leaderboard_{category}_{timeframe}"
            
            if self._is_cache_valid(cache_key):
                self.stats['cache_hits'] += 1
                return self.cache[cache_key]
            
            self.stats['cache_misses'] += 1
            
            # Fetch from API
            params = {
                'category': category,
                'timeframe': timeframe
            }
            
            response = await self._api_request('GET', '/leaderboard', params=params)
            
            if response.get('success'):
                result = {
                    'success': True,
                    'category': category,
                    'timeframe': timeframe,
                    'leaderboard': response.get('leaderboard', []),
                    'user_rank': response.get('user_rank'),
                    'total_participants': response.get('total_participants', 0)
                }
                
                # Cache result
                self._cache_data(cache_key, result)
                
                return result
            else:
                return {'error': response.get('error', 'Leaderboard fetch failed')}
                
        except Exception as e:
            logger.error(f"Leaderboard fetch failed: {str(e)}")
            return {'error': str(e)}
    
    async def get_community_insights(self) -> Dict[str, Any]:
        """Get community insights and statistics."""
        
        try:
            logger.info("Fetching community insights")
            
            # Check cache
            cache_key = "community_insights"
            
            if self._is_cache_valid(cache_key):
                self.stats['cache_hits'] += 1
                return self.cache[cache_key]
            
            self.stats['cache_misses'] += 1
            
            # Fetch from API
            response = await self._api_request('GET', '/insights')
            
            if response.get('success'):
                insights = response.get('insights', {})
                
                # Add local statistics
                insights['local_stats'] = {
                    'contributions_shared': self.stats['contributions_shared'],
                    'contributions_downloaded': self.stats['contributions_downloaded'],
                    'challenges_participated': self.stats['challenges_participated'],
                    'reputation_score': self.current_user.reputation_score if self.current_user else 0
                }
                
                result = {
                    'success': True,
                    'insights': insights,
                    'generated_at': time.time()
                }
                
                # Cache result
                self._cache_data(cache_key, result)
                
                return result
            else:
                return {'error': response.get('error', 'Insights fetch failed')}
                
        except Exception as e:
            logger.error(f"Community insights fetch failed: {str(e)}")
            return {'error': str(e)}
    
    async def search_community_content(self, query: str, 
                                     content_types: List[str] = None) -> Dict[str, Any]:
        """Search community content."""
        
        try:
            logger.info(f"Searching community content: {query}")
            
            content_types = content_types or ['security_rule', 'plugin', 'template']
            
            # Prepare search parameters
            params = {
                'query': query,
                'types': content_types,
                'limit': 50
            }
            
            response = await self._api_request('GET', '/search', params=params)
            
            if response.get('success'):
                results = response.get('results', [])
                
                # Enhance results with local data
                enhanced_results = []
                for result in results:
                    # Add local usage data if available
                    contribution_id = result.get('contribution_id')
                    if contribution_id in self.contributions:
                        local_contribution = self.contributions[contribution_id]
                        result['local_usage'] = {
                            'downloaded': True,
                            'usage_count': local_contribution.usage_count
                        }
                    
                    enhanced_results.append(result)
                
                return {
                    'success': True,
                    'query': query,
                    'results': enhanced_results,
                    'total_results': len(enhanced_results)
                }
            else:
                return {'error': response.get('error', 'Search failed')}
                
        except Exception as e:
            logger.error(f"Community search failed: {str(e)}")
            return {'error': str(e)}
    
    # Private methods
    
    async def _load_user_profile(self):
        """Load user profile from local storage."""
        
        try:
            profile_file = Path.home() / ".njordscan" / "community_profile.json"
            
            if profile_file.exists():
                with open(profile_file) as f:
                    data = json.load(f)
                
                if 'member_id' in data:
                    member = CommunityMember(**data)
                    self.current_user = member
                    self.members[member.member_id] = member
                    
                    logger.info(f"Loaded user profile: {member.username}")
                
        except Exception as e:
            logger.warning(f"Failed to load user profile: {str(e)}")
    
    async def _save_user_profile(self):
        """Save user profile to local storage."""
        
        if not self.current_user:
            return
        
        try:
            profile_dir = Path.home() / ".njordscan"
            profile_dir.mkdir(exist_ok=True)
            
            profile_file = profile_dir / "community_profile.json"
            
            # Convert member to dict
            profile_data = {
                'member_id': self.current_user.member_id,
                'username': self.current_user.username,
                'email': self.current_user.email,
                'reputation_score': self.current_user.reputation_score,
                'reputation_level': self.current_user.reputation_level.value,
                'contributions_count': self.current_user.contributions_count,
                'specializations': list(self.current_user.specializations),
                'frameworks_expertise': list(self.current_user.frameworks_expertise),
                'badges': self.current_user.badges,
                'achievements': self.current_user.achievements,
                'join_date': self.current_user.join_date,
                'last_active': time.time()
            }
            
            with open(profile_file, 'w') as f:
                json.dump(profile_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save user profile: {str(e)}")
    
    async def _sync_community_data(self):
        """Sync with community API."""
        
        try:
            if not self.current_user:
                return
            
            logger.info("Syncing community data")
            
            # Sync user profile
            profile_response = await self._api_request('GET', f'/members/{self.current_user.member_id}')
            
            if profile_response.get('success'):
                profile_data = profile_response['member']
                
                # Update local profile
                self.current_user.reputation_score = profile_data.get('reputation_score', 0)
                self.current_user.reputation_level = ReputationLevel(
                    profile_data.get('reputation_level', 'newcomer')
                )
                self.current_user.contributions_count = profile_data.get('contributions_count', 0)
                self.current_user.badges = profile_data.get('badges', [])
                self.current_user.achievements = profile_data.get('achievements', [])
            
            # Sync contributions
            contributions_response = await self._api_request(
                'GET', f'/members/{self.current_user.member_id}/contributions'
            )
            
            if contributions_response.get('success'):
                for contrib_data in contributions_response.get('contributions', []):
                    contribution = self._deserialize_contribution(contrib_data)
                    self.contributions[contribution.contribution_id] = contribution
            
            logger.info("Community data sync completed")
            
        except Exception as e:
            logger.error(f"Community data sync failed: {str(e)}")
    
    async def _api_request(self, method: str, endpoint: str, 
                         data: Dict[str, Any] = None, 
                         params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make API request to community service."""
        
        if not self.session:
            return {'error': 'HTTP session not available'}
        
        try:
            url = f"{self.config.community_api_url}{endpoint}"
            headers = {}
            
            if self.config.api_key:
                headers['Authorization'] = f'Bearer {self.config.api_key}'
            
            if self.current_user:
                headers['X-User-ID'] = self.current_user.member_id
            
            self.stats['api_requests'] += 1
            
            if method.upper() == 'GET':
                async with self.session.get(url, params=params, headers=headers) as response:
                    return await response.json()
            
            elif method.upper() == 'POST':
                async with self.session.post(url, json=data, headers=headers) as response:
                    return await response.json()
            
            elif method.upper() == 'PUT':
                async with self.session.put(url, json=data, headers=headers) as response:
                    return await response.json()
            
            elif method.upper() == 'DELETE':
                async with self.session.delete(url, headers=headers) as response:
                    return await response.json()
            
            else:
                return {'error': f'Unsupported HTTP method: {method}'}
                
        except Exception as e:
            logger.error(f"API request failed: {str(e)}")
            return {'error': str(e)}
    
    async def _update_reputation(self, member_id: str, action: str, points: int):
        """Update member reputation."""
        
        if member_id == self.current_user.member_id:
            self.current_user.reputation_score += points
            self.stats['reputation_gained'] += points
            
            # Check for level up
            new_level = self._calculate_reputation_level(self.current_user.reputation_score)
            if new_level != self.current_user.reputation_level:
                self.current_user.reputation_level = new_level
                logger.info(f"Reputation level up: {new_level.value}")
    
    def _calculate_reputation_level(self, score: int) -> ReputationLevel:
        """Calculate reputation level from score."""
        
        if score >= 10000:
            return ReputationLevel.GUARDIAN
        elif score >= 5000:
            return ReputationLevel.MAINTAINER
        elif score >= 2000:
            return ReputationLevel.EXPERT
        elif score >= 500:
            return ReputationLevel.TRUSTED
        elif score >= 100:
            return ReputationLevel.CONTRIBUTOR
        else:
            return ReputationLevel.NEWCOMER
    
    async def _anonymize_finding(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize sensitive data in vulnerability finding."""
        
        anonymized = finding_data.copy()
        
        # Remove sensitive fields
        sensitive_fields = [
            'file_path', 'project_name', 'organization',
            'internal_urls', 'api_keys', 'credentials'
        ]
        
        for field in sensitive_fields:
            if field in anonymized:
                del anonymized[field]
        
        # Hash identifiable information
        if 'code_snippet' in anonymized:
            # Keep pattern but remove specific values
            anonymized['code_snippet'] = self._anonymize_code_snippet(
                anonymized['code_snippet']
            )
        
        # Add anonymization metadata
        anonymized['anonymized'] = True
        anonymized['anonymized_at'] = time.time()
        
        return anonymized
    
    def _anonymize_code_snippet(self, code: str) -> str:
        """Anonymize code snippet while preserving patterns."""
        
        # Replace string literals with placeholders
        import re
        
        # Replace quoted strings
        code = re.sub(r'"[^"]*"', '"[STRING]"', code)
        code = re.sub(r"'[^']*'", "'[STRING]'", code)
        
        # Replace numeric literals
        code = re.sub(r'\b\d+\b', '[NUMBER]', code)
        
        # Replace URLs
        code = re.sub(r'https?://[^\s]+', '[URL]', code)
        
        return code
    
    def _serialize_contribution(self, contribution: CommunityContribution) -> Dict[str, Any]:
        """Serialize contribution for API transmission."""
        
        return {
            'contribution_id': contribution.contribution_id,
            'contributor_id': contribution.contributor_id,
            'type': contribution.contribution_type.value,
            'title': contribution.title,
            'description': contribution.description,
            'content': contribution.content,
            'tags': list(contribution.tags),
            'category': contribution.category,
            'version': contribution.version
        }
    
    def _deserialize_contribution(self, data: Dict[str, Any]) -> CommunityContribution:
        """Deserialize contribution from API response."""
        
        return CommunityContribution(
            contribution_id=data['contribution_id'],
            contributor_id=data['contributor_id'],
            contribution_type=ContributionType(data['type']),
            title=data['title'],
            description=data['description'],
            content=data.get('content', {}),
            tags=set(data.get('tags', [])),
            category=data.get('category', ''),
            status=ContributionStatus(data.get('status', 'published')),
            downloads=data.get('downloads', 0),
            likes=data.get('likes', 0),
            usage_count=data.get('usage_count', 0),
            effectiveness_score=data.get('effectiveness_score', 0.0),
            community_rating=data.get('community_rating', 0.0),
            version=data.get('version', '1.0.0')
        )
    
    async def _validate_community_rule(self, rule_data: Dict[str, Any]) -> bool:
        """Validate community security rule."""
        
        # Basic validation
        required_fields = ['rule_id', 'name', 'pattern', 'severity']
        
        for field in required_fields:
            if field not in rule_data:
                return False
        
        # Pattern validation
        try:
            import re
            re.compile(rule_data['pattern'])
        except re.error:
            return False
        
        # Severity validation
        valid_severities = ['low', 'medium', 'high', 'critical']
        if rule_data['severity'] not in valid_severities:
            return False
        
        return True
    
    async def _get_challenge(self, challenge_id: str) -> Optional[Challenge]:
        """Get challenge by ID."""
        
        if challenge_id in self.challenges:
            return self.challenges[challenge_id]
        
        # Fetch from API
        response = await self._api_request('GET', f'/challenges/{challenge_id}')
        
        if response.get('success'):
            challenge_data = response['challenge']
            challenge = Challenge(
                challenge_id=challenge_data['challenge_id'],
                title=challenge_data['title'],
                description=challenge_data['description'],
                challenge_type=challenge_data['type'],
                difficulty_level=challenge_data['difficulty'],
                category=challenge_data['category'],
                start_date=challenge_data['start_date'],
                end_date=challenge_data['end_date'],
                duration_days=challenge_data['duration_days'],
                participants=set(challenge_data.get('participants', [])),
                is_active=challenge_data.get('is_active', True)
            )
            
            self.challenges[challenge_id] = challenge
            return challenge
        
        return None
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is valid."""
        
        if cache_key not in self.cache:
            return False
        
        if cache_key not in self.cache_timestamps:
            return False
        
        age = time.time() - self.cache_timestamps[cache_key]
        return age < self.config.cache_ttl_seconds
    
    def _cache_data(self, cache_key: str, data: Any):
        """Cache data with timestamp."""
        
        self.cache[cache_key] = data
        self.cache_timestamps[cache_key] = time.time()
    
    # Background workers
    
    async def _sync_worker(self):
        """Background worker for syncing community data."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.contribution_sync_interval)
                
                if self.config.auto_sync_contributions:
                    await self._sync_community_data()
                
            except Exception as e:
                logger.error(f"Sync worker error: {str(e)}")
    
    async def _cache_cleanup_worker(self):
        """Background worker for cache cleanup."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Clean up expired cache entries
                current_time = time.time()
                expired_keys = []
                
                for key, timestamp in self.cache_timestamps.items():
                    if current_time - timestamp > self.config.cache_ttl_seconds:
                        expired_keys.append(key)
                
                for key in expired_keys:
                    del self.cache[key]
                    del self.cache_timestamps[key]
                
                logger.debug(f"Cache cleanup: removed {len(expired_keys)} expired entries")
                
            except Exception as e:
                logger.error(f"Cache cleanup worker error: {str(e)}")
    
    async def _activity_tracker(self):
        """Background worker for tracking user activity."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(300)  # Update every 5 minutes
                
                if self.current_user:
                    self.current_user.last_active = time.time()
                    await self._save_user_profile()
                
            except Exception as e:
                logger.error(f"Activity tracker error: {str(e)}")
    
    async def _challenges_worker(self):
        """Background worker for challenge management."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Check every hour
                
                # Fetch active challenges
                response = await self._api_request('GET', '/challenges/active')
                
                if response.get('success'):
                    for challenge_data in response.get('challenges', []):
                        challenge_id = challenge_data['challenge_id']
                        if challenge_id not in self.challenges:
                            # New challenge available
                            logger.info(f"New challenge available: {challenge_data['title']}")
                
            except Exception as e:
                logger.error(f"Challenges worker error: {str(e)}")
    
    async def shutdown(self):
        """Shutdown community hub."""
        
        logger.info("Shutting down Community Hub")
        
        self.running = False
        self.shutdown_event.set()
        
        # Save user profile
        if self.current_user:
            await self._save_user_profile()
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Close HTTP session
        if self.session:
            await self.session.close()
        
        logger.info("Community Hub shutdown completed")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get community hub statistics."""
        
        stats = dict(self.stats)
        stats['uptime'] = time.time() - self.start_time
        stats['members_count'] = len(self.members)
        stats['contributions_count'] = len(self.contributions)
        stats['challenges_count'] = len(self.challenges)
        stats['cache_size'] = len(self.cache)
        
        if self.current_user:
            stats['user_profile'] = {
                'username': self.current_user.username,
                'reputation_score': self.current_user.reputation_score,
                'reputation_level': self.current_user.reputation_level.value,
                'contributions_count': self.current_user.contributions_count,
                'badges_count': len(self.current_user.badges)
            }
        
        return stats
