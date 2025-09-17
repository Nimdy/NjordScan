"""
Maintainer Profile Analysis for NPM Attack Detection

Advanced analysis of package maintainers to detect suspicious patterns,
account takeovers, and social engineering attempts.
"""

import asyncio
import time
import json
import re
import hashlib
import difflib
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
import numpy as np
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import aiohttp
import aiofiles
from pathlib import Path

logger = logging.getLogger(__name__)

class MaintainerRiskLevel(Enum):
    """Maintainer risk levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SuspiciousPattern(Enum):
    """Types of suspicious maintainer patterns."""
    NEW_MAINTAINER = "new_maintainer"
    RAPID_ACTIVITY = "rapid_activity"
    SUSPICIOUS_EMAIL = "suspicious_email"
    GENERIC_NAME = "generic_name"
    NO_HISTORY = "no_history"
    MULTIPLE_ACCOUNTS = "multiple_accounts"
    ACCOUNT_TAKEOVER = "account_takeover"
    SOCIAL_ENGINEERING = "social_engineering"

@dataclass
class MaintainerProfile:
    """Maintainer profile information."""
    name: str
    email: str
    github_username: str = ""
    npm_username: str = ""
    
    # Profile metadata
    account_created: str = ""
    last_active: str = ""
    total_packages: int = 0
    total_downloads: int = 0
    
    # Activity patterns
    packages_created: List[str] = field(default_factory=list)
    packages_updated: List[str] = field(default_factory=list)
    recent_activity: List[Dict[str, Any]] = field(default_factory=list)
    
    # Risk indicators
    risk_level: MaintainerRiskLevel = MaintainerRiskLevel.LOW
    suspicious_patterns: List[SuspiciousPattern] = field(default_factory=list)
    confidence_score: float = 0.0
    
    # Analysis metadata
    analysis_time: float = 0.0
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MaintainerAnalysisResult:
    """Result of maintainer analysis."""
    maintainer: MaintainerProfile
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    similar_maintainers: List[Dict[str, Any]] = field(default_factory=list)
    activity_anomalies: List[Dict[str, Any]] = field(default_factory=list)

class MaintainerProfileAnalyzer:
    """Advanced maintainer profile analyzer for detecting suspicious patterns."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Analysis configuration
        self.analysis_config = {
            'enable_new_maintainer_detection': self.config.get('enable_new_maintainer_detection', True),
            'enable_activity_analysis': self.config.get('enable_activity_analysis', True),
            'enable_email_analysis': self.config.get('enable_email_analysis', True),
            'enable_name_analysis': self.config.get('enable_name_analysis', True),
            'enable_account_takeover_detection': self.config.get('enable_account_takeover_detection', True),
            'enable_social_engineering_detection': self.config.get('enable_social_engineering_detection', True),
            'suspicious_activity_threshold': self.config.get('suspicious_activity_threshold', 10),
            'new_maintainer_threshold_days': self.config.get('new_maintainer_threshold_days', 30),
            'rapid_activity_threshold': self.config.get('rapid_activity_threshold', 5),
            'max_concurrent_analyses': self.config.get('max_concurrent_analyses', 5),
        }
        
        # Load suspicious patterns
        self.suspicious_email_patterns = self._load_suspicious_email_patterns()
        self.generic_name_patterns = self._load_generic_name_patterns()
        self.social_engineering_patterns = self._load_social_engineering_patterns()
        
        # Known legitimate maintainers (for comparison)
        self.legitimate_maintainers = self._load_legitimate_maintainers()
        
        # Statistics
        self.stats = {
            'maintainers_analyzed': 0,
            'suspicious_maintainers_detected': 0,
            'new_maintainers_detected': 0,
            'account_takeovers_detected': 0,
            'social_engineering_detected': 0,
            'average_analysis_time': 0.0
        }
    
    def _load_suspicious_email_patterns(self) -> List[str]:
        """Load patterns for suspicious email addresses."""
        return [
            r'^[a-z0-9]{8,}@(gmail|yahoo|hotmail|outlook)\.com$',  # Random-looking emails
            r'^[a-z0-9]+@[a-z]+\.[a-z]+$',  # Mixed letters and numbers
            r'^[a-z]{1,3}\d+@[a-z]+\.[a-z]+$',  # Short name + numbers
            r'^[a-z0-9._-]+@(temp|temporary|fake|test)\.(com|org|net)$',  # Temporary domains
            r'^[a-z0-9._-]+@(example|test|demo)\.(com|org|net)$',  # Example domains
            r'^[a-z0-9._-]+@(disposable|throwaway)\.(com|org|net)$',  # Disposable domains
        ]
    
    def _load_generic_name_patterns(self) -> List[str]:
        """Load patterns for generic or suspicious names."""
        return [
            r'^[a-z0-9]{1,6}$',  # Short mixed name + numbers
            r'^[a-z]+\d+$',  # Name + numbers
            r'^[a-z]{1,2}[0-9]{2,}$',  # Very short name + many numbers
            r'^[a-z0-9._-]{15,}$',  # Very long names
            r'^[0-9a-f]{8,}$',  # Hex-like names
            r'^[A-Za-z0-9+/]{10,}={0,2}$',  # Base64-like names
        ]
    
    def _load_social_engineering_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for social engineering detection."""
        return {
            'phishing_indicators': [
                r'urgent',
                r'verify',
                r'confirm',
                r'update',
                r'security',
                r'breach',
                r'compromise',
                r'action required',
                r'immediate',
                r'asap',
            ],
            'authority_impersonation': [
                r'npm support',
                r'npm security',
                r'npm team',
                r'github support',
                r'github security',
                r'node\.js team',
                r'javascript foundation',
            ],
            'urgency_tactics': [
                r'within 24 hours',
                r'within 48 hours',
                r'by tomorrow',
                r'as soon as possible',
                r'before it\'s too late',
                r'final notice',
                r'last chance',
            ]
        }
    
    def _load_legitimate_maintainers(self) -> Set[str]:
        """Load known legitimate maintainers."""
        # This would typically be loaded from a database
        return {
            'sindresorhus', 'tj', 'substack', 'isaacs', 'feross',
            'addyosmani', 'gaearon', 'dan_abramov', 'kentcdodds',
            'babel', 'webpack', 'typescript', 'eslint', 'prettier',
            'facebook', 'google', 'microsoft', 'netflix', 'uber',
            'airbnb', 'stripe', 'shopify', 'github', 'gitlab'
        }
    
    async def analyze_maintainer(self, maintainer_data: Dict[str, Any]) -> MaintainerAnalysisResult:
        """Analyze a maintainer profile for suspicious patterns."""
        
        start_time = time.time()
        logger.info(f"Starting maintainer analysis for: {maintainer_data.get('name', 'unknown')}")
        
        # Create maintainer profile
        maintainer = MaintainerProfile(
            name=maintainer_data.get('name', ''),
            email=maintainer_data.get('email', ''),
            github_username=maintainer_data.get('github_username', ''),
            npm_username=maintainer_data.get('npm_username', ''),
            account_created=maintainer_data.get('account_created', ''),
            last_active=maintainer_data.get('last_active', ''),
            total_packages=maintainer_data.get('total_packages', 0),
            total_downloads=maintainer_data.get('total_downloads', 0),
            packages_created=maintainer_data.get('packages_created', []),
            packages_updated=maintainer_data.get('packages_updated', []),
            recent_activity=maintainer_data.get('recent_activity', [])
        )
        
        result = MaintainerAnalysisResult(maintainer=maintainer)
        
        try:
            # Analyze different aspects
            if self.analysis_config['enable_new_maintainer_detection']:
                await self._analyze_new_maintainer(maintainer, result)
            
            if self.analysis_config['enable_activity_analysis']:
                await self._analyze_activity_patterns(maintainer, result)
            
            if self.analysis_config['enable_email_analysis']:
                await self._analyze_email_patterns(maintainer, result)
            
            if self.analysis_config['enable_name_analysis']:
                await self._analyze_name_patterns(maintainer, result)
            
            if self.analysis_config['enable_account_takeover_detection']:
                await self._analyze_account_takeover_indicators(maintainer, result)
            
            if self.analysis_config['enable_social_engineering_detection']:
                await self._analyze_social_engineering_indicators(maintainer, result)
            
            # Calculate overall risk level
            maintainer.risk_level = self._calculate_risk_level(maintainer)
            maintainer.confidence_score = self._calculate_confidence_score(maintainer)
            
            # Generate recommendations
            result.recommendations = self._generate_recommendations(maintainer)
            
            # Update statistics
            self._update_statistics(maintainer)
            
        except Exception as e:
            logger.error(f"Error analyzing maintainer {maintainer.name}: {e}")
            maintainer.analysis_metadata['error'] = str(e)
        
        maintainer.analysis_time = time.time() - start_time
        return result
    
    async def _analyze_new_maintainer(self, maintainer: MaintainerProfile, result: MaintainerAnalysisResult):
        """Analyze for new maintainer patterns."""
        
        if not maintainer.account_created:
            maintainer.suspicious_patterns.append(SuspiciousPattern.NO_HISTORY)
            return
        
        try:
            # Parse account creation date
            created_date = datetime.fromisoformat(maintainer.account_created.replace('Z', '+00:00'))
            days_since_created = (datetime.now(created_date.tzinfo) - created_date).days
            
            if days_since_created <= self.analysis_config['new_maintainer_threshold_days']:
                maintainer.suspicious_patterns.append(SuspiciousPattern.NEW_MAINTAINER)
                
                # Check if they have many packages (suspicious for new maintainer)
                if maintainer.total_packages > self.analysis_config['suspicious_activity_threshold']:
                    result.activity_anomalies.append({
                        'type': 'new_maintainer_many_packages',
                        'description': f'New maintainer ({days_since_created} days) with {maintainer.total_packages} packages',
                        'severity': 'high'
                    })
        
        except ValueError:
            maintainer.suspicious_patterns.append(SuspiciousPattern.NO_HISTORY)
    
    async def _analyze_activity_patterns(self, maintainer: MaintainerProfile, result: MaintainerAnalysisResult):
        """Analyze maintainer activity patterns."""
        
        # Check for rapid activity
        if len(maintainer.recent_activity) > self.analysis_config['rapid_activity_threshold']:
            maintainer.suspicious_patterns.append(SuspiciousPattern.RAPID_ACTIVITY)
            
            result.activity_anomalies.append({
                'type': 'rapid_activity',
                'description': f'High activity: {len(maintainer.recent_activity)} recent actions',
                'severity': 'medium'
            })
        
        # Check for unusual package creation patterns
        if maintainer.packages_created:
            # Check for packages with similar names (potential typosquatting)
            similar_packages = self._find_similar_packages(maintainer.packages_created)
            if similar_packages:
                result.activity_anomalies.append({
                    'type': 'similar_package_names',
                    'description': f'Packages with similar names: {similar_packages}',
                    'severity': 'high'
                })
        
        # Check for packages with suspicious names
        suspicious_packages = self._find_suspicious_package_names(maintainer.packages_created)
        if suspicious_packages:
            result.activity_anomalies.append({
                'type': 'suspicious_package_names',
                'description': f'Packages with suspicious names: {suspicious_packages}',
                'severity': 'high'
            })
    
    async def _analyze_email_patterns(self, maintainer: MaintainerProfile, result: MaintainerAnalysisResult):
        """Analyze maintainer email patterns."""
        
        if not maintainer.email:
            maintainer.suspicious_patterns.append(SuspiciousPattern.SUSPICIOUS_EMAIL)
            return
        
        # Check against suspicious email patterns
        for pattern in self.suspicious_email_patterns:
            if re.match(pattern, maintainer.email, re.IGNORECASE):
                maintainer.suspicious_patterns.append(SuspiciousPattern.SUSPICIOUS_EMAIL)
                
                result.risk_assessment['suspicious_email'] = {
                    'email': maintainer.email,
                    'pattern': pattern,
                    'severity': 'medium'
                }
                break
        
        # Check for email domain reputation
        email_domain = maintainer.email.split('@')[-1] if '@' in maintainer.email else ''
        if self._is_suspicious_domain(email_domain):
            maintainer.suspicious_patterns.append(SuspiciousPattern.SUSPICIOUS_EMAIL)
            
            result.risk_assessment['suspicious_domain'] = {
                'domain': email_domain,
                'severity': 'high'
            }
    
    async def _analyze_name_patterns(self, maintainer: MaintainerProfile, result: MaintainerAnalysisResult):
        """Analyze maintainer name patterns."""
        
        if not maintainer.name:
            maintainer.suspicious_patterns.append(SuspiciousPattern.GENERIC_NAME)
            return
        
        # Check against generic name patterns
        for pattern in self.generic_name_patterns:
            if re.match(pattern, maintainer.name, re.IGNORECASE):
                maintainer.suspicious_patterns.append(SuspiciousPattern.GENERIC_NAME)
                
                result.risk_assessment['generic_name'] = {
                    'name': maintainer.name,
                    'pattern': pattern,
                    'severity': 'low'
                }
                break
        
        # Check if name is too similar to legitimate maintainers
        similar_maintainers = self._find_similar_maintainers(maintainer.name)
        if similar_maintainers:
            result.similar_maintainers = similar_maintainers
            
            if len(similar_maintainers) > 2:  # Multiple similar names
                maintainer.suspicious_patterns.append(SuspiciousPattern.MULTIPLE_ACCOUNTS)
    
    async def _analyze_account_takeover_indicators(self, maintainer: MaintainerProfile, result: MaintainerAnalysisResult):
        """Analyze for account takeover indicators."""
        
        # Check for sudden change in activity patterns
        if maintainer.recent_activity:
            activity_dates = [activity.get('date', '') for activity in maintainer.recent_activity]
            if self._has_sudden_activity_change(activity_dates):
                maintainer.suspicious_patterns.append(SuspiciousPattern.ACCOUNT_TAKEOVER)
                
                result.activity_anomalies.append({
                    'type': 'sudden_activity_change',
                    'description': 'Sudden change in activity patterns',
                    'severity': 'high'
                })
        
        # Check for packages with different coding styles (potential takeover)
        if maintainer.packages_created:
            coding_style_anomalies = self._analyze_coding_style_consistency(maintainer.packages_created)
            if coding_style_anomalies:
                result.activity_anomalies.append({
                    'type': 'coding_style_inconsistency',
                    'description': 'Inconsistent coding styles across packages',
                    'severity': 'medium'
                })
    
    async def _analyze_social_engineering_indicators(self, maintainer: MaintainerProfile, result: MaintainerAnalysisResult):
        """Analyze for social engineering indicators."""
        
        # This would typically analyze communication patterns, emails, etc.
        # For now, we'll check for suspicious patterns in maintainer data
        
        # Check for suspicious package descriptions
        suspicious_descriptions = self._find_suspicious_descriptions(maintainer.packages_created)
        if suspicious_descriptions:
            result.activity_anomalies.append({
                'type': 'suspicious_descriptions',
                'description': f'Packages with suspicious descriptions: {suspicious_descriptions}',
                'severity': 'medium'
            })
    
    def _find_similar_packages(self, package_names: List[str]) -> List[str]:
        """Find packages with similar names."""
        
        similar_packages = []
        
        for i, pkg1 in enumerate(package_names):
            for pkg2 in package_names[i+1:]:
                similarity = difflib.SequenceMatcher(None, pkg1.lower(), pkg2.lower()).ratio()
                if similarity > 0.8:  # High similarity
                    similar_packages.append(f"{pkg1} ~ {pkg2}")
        
        return similar_packages
    
    def _find_suspicious_package_names(self, package_names: List[str]) -> List[str]:
        """Find packages with suspicious names."""
        
        suspicious_packages = []
        
        for pkg_name in package_names:
            # Check for typosquatting patterns
            if self._is_suspicious_package_name(pkg_name):
                suspicious_packages.append(pkg_name)
        
        return suspicious_packages
    
    def _is_suspicious_package_name(self, name: str) -> bool:
        """Check if a package name is suspicious."""
        
        suspicious_patterns = [
            r'^[a-z]{1,3}\d+$',  # Short name + numbers
            r'^[a-z]+\d+$',  # Name + numbers
            r'^[a-z0-9._-]{20,}$',  # Very long names
            r'^[0-9a-f]{8,}$',  # Hex-like names
            r'^[A-Za-z0-9+/]{10,}={0,2}$',  # Base64-like names
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, name, re.IGNORECASE):
                return True
        
        return False
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if an email domain is suspicious."""
        
        suspicious_domains = {
            'temp-mail.org', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'throwaway.email', 'disposable.email'
        }
        
        return domain.lower() in suspicious_domains
    
    def _find_similar_maintainers(self, name: str) -> List[Dict[str, Any]]:
        """Find maintainers with similar names."""
        
        similar_maintainers = []
        
        for legitimate_maintainer in self.legitimate_maintainers:
            similarity = difflib.SequenceMatcher(None, name.lower(), legitimate_maintainer.lower()).ratio()
            if similarity > 0.8:  # High similarity
                similar_maintainers.append({
                    'name': legitimate_maintainer,
                    'similarity': similarity
                })
        
        return similar_maintainers
    
    def _has_sudden_activity_change(self, activity_dates: List[str]) -> bool:
        """Check for sudden changes in activity patterns."""
        
        if len(activity_dates) < 2:
            return False
        
        try:
            # Parse dates and check for gaps
            dates = [datetime.fromisoformat(date.replace('Z', '+00:00')) for date in activity_dates if date]
            dates.sort()
            
            # Check for large gaps in activity
            for i in range(1, len(dates)):
                gap = (dates[i] - dates[i-1]).days
                if gap > 365:  # More than a year gap
                    return True
            
            return False
        
        except ValueError:
            return False
    
    def _analyze_coding_style_consistency(self, package_names: List[str]) -> bool:
        """Analyze coding style consistency across packages."""
        
        # This is a simplified check - in practice, you'd analyze actual code
        # For now, we'll check for naming pattern consistency
        
        if len(package_names) < 2:
            return False
        
        # Check if all packages follow similar naming patterns
        patterns = []
        for name in package_names:
            if re.match(r'^[a-z-]+$', name):
                patterns.append('kebab-case')
            elif re.match(r'^[a-z]+$', name):
                patterns.append('lowercase')
            elif re.match(r'^[A-Z][a-z]+$', name):
                patterns.append('PascalCase')
            else:
                patterns.append('mixed')
        
        # If patterns are inconsistent, it might indicate different authors
        return len(set(patterns)) > 1
    
    def _find_suspicious_descriptions(self, package_names: List[str]) -> List[str]:
        """Find packages with suspicious descriptions."""
        
        # This would typically analyze actual package descriptions
        # For now, we'll return empty list
        return []
    
    def _calculate_risk_level(self, maintainer: MaintainerProfile) -> MaintainerRiskLevel:
        """Calculate overall risk level for maintainer."""
        
        if not maintainer.suspicious_patterns:
            return MaintainerRiskLevel.LOW
        
        # Weight different suspicious patterns
        pattern_weights = {
            SuspiciousPattern.NEW_MAINTAINER: 1,
            SuspiciousPattern.RAPID_ACTIVITY: 2,
            SuspiciousPattern.SUSPICIOUS_EMAIL: 3,
            SuspiciousPattern.GENERIC_NAME: 1,
            SuspiciousPattern.NO_HISTORY: 2,
            SuspiciousPattern.MULTIPLE_ACCOUNTS: 3,
            SuspiciousPattern.ACCOUNT_TAKEOVER: 4,
            SuspiciousPattern.SOCIAL_ENGINEERING: 3,
        }
        
        total_weight = sum(pattern_weights.get(pattern, 1) for pattern in maintainer.suspicious_patterns)
        
        if total_weight >= 8:
            return MaintainerRiskLevel.CRITICAL
        elif total_weight >= 5:
            return MaintainerRiskLevel.HIGH
        elif total_weight >= 3:
            return MaintainerRiskLevel.MEDIUM
        else:
            return MaintainerRiskLevel.LOW
    
    def _calculate_confidence_score(self, maintainer: MaintainerProfile) -> float:
        """Calculate confidence score for the analysis."""
        
        if not maintainer.suspicious_patterns:
            return 0.0
        
        # Base confidence on number of suspicious patterns
        base_confidence = min(len(maintainer.suspicious_patterns) * 0.2, 0.8)
        
        # Add confidence based on specific indicators
        if SuspiciousPattern.ACCOUNT_TAKEOVER in maintainer.suspicious_patterns:
            base_confidence += 0.2
        if SuspiciousPattern.SUSPICIOUS_EMAIL in maintainer.suspicious_patterns:
            base_confidence += 0.1
        
        return min(base_confidence, 1.0)
    
    def _generate_recommendations(self, maintainer: MaintainerProfile) -> List[str]:
        """Generate security recommendations based on analysis."""
        
        recommendations = []
        
        if SuspiciousPattern.NEW_MAINTAINER in maintainer.suspicious_patterns:
            recommendations.append("New maintainer detected - verify package authenticity before installation")
        
        if SuspiciousPattern.SUSPICIOUS_EMAIL in maintainer.suspicious_patterns:
            recommendations.append("Suspicious email pattern detected - verify maintainer identity")
        
        if SuspiciousPattern.ACCOUNT_TAKEOVER in maintainer.suspicious_patterns:
            recommendations.append("Potential account takeover detected - review maintainer activity")
        
        if SuspiciousPattern.RAPID_ACTIVITY in maintainer.suspicious_patterns:
            recommendations.append("Unusual activity pattern detected - monitor for suspicious behavior")
        
        if not recommendations:
            recommendations.append("No specific security concerns detected for this maintainer")
        
        return recommendations
    
    def _update_statistics(self, maintainer: MaintainerProfile):
        """Update analysis statistics."""
        
        self.stats['maintainers_analyzed'] += 1
        
        if maintainer.suspicious_patterns:
            self.stats['suspicious_maintainers_detected'] += 1
        
        if SuspiciousPattern.NEW_MAINTAINER in maintainer.suspicious_patterns:
            self.stats['new_maintainers_detected'] += 1
        
        if SuspiciousPattern.ACCOUNT_TAKEOVER in maintainer.suspicious_patterns:
            self.stats['account_takeovers_detected'] += 1
        
        if SuspiciousPattern.SOCIAL_ENGINEERING in maintainer.suspicious_patterns:
            self.stats['social_engineering_detected'] += 1
        
        # Update average analysis time
        total_time = self.stats['average_analysis_time'] * (self.stats['maintainers_analyzed'] - 1)
        self.stats['average_analysis_time'] = (total_time + maintainer.analysis_time) / self.stats['maintainers_analyzed']
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset analysis statistics."""
        self.stats = {
            'maintainers_analyzed': 0,
            'suspicious_maintainers_detected': 0,
            'new_maintainers_detected': 0,
            'account_takeovers_detected': 0,
            'social_engineering_detected': 0,
            'average_analysis_time': 0.0
        }
