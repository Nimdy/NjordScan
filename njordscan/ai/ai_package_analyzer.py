"""
AI Package Analyzer for NPM Attack Detection

Advanced AI-powered analysis for detecting AI-generated malicious packages,
typosquatting attempts, and sophisticated supply chain attacks.
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
from pathlib import Path
import logging
import numpy as np
from collections import defaultdict, Counter
import aiohttp
import aiofiles

from ..vulnerability import Vulnerability, Severity, Confidence
from ..vulnerability_types import VulnerabilityType, normalize_vulnerability_type

logger = logging.getLogger(__name__)

class AIPackageThreatType(Enum):
    """Types of AI-powered package threats."""
    AI_GENERATED_MALWARE = "ai_generated_malware"
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    MAINTAINER_IMPERSONATION = "maintainer_impersonation"
    ACCOUNT_TAKEOVER = "account_takeover"
    AI_OBFUSCATION = "ai_obfuscation"
    CRYPTO_TARGETING = "crypto_targeting"
    AI_CLI_EXPLOITATION = "ai_cli_exploitation"
    DATA_EXFILTRATION = "data_exfiltration"
    SOCIAL_ENGINEERING = "social_engineering"

class PackageRiskLevel(Enum):
    """Package risk levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AIPackageAnalysisResult:
    """Result of AI package analysis."""
    package_name: str
    package_version: str
    analysis_time: float
    
    # Threat detection results
    detected_threats: List[AIPackageThreatType] = field(default_factory=list)
    risk_level: PackageRiskLevel = PackageRiskLevel.LOW
    confidence_score: float = 0.0
    
    # Detailed analysis
    ai_generated_indicators: List[str] = field(default_factory=list)
    typosquatting_matches: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)
    maintainer_anomalies: List[str] = field(default_factory=list)
    
    # Code analysis
    obfuscation_score: float = 0.0
    crypto_targeting_score: float = 0.0
    data_exfiltration_score: float = 0.0
    ai_cli_exploitation_score: float = 0.0
    
    # Metadata
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

@dataclass
class PackageSimilarityResult:
    """Result of package name similarity analysis."""
    target_package: str
    similar_packages: List[Dict[str, Any]] = field(default_factory=list)
    typosquatting_candidates: List[Dict[str, Any]] = field(default_factory=list)
    similarity_scores: Dict[str, float] = field(default_factory=dict)

class AIPackageAnalyzer:
    """AI-powered package analyzer for detecting sophisticated npm attacks."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Analysis configuration
        self.analysis_config = {
            'enable_ai_detection': self.config.get('enable_ai_detection', True),
            'enable_typosquatting_detection': self.config.get('enable_typosquatting_detection', True),
            'enable_maintainer_analysis': self.config.get('enable_maintainer_analysis', True),
            'enable_code_analysis': self.config.get('enable_code_analysis', True),
            'similarity_threshold': self.config.get('similarity_threshold', 0.8),
            'typosquatting_threshold': self.config.get('typosquatting_threshold', 0.9),
            'obfuscation_threshold': self.config.get('obfuscation_threshold', 0.005),
            'crypto_targeting_threshold': self.config.get('crypto_targeting_threshold', 0.04),
            'data_exfiltration_threshold': self.config.get('data_exfiltration_threshold', 0.03),
            'ai_cli_exploitation_threshold': self.config.get('ai_cli_exploitation_threshold', 0.04),
            'max_concurrent_analyses': self.config.get('max_concurrent_analyses', 5),
            'analysis_timeout': self.config.get('analysis_timeout', 60)
        }
        
        # AI detection patterns
        self.ai_generated_patterns = self._load_ai_generated_patterns()
        self.obfuscation_patterns = self._load_obfuscation_patterns()
        self.crypto_targeting_patterns = self._load_crypto_targeting_patterns()
        self.data_exfiltration_patterns = self._load_data_exfiltration_patterns()
        self.ai_cli_patterns = self._load_ai_cli_patterns()
        
        # Known legitimate packages for comparison
        self.legitimate_packages = self._load_legitimate_packages()
        
        # Statistics
        self.stats = {
            'packages_analyzed': 0,
            'threats_detected': 0,
            'ai_generated_detected': 0,
            'typosquatting_detected': 0,
            'maintainer_anomalies_detected': 0,
            'average_analysis_time': 0.0
        }
    
    def _load_ai_generated_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that indicate AI-generated code."""
        return {
            'variable_naming': [
                r'var\s+[a-z]{1,2}\d+',  # var a1, b2, etc.
                r'let\s+[a-z]{1,2}\d+',
                r'const\s+[a-z]{1,2}\d+',
                r'function\s+[a-z]{1,2}\d+',
            ],
            'code_structure': [
                r'function\s+\w+\s*\(\s*\)\s*{\s*return\s*[^;]+;\s*}',  # Simple return functions
                r'const\s+\w+\s*=\s*\([^)]*\)\s*=>\s*[^;]+;',  # Arrow functions
                r'if\s*\(\s*true\s*\)\s*{\s*[^}]*\s*}',  # Always true conditions
            ],
            'ai_signatures': [
                r'\/\/\s*Generated\s+by\s+AI',
                r'\/\*\s*AI\s+Generated\s+\*\/',
                r'\/\/\s*Auto-generated',
                r'\/\*\s*Machine\s+Generated\s+\*\/',
            ],
            'obfuscation_indicators': [
                r'[a-zA-Z]{20,}',  # Very long variable names
                r'[0-9a-fA-F]{32,}',  # Hex strings
                r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64-like strings
                r'eval\s*\(\s*[^)]+\)',  # Eval usage
                r'Function\s*\(\s*[^)]+\)',  # Function constructor
            ]
        }
    
    def _load_obfuscation_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that indicate code obfuscation."""
        return {
            'string_obfuscation': [
                r'String\.fromCharCode\s*\([^)]+\)',
                r'atob\s*\(\s*["\'][^"\']+["\']\s*\)',
                r'btoa\s*\(\s*[^)]+\s*\)',
                r'unescape\s*\(\s*[^)]+\s*\)',
                r'decodeURIComponent\s*\(\s*[^)]+\s*\)',
            ],
            'control_flow_obfuscation': [
                r'while\s*\(\s*true\s*\)\s*{',
                r'for\s*\(\s*;;\s*\)\s*{',
                r'if\s*\(\s*Math\.random\s*\(\s*\)\s*>\s*0\.5\s*\)',
                r'switch\s*\(\s*Math\.floor\s*\(\s*Math\.random\s*\(\s*\)\s*\*\s*\d+\s*\)\s*\)',
            ],
            'variable_obfuscation': [
                r'var\s+[a-zA-Z_$][a-zA-Z0-9_$]{10,}\s*=',
                r'let\s+[a-zA-Z_$][a-zA-Z0-9_$]{10,}\s*=',
                r'const\s+[a-zA-Z_$][a-zA-Z0-9_$]{10,}\s*=',
            ]
        }
    
    def _load_crypto_targeting_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that indicate cryptocurrency targeting."""
        return {
            'wallet_apis': [
                r'window\.ethereum',
                r'web3\.eth',
                r'bitcoin\.',
                r'wallet\.',
                r'crypto\.',
                r'blockchain\.',
            ],
            'transaction_hooks': [
                r'addEventListener\s*\(\s*["\']message["\']',
                r'postMessage\s*\(',
                r'chrome\.runtime\.sendMessage',
                r'browser\.runtime\.sendMessage',
            ],
            'crypto_keywords': [
                r'privateKey',
                r'seedPhrase',
                r'mnemonic',
                r'walletAddress',
                r'cryptocurrency',
                r'bitcoin',
                r'ethereum',
                r'wallet',
            ]
        }
    
    def _load_data_exfiltration_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that indicate data exfiltration."""
        return {
            'network_requests': [
                r'fetch\s*\(\s*["\'][^"\']*["\']',
                r'XMLHttpRequest',
                r'axios\s*\.\s*post',
                r'request\s*\.\s*post',
                r'https?://[^\s"\']+',
            ],
            'data_collection': [
                r'localStorage\s*\.\s*getItem',
                r'sessionStorage\s*\.\s*getItem',
                r'cookie\s*\.\s*get',
                r'document\.cookie',
                r'navigator\.userAgent',
                r'location\.href',
            ],
            'file_operations': [
                r'fs\s*\.\s*readFile',
                r'fs\s*\.\s*writeFile',
                r'fs\s*\.\s*readdir',
                r'path\s*\.\s*join',
            ]
        }
    
    def _load_ai_cli_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that indicate AI CLI exploitation."""
        return {
            'ai_cli_commands': [
                r'claude\s+',
                r'gemini\s+',
                r'chatgpt\s+',
                r'openai\s+',
                r'anthropic\s+',
                r'google\s+ai',
            ],
            'prompt_injection': [
                r'prompt\s*:\s*["\'][^"\']*["\']',
                r'system\s*:\s*["\'][^"\']*["\']',
                r'user\s*:\s*["\'][^"\']*["\']',
                r'role\s*:\s*["\'][^"\']*["\']',
            ],
            'ai_api_calls': [
                r'openai\.api',
                r'anthropic\.api',
                r'google\.ai',
                r'claude\.api',
            ]
        }
    
    def _load_legitimate_packages(self) -> Set[str]:
        """Load known legitimate packages for comparison."""
        # This would typically be loaded from a database or API
        # For now, we'll use a basic set of well-known packages
        return {
            'react', 'vue', 'angular', 'express', 'lodash', 'moment', 'axios',
            'webpack', 'babel', 'typescript', 'eslint', 'prettier', 'jest',
            'mocha', 'chai', 'sinon', 'cypress', 'puppeteer', 'playwright',
            'next', 'nuxt', 'gatsby', 'svelte', 'solid', 'lit', 'stencil'
        }
    
    async def analyze_package(self, package_name: str, package_data: Dict[str, Any], 
                            package_files: Dict[str, str] = None) -> AIPackageAnalysisResult:
        """Analyze a package for AI-powered threats."""
        
        start_time = time.time()
        logger.info(f"Starting AI package analysis for: {package_name}")
        
        result = AIPackageAnalysisResult(
            package_name=package_name,
            package_version=package_data.get('version', 'unknown'),
            analysis_time=start_time
        )
        
        try:
            # AI-generated code detection
            if self.analysis_config['enable_ai_detection']:
                await self._analyze_ai_generated_code(package_files or {}, result)
            
            # Typosquatting detection
            if self.analysis_config['enable_typosquatting_detection']:
                await self._analyze_typosquatting(package_name, result)
            
            # Maintainer analysis
            if self.analysis_config['enable_maintainer_analysis']:
                await self._analyze_maintainer(package_data, result)
            
            # Code analysis
            if self.analysis_config['enable_code_analysis'] and package_files:
                await self._analyze_code_patterns(package_files, result)
            
            # Calculate overall risk level
            result.risk_level = self._calculate_risk_level(result)
            result.confidence_score = self._calculate_confidence_score(result)
            
            # Generate recommendations
            result.recommendations = self._generate_recommendations(result)
            
            # Update statistics
            self._update_statistics(result)
            
        except Exception as e:
            logger.error(f"Error analyzing package {package_name}: {e}")
            result.analysis_metadata['error'] = str(e)
        
        result.analysis_time = time.time() - start_time
        return result
    
    async def _analyze_ai_generated_code(self, package_files: Dict[str, str], result: AIPackageAnalysisResult):
        """Analyze code for AI-generated patterns."""
        
        ai_indicators = []
        
        for file_path, content in package_files.items():
            if not content:
                continue
                
            # Check for AI-generated patterns
            for category, patterns in self.ai_generated_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        ai_indicators.append(f"{category}: {pattern} (found {len(matches)} matches)")
            
            # Check for obfuscation
            obfuscation_score = self._calculate_obfuscation_score(content)
            result.obfuscation_score = max(result.obfuscation_score, obfuscation_score)
            if obfuscation_score > self.analysis_config['obfuscation_threshold']:
                ai_indicators.append(f"High obfuscation score: {obfuscation_score:.2f}")
                result.detected_threats.append(AIPackageThreatType.AI_OBFUSCATION)
        
        if ai_indicators:
            result.detected_threats.append(AIPackageThreatType.AI_GENERATED_MALWARE)
            result.ai_generated_indicators = ai_indicators
    
    async def _analyze_typosquatting(self, package_name: str, result: AIPackageAnalysisResult):
        """Analyze package name for typosquatting attempts."""
        
        similar_packages = []
        typosquatting_candidates = []
        
        for legitimate_package in self.legitimate_packages:
            similarity = difflib.SequenceMatcher(None, package_name.lower(), legitimate_package.lower()).ratio()
            
            if similarity > self.analysis_config['similarity_threshold']:
                similar_packages.append({
                    'package': legitimate_package,
                    'similarity': similarity
                })
            
            if similarity > self.analysis_config['typosquatting_threshold']:
                typosquatting_candidates.append({
                    'package': legitimate_package,
                    'similarity': similarity,
                    'risk': 'high' if similarity > 0.95 else 'medium'
                })
        
        if typosquatting_candidates:
            result.detected_threats.append(AIPackageThreatType.TYPOSQUATTING)
            result.typosquatting_matches = [c['package'] for c in typosquatting_candidates]
    
    async def _analyze_maintainer(self, package_data: Dict[str, Any], result: AIPackageAnalysisResult):
        """Analyze maintainer information for anomalies."""
        
        maintainer_anomalies = []
        
        # Check for suspicious maintainer patterns
        maintainers = package_data.get('maintainers', [])
        if not maintainers:
            maintainer_anomalies.append("No maintainers listed")
        
        for maintainer in maintainers:
            name = maintainer.get('name', '')
            email = maintainer.get('email', '')
            
            # Check for suspicious email patterns
            if email and ('@' not in email or len(email.split('@')) != 2):
                maintainer_anomalies.append(f"Suspicious email format: {email}")
            
            # Check for suspicious name patterns
            if name and (len(name) < 2 or not re.match(r'^[a-zA-Z0-9._-]+$', name)):
                maintainer_anomalies.append(f"Suspicious name format: {name}")
        
        if maintainer_anomalies:
            result.detected_threats.append(AIPackageThreatType.MAINTAINER_IMPERSONATION)
            result.maintainer_anomalies = maintainer_anomalies
    
    async def _analyze_code_patterns(self, package_files: Dict[str, str], result: AIPackageAnalysisResult):
        """Analyze code for malicious patterns."""
        
        for file_path, content in package_files.items():
            if not content:
                continue
            
            # Check for crypto targeting
            crypto_score = self._calculate_crypto_targeting_score(content)
            result.crypto_targeting_score = max(result.crypto_targeting_score, crypto_score)
            if crypto_score > self.analysis_config['crypto_targeting_threshold']:
                result.detected_threats.append(AIPackageThreatType.CRYPTO_TARGETING)
            
            # Check for data exfiltration
            exfiltration_score = self._calculate_data_exfiltration_score(content)
            result.data_exfiltration_score = max(result.data_exfiltration_score, exfiltration_score)
            if exfiltration_score > self.analysis_config['data_exfiltration_threshold']:
                result.detected_threats.append(AIPackageThreatType.DATA_EXFILTRATION)
            
            # Check for AI CLI exploitation
            ai_cli_score = self._calculate_ai_cli_exploitation_score(content)
            result.ai_cli_exploitation_score = max(result.ai_cli_exploitation_score, ai_cli_score)
            if ai_cli_score > self.analysis_config['ai_cli_exploitation_threshold']:
                result.detected_threats.append(AIPackageThreatType.AI_CLI_EXPLOITATION)
    
    def _calculate_obfuscation_score(self, content: str) -> float:
        """Calculate obfuscation score for content."""
        score = 0.0
        total_patterns = 0
        
        for category, patterns in self.obfuscation_patterns.items():
            for pattern in patterns:
                matches = len(re.findall(pattern, content, re.IGNORECASE | re.MULTILINE))
                if matches > 0:
                    score += min(matches * 0.1, 1.0)  # Cap at 1.0 per pattern
                total_patterns += 1
        
        return score / max(total_patterns, 1)
    
    def _calculate_crypto_targeting_score(self, content: str) -> float:
        """Calculate crypto targeting score for content."""
        score = 0.0
        total_patterns = 0
        
        for category, patterns in self.crypto_targeting_patterns.items():
            for pattern in patterns:
                matches = len(re.findall(pattern, content, re.IGNORECASE | re.MULTILINE))
                if matches > 0:
                    score += min(matches * 0.2, 1.0)  # Higher weight for crypto patterns
                total_patterns += 1
        
        return score / max(total_patterns, 1)
    
    def _calculate_data_exfiltration_score(self, content: str) -> float:
        """Calculate data exfiltration score for content."""
        score = 0.0
        total_patterns = 0
        
        for category, patterns in self.data_exfiltration_patterns.items():
            for pattern in patterns:
                matches = len(re.findall(pattern, content, re.IGNORECASE | re.MULTILINE))
                if matches > 0:
                    score += min(matches * 0.15, 1.0)
                total_patterns += 1
        
        return score / max(total_patterns, 1)
    
    def _calculate_ai_cli_exploitation_score(self, content: str) -> float:
        """Calculate AI CLI exploitation score for content."""
        score = 0.0
        total_patterns = 0
        
        for category, patterns in self.ai_cli_patterns.items():
            for pattern in patterns:
                matches = len(re.findall(pattern, content, re.IGNORECASE | re.MULTILINE))
                if matches > 0:
                    score += min(matches * 0.3, 1.0)  # High weight for AI CLI patterns
                total_patterns += 1
        
        return score / max(total_patterns, 1)
    
    def _calculate_risk_level(self, result: AIPackageAnalysisResult) -> PackageRiskLevel:
        """Calculate overall risk level based on detected threats."""
        
        if not result.detected_threats:
            return PackageRiskLevel.LOW
        
        # Weight different threat types
        threat_weights = {
            AIPackageThreatType.AI_GENERATED_MALWARE: 3,
            AIPackageThreatType.TYPOSQUATTING: 2,
            AIPackageThreatType.DEPENDENCY_CONFUSION: 2,
            AIPackageThreatType.MAINTAINER_IMPERSONATION: 2,
            AIPackageThreatType.ACCOUNT_TAKEOVER: 4,
            AIPackageThreatType.AI_OBFUSCATION: 3,
            AIPackageThreatType.CRYPTO_TARGETING: 4,
            AIPackageThreatType.AI_CLI_EXPLOITATION: 3,
            AIPackageThreatType.DATA_EXFILTRATION: 3,
            AIPackageThreatType.SOCIAL_ENGINEERING: 2,
        }
        
        total_weight = sum(threat_weights.get(threat, 1) for threat in result.detected_threats)
        
        if total_weight >= 8:
            return PackageRiskLevel.CRITICAL
        elif total_weight >= 5:
            return PackageRiskLevel.HIGH
        elif total_weight >= 3:
            return PackageRiskLevel.MEDIUM
        else:
            return PackageRiskLevel.LOW
    
    def _calculate_confidence_score(self, result: AIPackageAnalysisResult) -> float:
        """Calculate confidence score for the analysis."""
        
        if not result.detected_threats:
            return 0.0
        
        # Base confidence on number of indicators and threat types
        base_confidence = min(len(result.detected_threats) * 0.2, 0.8)
        
        # Add confidence based on specific scores
        score_confidence = (
            result.obfuscation_score * 0.2 +
            result.crypto_targeting_score * 0.2 +
            result.data_exfiltration_score * 0.2 +
            result.ai_cli_exploitation_score * 0.2
        )
        
        return min(base_confidence + score_confidence, 1.0)
    
    def _generate_recommendations(self, result: AIPackageAnalysisResult) -> List[str]:
        """Generate security recommendations based on analysis."""
        
        recommendations = []
        
        if AIPackageThreatType.AI_GENERATED_MALWARE in result.detected_threats:
            recommendations.append("Package appears to contain AI-generated code - verify authenticity")
        
        if AIPackageThreatType.TYPOSQUATTING in result.detected_threats:
            recommendations.append("Package name is very similar to legitimate packages - verify correct package")
        
        if AIPackageThreatType.CRYPTO_TARGETING in result.detected_threats:
            recommendations.append("Package may target cryptocurrency wallets - review before use")
        
        if AIPackageThreatType.DATA_EXFILTRATION in result.detected_threats:
            recommendations.append("Package may attempt data exfiltration - review network requests")
        
        if AIPackageThreatType.AI_CLI_EXPLOITATION in result.detected_threats:
            recommendations.append("Package may exploit AI CLI tools - review for suspicious prompts")
        
        if result.obfuscation_score > 0.7:
            recommendations.append("Package contains highly obfuscated code - consider alternatives")
        
        if not recommendations:
            recommendations.append("No specific security concerns detected")
        
        return recommendations
    
    def _update_statistics(self, result: AIPackageAnalysisResult):
        """Update analysis statistics."""
        self.stats['packages_analyzed'] += 1
        
        if result.detected_threats:
            self.stats['threats_detected'] += 1
        
        if AIPackageThreatType.AI_GENERATED_MALWARE in result.detected_threats:
            self.stats['ai_generated_detected'] += 1
        
        if AIPackageThreatType.TYPOSQUATTING in result.detected_threats:
            self.stats['typosquatting_detected'] += 1
        
        if AIPackageThreatType.MAINTAINER_IMPERSONATION in result.detected_threats:
            self.stats['maintainer_anomalies_detected'] += 1
        
        # Update average analysis time
        total_time = self.stats['average_analysis_time'] * (self.stats['packages_analyzed'] - 1)
        self.stats['average_analysis_time'] = (total_time + result.analysis_time) / self.stats['packages_analyzed']
    
    async def analyze_package_similarity(self, package_name: str) -> PackageSimilarityResult:
        """Analyze package name similarity for typosquatting detection."""
        
        result = PackageSimilarityResult(target_package=package_name)
        
        for legitimate_package in self.legitimate_packages:
            similarity = difflib.SequenceMatcher(None, package_name.lower(), legitimate_package.lower()).ratio()
            result.similarity_scores[legitimate_package] = similarity
            
            if similarity > self.analysis_config['similarity_threshold']:
                result.similar_packages.append({
                    'package': legitimate_package,
                    'similarity': similarity
                })
            
            if similarity > self.analysis_config['typosquatting_threshold']:
                result.typosquatting_candidates.append({
                    'package': legitimate_package,
                    'similarity': similarity,
                    'risk': 'high' if similarity > 0.95 else 'medium'
                })
        
        return result
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset analysis statistics."""
        self.stats = {
            'packages_analyzed': 0,
            'threats_detected': 0,
            'ai_generated_detected': 0,
            'typosquatting_detected': 0,
            'maintainer_anomalies_detected': 0,
            'average_analysis_time': 0.0
        }
