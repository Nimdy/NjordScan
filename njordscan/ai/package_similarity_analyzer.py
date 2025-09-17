"""
Package Name Similarity Analysis for Typosquatting Detection

Advanced ML-based similarity analysis for detecting typosquatting attempts,
dependency confusion attacks, and package name manipulation.
"""

import asyncio
import time
import json
import re
import difflib
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
import numpy as np
from collections import defaultdict, Counter
import aiohttp
import aiofiles
from pathlib import Path

logger = logging.getLogger(__name__)

class SimilarityType(Enum):
    """Types of package name similarity."""
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    HOMOGLYPH_ATTACK = "homoglyph_attack"
    SUBDOMAIN_ATTACK = "subdomain_attack"
    NORMAL_SIMILARITY = "normal_similarity"

class ThreatLevel(Enum):
    """Threat levels for package similarity."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SimilarityResult:
    """Result of package similarity analysis."""
    target_package: str
    similar_packages: List[Dict[str, Any]] = field(default_factory=list)
    typosquatting_candidates: List[Dict[str, Any]] = field(default_factory=list)
    dependency_confusion_candidates: List[Dict[str, Any]] = field(default_factory=list)
    homoglyph_candidates: List[Dict[str, Any]] = field(default_factory=list)
    
    # Similarity scores
    similarity_scores: Dict[str, float] = field(default_factory=dict)
    threat_level: ThreatLevel = ThreatLevel.LOW
    confidence_score: float = 0.0
    
    # Analysis metadata
    analysis_time: float = 0.0
    total_packages_compared: int = 0
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PackageInfo:
    """Information about a package for comparison."""
    name: str
    version: str
    description: str = ""
    maintainers: List[str] = field(default_factory=list)
    download_count: int = 0
    last_updated: str = ""
    repository: str = ""
    homepage: str = ""
    license: str = ""

class PackageSimilarityAnalyzer:
    """Advanced package similarity analyzer for typosquatting detection."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Analysis configuration
        self.analysis_config = {
            'enable_typosquatting_detection': self.config.get('enable_typosquatting_detection', True),
            'enable_dependency_confusion_detection': self.config.get('enable_dependency_confusion_detection', True),
            'enable_homoglyph_detection': self.config.get('enable_homoglyph_detection', True),
            'similarity_threshold': self.config.get('similarity_threshold', 0.8),
            'typosquatting_threshold': self.config.get('typosquatting_threshold', 0.9),
            'dependency_confusion_threshold': self.config.get('dependency_confusion_threshold', 0.5),
            'homoglyph_threshold': self.config.get('homoglyph_threshold', 0.95),
            'max_packages_to_compare': self.config.get('max_packages_to_compare', 10000),
            'enable_ml_similarity': self.config.get('enable_ml_similarity', True),
            'enable_fuzzy_matching': self.config.get('enable_fuzzy_matching', True),
        }
        
        # Load legitimate packages database
        self.legitimate_packages = self._load_legitimate_packages()
        
        # Load common typosquatting patterns
        self.typosquatting_patterns = self._load_typosquatting_patterns()
        
        # Load homoglyph mappings
        self.homoglyph_mappings = self._load_homoglyph_mappings()
        
        # Statistics
        self.stats = {
            'packages_analyzed': 0,
            'typosquatting_detected': 0,
            'dependency_confusion_detected': 0,
            'homoglyph_attacks_detected': 0,
            'average_analysis_time': 0.0
        }
    
    def _load_legitimate_packages(self) -> Dict[str, PackageInfo]:
        """Load database of legitimate packages."""
        
        # This would typically be loaded from a database or API
        # For now, we'll use a comprehensive set of well-known packages
        legitimate_packages = {
            'react': PackageInfo('react', '18.2.0', 'A JavaScript library for building user interfaces'),
            'vue': PackageInfo('vue', '3.3.0', 'Progressive JavaScript framework'),
            'angular': PackageInfo('angular', '16.0.0', 'The modern web developer\'s platform'),
            'express': PackageInfo('express', '4.18.0', 'Fast, unopinionated, minimalist web framework'),
            'lodash': PackageInfo('lodash', '4.17.21', 'A modern JavaScript utility library'),
            'moment': PackageInfo('moment', '2.29.4', 'Parse, validate, manipulate, and display dates'),
            'axios': PackageInfo('axios', '1.4.0', 'Promise based HTTP client for the browser and node.js'),
            'webpack': PackageInfo('webpack', '5.88.0', 'A bundler for javascript and friends'),
            'babel': PackageInfo('babel', '7.22.0', 'Babel is a compiler for writing next generation JavaScript'),
            '@babel/core': PackageInfo('@babel/core', '7.22.0', 'Babel compiler core'),
            '@babel/preset-env': PackageInfo('@babel/preset-env', '7.22.0', 'Babel preset for environment'),
            '@types/react': PackageInfo('@types/react', '18.2.0', 'TypeScript definitions for React'),
            '@types/node': PackageInfo('@types/node', '20.0.0', 'TypeScript definitions for Node.js'),
            'typescript': PackageInfo('typescript', '5.1.0', 'TypeScript is a language for application-scale JavaScript'),
            'eslint': PackageInfo('eslint', '8.44.0', 'An AST-based pattern checker for JavaScript'),
            'prettier': PackageInfo('prettier', '2.8.8', 'Prettier is an opinionated code formatter'),
            'jest': PackageInfo('jest', '29.6.0', 'Delightful JavaScript Testing'),
            'mocha': PackageInfo('mocha', '10.2.0', 'Simple, flexible, fun test framework'),
            'chai': PackageInfo('chai', '4.3.7', 'BDD / TDD assertion library for node and the browser'),
            'cypress': PackageInfo('cypress', '12.15.0', 'Fast, easy and reliable testing for anything that runs in a browser'),
            'puppeteer': PackageInfo('puppeteer', '20.5.0', 'Headless Chrome Node.js API'),
            'playwright': PackageInfo('playwright', '1.35.0', 'Playwright is a framework for Web Testing and Automation'),
            'next': PackageInfo('next', '13.4.0', 'The React Framework for Production'),
            'nuxt': PackageInfo('nuxt', '3.4.0', 'The Intuitive Vue Framework'),
            'gatsby': PackageInfo('gatsby', '5.9.0', 'Build blazing fast, modern apps and websites with React'),
            'svelte': PackageInfo('svelte', '4.0.0', 'Cybernetically enhanced web apps'),
            'solid': PackageInfo('solid', '1.7.0', 'A declarative, efficient, and flexible JavaScript library'),
            'lit': PackageInfo('lit', '2.7.0', 'Simple. Fast. Web Components.'),
            'stencil': PackageInfo('stencil', '3.0.0', 'A compiler that generates Web Components'),
        }
        
        return legitimate_packages
    
    def _load_typosquatting_patterns(self) -> Dict[str, List[str]]:
        """Load common typosquatting patterns."""
        return {
            'character_substitution': [
                r'^[0o]+$',  # Only 0 and o characters
                r'^[1lI]+$',  # Only 1, l, I characters
                r'^[5sS]+$',  # Only 5 and s characters
                r'^[6g]+$',   # Only 6 and g characters
                r'^[8bB]+$',  # Only 8 and b characters
            ],
            'character_omission': [
                r'^[a-z]{1,2}$',  # Very short lowercase
                r'^[A-Z]{1,2}$',  # Very short uppercase
            ],
            'character_addition': [
                r'^[a-z]+\d{3,}$',  # Many numbers at end
                r'^[a-z]+-[a-z]+-[a-z]+$',  # Multiple hyphens
                r'^[a-z]+_[a-z]+_[a-z]+$',  # Multiple underscores
            ],
            'common_typos': [
                'recieve', 'recieved', 'recieving',  # receive
                'seperate', 'seperated', 'seperating',  # separate
                'occured', 'occuring',  # occurred
                'definately', 'definately',  # definitely
                'accomodate', 'accomodated',  # accommodate
            ]
        }
    
    def _load_homoglyph_mappings(self) -> Dict[str, str]:
        """Load homoglyph character mappings."""
        return {
            # Latin look-alikes
            'а': 'a',  # Cyrillic 'а' -> Latin 'a'
            'е': 'e',  # Cyrillic 'е' -> Latin 'e'
            'о': 'o',  # Cyrillic 'о' -> Latin 'o'
            'р': 'p',  # Cyrillic 'р' -> Latin 'p'
            'с': 'c',  # Cyrillic 'с' -> Latin 'c'
            'х': 'x',  # Cyrillic 'х' -> Latin 'x'
            'у': 'y',  # Cyrillic 'у' -> Latin 'y'
            
            # Number look-alikes
            '0': 'O',  # Zero -> O
            '1': 'l',  # One -> l
            '5': 'S',  # Five -> S
            '6': 'G',  # Six -> G
            '8': 'B',  # Eight -> B
            
            # Special characters
            '‐': '-',  # En dash -> hyphen
            '–': '-',  # Em dash -> hyphen
            '—': '-',  # Em dash -> hyphen
            '＂': '"',  # Fullwidth quotation mark
            '＇': "'",  # Fullwidth apostrophe
        }
    
    async def analyze_package_similarity(self, package_name: str, 
                                       custom_packages: List[PackageInfo] = None) -> SimilarityResult:
        """Analyze package name for similarity threats."""
        
        start_time = time.time()
        logger.info(f"Starting similarity analysis for package: {package_name}")
        
        result = SimilarityResult(
            target_package=package_name,
            analysis_time=0.0,
            total_packages_compared=0
        )
        
        try:
            # Get packages to compare against
            packages_to_compare = self._get_packages_to_compare(custom_packages)
            result.total_packages_compared = len(packages_to_compare)
            
            # Analyze different types of similarity
            if self.analysis_config['enable_typosquatting_detection']:
                await self._analyze_typosquatting(package_name, packages_to_compare, result)
            
            if self.analysis_config['enable_dependency_confusion_detection']:
                await self._analyze_dependency_confusion(package_name, packages_to_compare, result)
            
            if self.analysis_config['enable_homoglyph_detection']:
                await self._analyze_homoglyph_attacks(package_name, packages_to_compare, result)
            
            # Calculate overall threat level
            result.threat_level = self._calculate_threat_level(result)
            result.confidence_score = self._calculate_confidence_score(result)
            
            # Update statistics
            self._update_statistics(result)
            
        except Exception as e:
            logger.error(f"Error analyzing package similarity for {package_name}: {e}")
            result.analysis_metadata['error'] = str(e)
        
        result.analysis_time = time.time() - start_time
        return result
    
    def _get_packages_to_compare(self, custom_packages: List[PackageInfo] = None) -> List[PackageInfo]:
        """Get packages to compare against."""
        
        if custom_packages:
            return custom_packages
        
        # Use legitimate packages database
        return list(self.legitimate_packages.values())
    
    async def _analyze_typosquatting(self, package_name: str, packages_to_compare: List[PackageInfo], 
                                   result: SimilarityResult):
        """Analyze for typosquatting attempts."""
        
        typosquatting_candidates = []
        
        for package in packages_to_compare:
            similarity = self._calculate_similarity(package_name, package.name)
            result.similarity_scores[package.name] = similarity
            
            if similarity >= self.analysis_config['typosquatting_threshold']:
                typosquatting_candidates.append({
                    'package': package.name,
                    'similarity': similarity,
                    'description': package.description,
                    'maintainers': package.maintainers,
                    'download_count': package.download_count,
                    'threat_type': SimilarityType.TYPOSQUATTING,
                    'risk_level': self._calculate_typosquatting_risk(similarity, package)
                })
        
        result.typosquatting_candidates = typosquatting_candidates
        
        # Also check against common typosquatting patterns
        pattern_matches = self._check_typosquatting_patterns(package_name)
        if pattern_matches:
            result.typosquatting_candidates.extend(pattern_matches)
    
    async def _analyze_dependency_confusion(self, package_name: str, packages_to_compare: List[PackageInfo], 
                                          result: SimilarityResult):
        """Analyze for dependency confusion attacks."""
        
        dependency_confusion_candidates = []
        
        for package in packages_to_compare:
            # Check for scoped package confusion
            if '@' in package.name and '@' not in package_name:
                unscoped_name = package.name.split('/')[-1]
                scope_name = package.name.split('/')[0].replace('@', '')
                
                # Check similarity with both unscoped name and scope name
                unscoped_similarity = self._calculate_similarity(package_name, unscoped_name)
                scope_similarity = self._calculate_similarity(package_name, scope_name)
                max_similarity = max(unscoped_similarity, scope_similarity)
                
                if max_similarity >= self.analysis_config['dependency_confusion_threshold']:
                    dependency_confusion_candidates.append({
                        'package': package.name,
                        'unscoped_name': unscoped_name,
                        'scope_name': scope_name,
                        'similarity': max_similarity,
                        'description': package.description,
                        'threat_type': SimilarityType.DEPENDENCY_CONFUSION,
                        'risk_level': self._calculate_dependency_confusion_risk(max_similarity, package)
                    })
            
            # Check for subdomain-style confusion
            if '-' in package.name and '-' not in package_name:
                parts = package.name.split('-')
                for part in parts:
                    similarity = self._calculate_similarity(package_name, part)
                    if similarity >= self.analysis_config['dependency_confusion_threshold']:
                        dependency_confusion_candidates.append({
                            'package': package.name,
                            'confused_part': part,
                            'similarity': similarity,
                            'description': package.description,
                            'threat_type': SimilarityType.DEPENDENCY_CONFUSION,
                            'risk_level': self._calculate_dependency_confusion_risk(similarity, package)
                        })
        
        result.dependency_confusion_candidates = dependency_confusion_candidates
    
    async def _analyze_homoglyph_attacks(self, package_name: str, packages_to_compare: List[PackageInfo], 
                                       result: SimilarityResult):
        """Analyze for homoglyph attacks."""
        
        homoglyph_candidates = []
        
        # Normalize package name for homoglyph detection
        normalized_name = self._normalize_homoglyphs(package_name)
        
        for package in packages_to_compare:
            normalized_package = self._normalize_homoglyphs(package.name)
            
            if normalized_name == normalized_package and package_name != package.name:
                # Calculate visual similarity
                visual_similarity = self._calculate_visual_similarity(package_name, package.name)
                
                if visual_similarity >= self.analysis_config['homoglyph_threshold']:
                    homoglyph_candidates.append({
                        'package': package.name,
                        'visual_similarity': visual_similarity,
                        'description': package.description,
                        'threat_type': SimilarityType.HOMOGLYPH_ATTACK,
                        'risk_level': self._calculate_homoglyph_risk(visual_similarity, package)
                    })
        
        result.homoglyph_candidates = homoglyph_candidates
    
    def _calculate_similarity(self, name1: str, name2: str) -> float:
        """Calculate similarity between two package names."""
        
        if not name1 or not name2:
            return 0.0
        
        # Normalize names
        name1 = name1.lower().strip()
        name2 = name2.lower().strip()
        
        if name1 == name2:
            return 1.0
        
        # Use difflib for sequence matching
        similarity = difflib.SequenceMatcher(None, name1, name2).ratio()
        
        # Apply ML-based similarity if enabled
        if self.analysis_config['enable_ml_similarity']:
            ml_similarity = self._calculate_ml_similarity(name1, name2)
            # Combine traditional and ML similarity
            similarity = (similarity + ml_similarity) / 2
        
        return similarity
    
    def _calculate_ml_similarity(self, name1: str, name2: str) -> float:
        """Calculate ML-based similarity between package names."""
        
        # Simple character n-gram similarity
        def get_ngrams(text, n=2):
            return [text[i:i+n] for i in range(len(text) - n + 1)]
        
        ngrams1 = set(get_ngrams(name1, 2))
        ngrams2 = set(get_ngrams(name2, 2))
        
        if not ngrams1 and not ngrams2:
            return 1.0
        if not ngrams1 or not ngrams2:
            return 0.0
        
        intersection = len(ngrams1.intersection(ngrams2))
        union = len(ngrams1.union(ngrams2))
        
        return intersection / union if union > 0 else 0.0
    
    def _calculate_visual_similarity(self, name1: str, name2: str) -> float:
        """Calculate visual similarity for homoglyph detection."""
        
        if len(name1) != len(name2):
            return 0.0
        
        similar_chars = 0
        total_chars = len(name1)
        
        for char1, char2 in zip(name1, name2):
            if char1 == char2:
                similar_chars += 1
            elif self._are_homoglyphs(char1, char2):
                similar_chars += 0.8  # Partial similarity for homoglyphs
        
        return similar_chars / total_chars if total_chars > 0 else 0.0
    
    def _are_homoglyphs(self, char1: str, char2: str) -> bool:
        """Check if two characters are homoglyphs."""
        
        # Check direct mapping
        if self.homoglyph_mappings.get(char1) == char2:
            return True
        if self.homoglyph_mappings.get(char2) == char1:
            return True
        
        # Check if both normalize to the same character
        norm1 = self._normalize_homoglyphs(char1)
        norm2 = self._normalize_homoglyphs(char2)
        
        return norm1 == norm2
    
    def _normalize_homoglyphs(self, text: str) -> str:
        """Normalize text by converting homoglyphs to their base characters."""
        
        normalized = text
        for homoglyph, base_char in self.homoglyph_mappings.items():
            normalized = normalized.replace(homoglyph, base_char)
        
        return normalized.lower()
    
    def _check_typosquatting_patterns(self, package_name: str) -> List[Dict[str, Any]]:
        """Check package name against common typosquatting patterns."""
        
        pattern_matches = []
        
        for pattern_type, patterns in self.typosquatting_patterns.items():
            for pattern in patterns:
                if re.search(pattern, package_name, re.IGNORECASE):
                    pattern_matches.append({
                        'package': package_name,
                        'pattern_type': pattern_type,
                        'pattern': pattern,
                        'threat_type': SimilarityType.TYPOSQUATTING,
                        'risk_level': 'medium'
                    })
        
        return pattern_matches
    
    def _calculate_typosquatting_risk(self, similarity: float, package: PackageInfo) -> str:
        """Calculate risk level for typosquatting."""
        
        if similarity >= 0.98:
            return 'critical'
        elif similarity >= 0.95:
            return 'high'
        elif similarity >= 0.90:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_dependency_confusion_risk(self, similarity: float, package: PackageInfo) -> str:
        """Calculate risk level for dependency confusion."""
        
        if similarity >= 0.95:
            return 'critical'
        elif similarity >= 0.90:
            return 'high'
        elif similarity >= 0.85:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_homoglyph_risk(self, similarity: float, package: PackageInfo) -> str:
        """Calculate risk level for homoglyph attacks."""
        
        if similarity >= 0.98:
            return 'critical'
        elif similarity >= 0.95:
            return 'high'
        elif similarity >= 0.90:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_threat_level(self, result: SimilarityResult) -> ThreatLevel:
        """Calculate overall threat level."""
        
        all_candidates = (
            result.typosquatting_candidates +
            result.dependency_confusion_candidates +
            result.homoglyph_candidates
        )
        
        if not all_candidates:
            return ThreatLevel.LOW
        
        # Find highest risk level
        risk_levels = [candidate.get('risk_level', 'low') for candidate in all_candidates]
        
        if 'critical' in risk_levels:
            return ThreatLevel.CRITICAL
        elif 'high' in risk_levels:
            return ThreatLevel.HIGH
        elif 'medium' in risk_levels:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _calculate_confidence_score(self, result: SimilarityResult) -> float:
        """Calculate confidence score for the analysis."""
        
        all_candidates = (
            result.typosquatting_candidates +
            result.dependency_confusion_candidates +
            result.homoglyph_candidates
        )
        
        if not all_candidates:
            return 0.0
        
        # Calculate average similarity score
        similarity_scores = [candidate.get('similarity', 0) for candidate in all_candidates]
        avg_similarity = sum(similarity_scores) / len(similarity_scores)
        
        # Adjust confidence based on number of candidates
        confidence = avg_similarity * min(len(all_candidates) / 5, 1.0)
        
        return min(confidence, 1.0)
    
    def _update_statistics(self, result: SimilarityResult):
        """Update analysis statistics."""
        
        self.stats['packages_analyzed'] += 1
        
        if result.typosquatting_candidates:
            self.stats['typosquatting_detected'] += 1
        
        if result.dependency_confusion_candidates:
            self.stats['dependency_confusion_detected'] += 1
        
        if result.homoglyph_candidates:
            self.stats['homoglyph_attacks_detected'] += 1
        
        # Update average analysis time
        total_time = self.stats['average_analysis_time'] * (self.stats['packages_analyzed'] - 1)
        self.stats['average_analysis_time'] = (total_time + result.analysis_time) / self.stats['packages_analyzed']
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset analysis statistics."""
        self.stats = {
            'packages_analyzed': 0,
            'typosquatting_detected': 0,
            'dependency_confusion_detected': 0,
            'homoglyph_attacks_detected': 0,
            'average_analysis_time': 0.0
        }
