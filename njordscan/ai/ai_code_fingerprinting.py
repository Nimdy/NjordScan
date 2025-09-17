"""
AI Code Fingerprinting and Pattern Detection

Advanced fingerprinting system for detecting AI-generated code patterns,
obfuscation techniques, and malicious code signatures.
"""

import re
import ast
import hashlib
import json
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
import numpy as np
from collections import Counter, defaultdict
import difflib

logger = logging.getLogger(__name__)

class CodePatternType(Enum):
    """Types of code patterns."""
    AI_GENERATED = "ai_generated"
    OBFUSCATED = "obfuscated"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NORMAL = "normal"

class FingerprintConfidence(Enum):
    """Confidence levels for fingerprinting."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

@dataclass
class CodeFingerprint:
    """Code fingerprint analysis result."""
    file_path: str
    content_hash: str
    pattern_type: CodePatternType
    confidence: FingerprintConfidence
    score: float
    
    # Pattern details
    detected_patterns: List[str] = field(default_factory=list)
    suspicious_functions: List[str] = field(default_factory=list)
    obfuscation_indicators: List[str] = field(default_factory=list)
    ai_signatures: List[str] = field(default_factory=list)
    
    # Code metrics
    complexity_score: float = 0.0
    entropy_score: float = 0.0
    readability_score: float = 0.0
    obfuscation_score: float = 0.0
    
    # Metadata
    analysis_time: float = 0.0
    file_size: int = 0
    line_count: int = 0

@dataclass
class PatternMatch:
    """Individual pattern match result."""
    pattern_name: str
    pattern_type: str
    matches: List[str]
    confidence: float
    line_numbers: List[int] = field(default_factory=list)

class AICodeFingerprinter:
    """Advanced AI code fingerprinting and pattern detection system."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Configuration
        self.fingerprint_config = {
            'enable_ai_detection': self.config.get('enable_ai_detection', True),
            'enable_obfuscation_detection': self.config.get('enable_obfuscation_detection', True),
            'enable_malicious_detection': self.config.get('enable_malicious_detection', True),
            'min_confidence_threshold': self.config.get('min_confidence_threshold', 0.6),
            'high_confidence_threshold': self.config.get('high_confidence_threshold', 0.8),
            'very_high_confidence_threshold': self.config.get('very_high_confidence_threshold', 0.9),
            'max_file_size': self.config.get('max_file_size', 1024 * 1024),  # 1MB
            'enable_entropy_analysis': self.config.get('enable_entropy_analysis', True),
            'enable_complexity_analysis': self.config.get('enable_complexity_analysis', True),
        }
        
        # Load pattern databases
        self.ai_patterns = self._load_ai_patterns()
        self.obfuscation_patterns = self._load_obfuscation_patterns()
        self.malicious_patterns = self._load_malicious_patterns()
        self.suspicious_patterns = self._load_suspicious_patterns()
        
        # Statistics
        self.stats = {
            'files_analyzed': 0,
            'ai_generated_detected': 0,
            'obfuscated_detected': 0,
            'malicious_detected': 0,
            'suspicious_detected': 0,
            'average_analysis_time': 0.0
        }
    
    def _load_ai_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load AI-generated code patterns."""
        return {
            'variable_naming': {
                'patterns': [
                    r'var\s+[a-z]{1,2}\d+',  # var a1, b2, etc.
                    r'let\s+[a-z]{1,2}\d+',
                    r'const\s+[a-z]{1,2}\d+',
                    r'function\s+[a-z]{1,2}\d+',
                    r'class\s+[A-Z][a-z]{1,2}\d+',
                ],
                'weight': 0.3,
                'description': 'AI-generated variable naming patterns'
            },
            'code_structure': {
                'patterns': [
                    r'function\s+\w+\s*\(\s*\)\s*{\s*return\s*[^;]+;\s*}',  # Simple return functions
                    r'const\s+\w+\s*=\s*\([^)]*\)\s*=>\s*[^;]+;',  # Arrow functions
                    r'if\s*\(\s*true\s*\)\s*{\s*[^}]*\s*}',  # Always true conditions
                    r'for\s*\(\s*let\s+i\s*=\s*0\s*;\s*i\s*<\s*\d+\s*;\s*i\+\+\s*\)',  # Generic for loops
                ],
                'weight': 0.4,
                'description': 'AI-generated code structure patterns'
            },
            'ai_signatures': {
                'patterns': [
                    r'\/\/\s*Generated\s+by\s+AI',
                    r'\/\*\s*AI\s+Generated\s+\*\/',
                    r'\/\/\s*Auto-generated',
                    r'\/\*\s*Machine\s+Generated\s+\*\/',
                    r'\/\/\s*Generated\s+by\s+ChatGPT',
                    r'\/\/\s*Generated\s+by\s+Claude',
                    r'\/\/\s*Generated\s+by\s+Gemini',
                ],
                'weight': 0.8,
                'description': 'Explicit AI generation signatures'
            },
            'generic_functions': {
                'patterns': [
                    r'function\s+process\w*\s*\(',
                    r'function\s+handle\w*\s*\(',
                    r'function\s+execute\w*\s*\(',
                    r'function\s+perform\w*\s*\(',
                    r'function\s+generate\w*\s*\(',
                ],
                'weight': 0.2,
                'description': 'Generic AI-generated function names'
            }
        }
    
    def _load_obfuscation_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load code obfuscation patterns."""
        return {
            'string_obfuscation': {
                'patterns': [
                    r'String\.fromCharCode\s*\(\s*\d+\s*\)',
                    r'atob\s*\(\s*["\'][^"\']+["\']\s*\)',
                    r'btoa\s*\(\s*[^)]+\s*\)',
                    r'unescape\s*\(\s*[^)]+\s*\)',
                    r'decodeURIComponent\s*\(\s*[^)]+\s*\)',
                    r'Buffer\.from\s*\(\s*[^,]+,\s*["\']base64["\']\s*\)',
                ],
                'weight': 0.6,
                'description': 'String obfuscation techniques'
            },
            'control_flow_obfuscation': {
                'patterns': [
                    r'while\s*\(\s*true\s*\)\s*{',
                    r'for\s*\(\s*;;\s*\)\s*{',
                    r'if\s*\(\s*Math\.random\s*\(\s*\)\s*>\s*0\.5\s*\)',
                    r'switch\s*\(\s*Math\.floor\s*\(\s*Math\.random\s*\(\s*\)\s*\*\s*\d+\s*\)\s*\)',
                    r'do\s*{\s*[^}]*\s*}\s*while\s*\(\s*false\s*\)',
                ],
                'weight': 0.7,
                'description': 'Control flow obfuscation'
            },
            'variable_obfuscation': {
                'patterns': [
                    r'var\s+[a-zA-Z_$][a-zA-Z0-9_$]{15,}\s*=',
                    r'let\s+[a-zA-Z_$][a-zA-Z0-9_$]{15,}\s*=',
                    r'const\s+[a-zA-Z_$][a-zA-Z0-9_$]{15,}\s*=',
                    r'function\s+[a-zA-Z_$][a-zA-Z0-9_$]{15,}\s*\(',
                ],
                'weight': 0.5,
                'description': 'Variable name obfuscation'
            },
            'eval_usage': {
                'patterns': [
                    r'eval\s*\(\s*[^)]+\)',
                    r'Function\s*\(\s*[^)]+\)',
                    r'setTimeout\s*\(\s*[^,]+,\s*\d+\s*\)',
                    r'setInterval\s*\(\s*[^,]+,\s*\d+\s*\)',
                ],
                'weight': 0.8,
                'description': 'Dynamic code execution'
            },
            'hex_encoding': {
                'patterns': [
                    r'[0-9a-fA-F]{32,}',
                    r'0x[0-9a-fA-F]{16,}',
                    r'\\x[0-9a-fA-F]{2}',
                ],
                'weight': 0.4,
                'description': 'Hex encoding patterns'
            }
        }
    
    def _load_malicious_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load malicious code patterns."""
        return {
            'crypto_targeting': {
                'patterns': [
                    r'window\.ethereum',
                    r'web3\.eth',
                    r'bitcoin\.',
                    r'wallet\.',
                    r'crypto\.',
                    r'blockchain\.',
                    r'privateKey',
                    r'seedPhrase',
                    r'mnemonic',
                    r'walletAddress',
                ],
                'weight': 0.9,
                'description': 'Cryptocurrency targeting patterns'
            },
            'data_exfiltration': {
                'patterns': [
                    r'fetch\s*\(\s*["\'][^"\']*["\']',
                    r'XMLHttpRequest',
                    r'localStorage\s*\.\s*getItem',
                    r'sessionStorage\s*\.\s*getItem',
                    r'document\.cookie',
                    r'navigator\.userAgent',
                    r'location\.href',
                    r'fs\s*\.\s*readFile',
                    r'fs\s*\.\s*writeFile',
                ],
                'weight': 0.8,
                'description': 'Data exfiltration patterns'
            },
            'network_requests': {
                'patterns': [
                    r'https?://[^\s"\']+',
                    r'axios\s*\.\s*post',
                    r'request\s*\.\s*post',
                    r'http\s*\.\s*post',
                    r'https\s*\.\s*post',
                ],
                'weight': 0.6,
                'description': 'Suspicious network requests'
            },
            'file_operations': {
                'patterns': [
                    r'fs\s*\.\s*readFile',
                    r'fs\s*\.\s*writeFile',
                    r'fs\s*\.\s*readdir',
                    r'fs\s*\.\s*unlink',
                    r'path\s*\.\s*join',
                    r'path\s*\.\s*resolve',
                ],
                'weight': 0.7,
                'description': 'File system operations'
            }
        }
    
    def _load_suspicious_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load suspicious code patterns."""
        return {
            'unusual_imports': {
                'patterns': [
                    r'require\s*\(\s*["\'][^"\']*["\']\s*\)',
                    r'import\s+.*\s+from\s+["\'][^"\']*["\']',
                    r'import\s*\(\s*["\'][^"\']*["\']\s*\)',
                ],
                'weight': 0.3,
                'description': 'Unusual import patterns'
            },
            'global_access': {
                'patterns': [
                    r'window\[',
                    r'global\[',
                    r'process\[',
                    r'globalThis\[',
                ],
                'weight': 0.4,
                'description': 'Global object access'
            },
            'prototype_pollution': {
                'patterns': [
                    r'__proto__',
                    r'constructor\.prototype',
                    r'Object\.prototype',
                ],
                'weight': 0.7,
                'description': 'Prototype pollution attempts'
            }
        }
    
    async def analyze_code(self, file_path: str, content: str) -> CodeFingerprint:
        """Analyze code and generate fingerprint."""
        
        start_time = time.time()
        
        # Handle None or empty content
        if content is None:
            content = ""
        
        # Basic file information
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        file_size = len(content.encode('utf-8'))
        line_count = len(content.splitlines())
        
        # Initialize fingerprint
        fingerprint = CodeFingerprint(
            file_path=file_path,
            content_hash=content_hash,
            pattern_type=CodePatternType.NORMAL,
            confidence=FingerprintConfidence.LOW,
            score=0.0,
            file_size=file_size,
            line_count=line_count,
            analysis_time=0.0
        )
        
        try:
            # Skip if file is too large
            if file_size > self.fingerprint_config['max_file_size']:
                fingerprint.pattern_type = CodePatternType.SUSPICIOUS
                fingerprint.suspicious_functions.append("File too large for analysis")
                return fingerprint
            
            # Analyze patterns
            pattern_matches = await self._analyze_patterns(content)
            
            # Calculate scores
            ai_score = self._calculate_ai_score(pattern_matches)
            obfuscation_score = self._calculate_obfuscation_score(pattern_matches)
            malicious_score = self._calculate_malicious_score(pattern_matches)
            suspicious_score = self._calculate_suspicious_score(pattern_matches)
            
            # Determine pattern type and confidence
            fingerprint.pattern_type, fingerprint.confidence = self._classify_pattern(
                ai_score, obfuscation_score, malicious_score, suspicious_score
            )
            
            # Set overall score
            fingerprint.score = max(ai_score, obfuscation_score, malicious_score, suspicious_score)
            
            # Extract specific patterns
            fingerprint.detected_patterns = [match.pattern_name for match in pattern_matches]
            fingerprint.suspicious_functions = self._extract_suspicious_functions(content)
            fingerprint.obfuscation_indicators = self._extract_obfuscation_indicators(pattern_matches)
            fingerprint.ai_signatures = self._extract_ai_signatures(pattern_matches)
            
            # Calculate code metrics
            if self.fingerprint_config['enable_entropy_analysis']:
                fingerprint.entropy_score = self._calculate_entropy(content)
            
            if self.fingerprint_config['enable_complexity_analysis']:
                fingerprint.complexity_score = self._calculate_complexity(content)
            
            fingerprint.readability_score = self._calculate_readability(content)
            fingerprint.obfuscation_score = self._calculate_obfuscation_score_from_patterns(pattern_matches)
            
            # Update statistics
            self._update_statistics(fingerprint)
            
        except Exception as e:
            logger.error(f"Error analyzing code {file_path}: {e}")
            fingerprint.suspicious_functions.append(f"Analysis error: {str(e)}")
        
        fingerprint.analysis_time = time.time() - start_time
        return fingerprint
    
    async def _analyze_patterns(self, content: str) -> List[PatternMatch]:
        """Analyze content for all pattern types."""
        
        pattern_matches = []
        
        # Analyze AI patterns
        if self.fingerprint_config['enable_ai_detection']:
            ai_matches = self._match_patterns(content, self.ai_patterns, "ai")
            pattern_matches.extend(ai_matches)
        
        # Analyze obfuscation patterns
        if self.fingerprint_config['enable_obfuscation_detection']:
            obfuscation_matches = self._match_patterns(content, self.obfuscation_patterns, "obfuscation")
            pattern_matches.extend(obfuscation_matches)
        
        # Analyze malicious patterns
        if self.fingerprint_config['enable_malicious_detection']:
            malicious_matches = self._match_patterns(content, self.malicious_patterns, "malicious")
            pattern_matches.extend(malicious_matches)
        
        # Analyze suspicious patterns
        suspicious_matches = self._match_patterns(content, self.suspicious_patterns, "suspicious")
        pattern_matches.extend(suspicious_matches)
        
        return pattern_matches
    
    def _match_patterns(self, content: str, pattern_db: Dict[str, Dict[str, Any]], category: str) -> List[PatternMatch]:
        """Match patterns against content."""
        
        matches = []
        
        for pattern_name, pattern_info in pattern_db.items():
            pattern_list = pattern_info['patterns']
            weight = pattern_info['weight']
            
            for pattern in pattern_list:
                try:
                    regex_matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in regex_matches:
                        line_number = content[:match.start()].count('\n') + 1
                        
                        matches.append(PatternMatch(
                            pattern_name=pattern_name,
                            pattern_type=category,
                            matches=[match.group()],
                            confidence=weight,
                            line_numbers=[line_number]
                        ))
                
                except re.error as e:
                    logger.warning(f"Invalid regex pattern {pattern}: {e}")
                    continue
        
        return matches
    
    def _calculate_ai_score(self, pattern_matches: List[PatternMatch]) -> float:
        """Calculate AI-generated code score."""
        
        ai_matches = [m for m in pattern_matches if m.pattern_type == "ai"]
        if not ai_matches:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for match in ai_matches:
            total_score += match.confidence * len(match.matches)
            total_weight += match.confidence
        
        return total_score / max(total_weight, 1.0)
    
    def _calculate_obfuscation_score(self, pattern_matches: List[PatternMatch]) -> float:
        """Calculate obfuscation score."""
        
        obfuscation_matches = [m for m in pattern_matches if m.pattern_type == "obfuscation"]
        if not obfuscation_matches:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for match in obfuscation_matches:
            total_score += match.confidence * len(match.matches)
            total_weight += match.confidence
        
        return total_score / max(total_weight, 1.0)
    
    def _calculate_malicious_score(self, pattern_matches: List[PatternMatch]) -> float:
        """Calculate malicious code score."""
        
        malicious_matches = [m for m in pattern_matches if m.pattern_type == "malicious"]
        if not malicious_matches:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for match in malicious_matches:
            total_score += match.confidence * len(match.matches)
            total_weight += match.confidence
        
        return total_score / max(total_weight, 1.0)
    
    def _calculate_suspicious_score(self, pattern_matches: List[PatternMatch]) -> float:
        """Calculate suspicious code score."""
        
        suspicious_matches = [m for m in pattern_matches if m.pattern_type == "suspicious"]
        if not suspicious_matches:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for match in suspicious_matches:
            total_score += match.confidence * len(match.matches)
            total_weight += match.confidence
        
        return total_score / max(total_weight, 1.0)
    
    def _classify_pattern(self, ai_score: float, obfuscation_score: float, 
                         malicious_score: float, suspicious_score: float) -> Tuple[CodePatternType, FingerprintConfidence]:
        """Classify the overall pattern type and confidence."""
        
        scores = {
            CodePatternType.AI_GENERATED: ai_score,
            CodePatternType.OBFUSCATED: obfuscation_score,
            CodePatternType.MALICIOUS: malicious_score,
            CodePatternType.SUSPICIOUS: suspicious_score
        }
        
        # Find the highest scoring pattern type
        max_pattern = max(scores, key=scores.get)
        max_score = scores[max_pattern]
        
        # Determine confidence level
        if max_score >= self.fingerprint_config['very_high_confidence_threshold']:
            confidence = FingerprintConfidence.VERY_HIGH
        elif max_score >= self.fingerprint_config['high_confidence_threshold']:
            confidence = FingerprintConfidence.HIGH
        elif max_score >= self.fingerprint_config['min_confidence_threshold']:
            confidence = FingerprintConfidence.MEDIUM
        else:
            confidence = FingerprintConfidence.LOW
            max_pattern = CodePatternType.NORMAL
        
        return max_pattern, confidence
    
    def _extract_suspicious_functions(self, content: str) -> List[str]:
        """Extract suspicious function names from content."""
        
        suspicious_functions = []
        
        # Look for function declarations
        function_patterns = [
            r'function\s+(\w+)\s*\(',
            r'const\s+(\w+)\s*=\s*function',
            r'let\s+(\w+)\s*=\s*function',
            r'var\s+(\w+)\s*=\s*function',
            r'(\w+)\s*:\s*function',
        ]
        
        for pattern in function_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if self._is_suspicious_function_name(match):
                    suspicious_functions.append(match)
        
        return list(set(suspicious_functions))
    
    def _is_suspicious_function_name(self, name: str) -> bool:
        """Check if a function name is suspicious."""
        
        suspicious_patterns = [
            r'^[a-z]{1,2}\d+$',  # a1, b2, etc.
            r'^[a-zA-Z_$][a-zA-Z0-9_$]{15,}$',  # Very long names
            r'^[0-9a-fA-F]{8,}$',  # Hex-like names
            r'^[A-Za-z0-9+/]{10,}={0,2}$',  # Base64-like names
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, name):
                return True
        
        return False
    
    def _extract_obfuscation_indicators(self, pattern_matches: List[PatternMatch]) -> List[str]:
        """Extract obfuscation indicators from pattern matches."""
        
        indicators = []
        obfuscation_matches = [m for m in pattern_matches if m.pattern_type == "obfuscation"]
        
        for match in obfuscation_matches:
            indicators.append(f"{match.pattern_name}: {len(match.matches)} matches")
        
        return indicators
    
    def _extract_ai_signatures(self, pattern_matches: List[PatternMatch]) -> List[str]:
        """Extract AI signatures from pattern matches."""
        
        signatures = []
        ai_matches = [m for m in pattern_matches if m.pattern_type == "ai"]
        
        for match in ai_matches:
            if match.pattern_name == "ai_signatures":
                signatures.extend(match.matches)
        
        return signatures
    
    def _calculate_entropy(self, content: str) -> float:
        """Calculate Shannon entropy of content."""
        
        if not content:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(content)
        total_chars = len(content)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _calculate_complexity(self, content: str) -> float:
        """Calculate code complexity score."""
        
        try:
            # Parse as JavaScript (simplified)
            complexity_indicators = [
                r'if\s*\(',
                r'else\s*if\s*\(',
                r'for\s*\(',
                r'while\s*\(',
                r'switch\s*\(',
                r'case\s+',
                r'try\s*{',
                r'catch\s*\(',
                r'throw\s+',
                r'return\s+',
            ]
            
            complexity_score = 0.0
            for pattern in complexity_indicators:
                matches = len(re.findall(pattern, content, re.IGNORECASE))
                complexity_score += matches * 0.1
            
            return min(complexity_score, 1.0)
        
        except Exception:
            return 0.0
    
    def _calculate_readability(self, content: str) -> float:
        """Calculate code readability score."""
        
        if not content:
            return 0.0
        
        lines = content.splitlines()
        if not lines:
            return 0.0
        
        # Simple readability metrics
        avg_line_length = sum(len(line) for line in lines) / len(lines)
        comment_ratio = sum(1 for line in lines if line.strip().startswith(('//', '/*', '*'))) / len(lines)
        
        # Calculate readability score (0-1, higher is better)
        length_score = max(0, 1 - (avg_line_length - 80) / 100)  # Penalty for very long lines
        comment_score = min(comment_ratio * 2, 1.0)  # Bonus for comments
        
        return (length_score + comment_score) / 2
    
    def _calculate_obfuscation_score_from_patterns(self, pattern_matches: List[PatternMatch]) -> float:
        """Calculate obfuscation score from pattern matches."""
        
        obfuscation_matches = [m for m in pattern_matches if m.pattern_type == "obfuscation"]
        if not obfuscation_matches:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for match in obfuscation_matches:
            total_score += match.confidence * len(match.matches)
            total_weight += match.confidence
        
        return total_score / max(total_weight, 1.0)
    
    def _update_statistics(self, fingerprint: CodeFingerprint):
        """Update analysis statistics."""
        
        self.stats['files_analyzed'] += 1
        
        if fingerprint.pattern_type == CodePatternType.AI_GENERATED:
            self.stats['ai_generated_detected'] += 1
        elif fingerprint.pattern_type == CodePatternType.OBFUSCATED:
            self.stats['obfuscated_detected'] += 1
        elif fingerprint.pattern_type == CodePatternType.MALICIOUS:
            self.stats['malicious_detected'] += 1
        elif fingerprint.pattern_type == CodePatternType.SUSPICIOUS:
            self.stats['suspicious_detected'] += 1
        
        # Update average analysis time
        total_time = self.stats['average_analysis_time'] * (self.stats['files_analyzed'] - 1)
        self.stats['average_analysis_time'] = (total_time + fingerprint.analysis_time) / self.stats['files_analyzed']
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset analysis statistics."""
        self.stats = {
            'files_analyzed': 0,
            'ai_generated_detected': 0,
            'obfuscated_detected': 0,
            'malicious_detected': 0,
            'suspicious_detected': 0,
            'average_analysis_time': 0.0
        }
