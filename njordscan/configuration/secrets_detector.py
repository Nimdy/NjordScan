"""
Advanced Secrets Detector

Comprehensive secrets detection using multiple techniques including:
- Pattern matching for various secret types
- Entropy analysis for high-entropy strings
- Machine learning-inspired classification
- Context-aware detection with false positive reduction
"""

import re
import math
import hashlib
import base64
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class SecretType(Enum):
    """Types of secrets that can be detected."""
    API_KEY = "api_key"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"
    STRIPE_KEY = "stripe_key"
    JWT_TOKEN = "jwt_token"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    DATABASE_URL = "database_url"
    OAUTH_TOKEN = "oauth_token"
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"
    WEBHOOK_URL = "webhook_url"
    GENERIC_SECRET = "generic_secret"

class DetectionMethod(Enum):
    """Methods used for secret detection."""
    PATTERN_MATCH = "pattern_match"
    ENTROPY_ANALYSIS = "entropy_analysis"
    CONTEXT_ANALYSIS = "context_analysis"
    MACHINE_LEARNING = "machine_learning"
    HYBRID = "hybrid"

@dataclass
class SecretMatch:
    """Detected secret information."""
    secret_type: SecretType
    detection_method: DetectionMethod
    
    # Location information
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    
    # Content
    matched_text: str
    context: str
    
    # Confidence and analysis
    confidence: float
    entropy: float
    false_positive_likelihood: float
    
    # Pattern information
    pattern_name: str = ""
    pattern_regex: str = ""
    
    # Context clues
    variable_name: str = ""
    surrounding_keywords: List[str] = field(default_factory=list)
    
    # Validation
    is_likely_test: bool = False
    is_likely_example: bool = False
    is_likely_placeholder: bool = False
    
    # Metadata
    severity: str = "high"
    remediation_advice: str = ""

@dataclass
class SecretsAnalysisResult:
    """Result of secrets analysis."""
    total_secrets_found: int
    secrets_by_type: Dict[SecretType, int]
    secrets_by_file: Dict[str, int]
    high_confidence_secrets: int
    likely_false_positives: int
    
    # Detailed findings
    secret_matches: List[SecretMatch]
    
    # Risk assessment
    overall_risk_score: float
    critical_secrets: List[SecretMatch]
    
    # Statistics
    files_scanned: int
    lines_scanned: int
    patterns_matched: int
    entropy_detections: int

class SecretsDetector:
    """Advanced secrets detection engine."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Detection configuration
        self.detection_config = {
            'enable_pattern_matching': self.config.get('enable_pattern_matching', True),
            'enable_entropy_analysis': self.config.get('enable_entropy_analysis', True),
            'enable_context_analysis': self.config.get('enable_context_analysis', True),
            'min_entropy_threshold': self.config.get('min_entropy_threshold', 4.5),
            'min_secret_length': self.config.get('min_secret_length', 8),
            'max_secret_length': self.config.get('max_secret_length', 200),
            'confidence_threshold': self.config.get('confidence_threshold', 0.7),
            'reduce_false_positives': self.config.get('reduce_false_positives', True)
        }
        
        # Initialize detection patterns
        self.secret_patterns = self._initialize_secret_patterns()
        
        # Context keywords for different secret types
        self.context_keywords = self._initialize_context_keywords()
        
        # False positive indicators
        self.false_positive_indicators = self._initialize_false_positive_indicators()
        
        # Statistics
        self.stats = {
            'total_detections': 0,
            'pattern_detections': 0,
            'entropy_detections': 0,
            'context_detections': 0,
            'false_positives_filtered': 0
        }
    
    async def detect_secrets_in_content(self, content: str, file_path: str = "") -> List[SecretMatch]:
        """Detect secrets in text content."""
        
        secrets = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Pattern-based detection
            if self.detection_config['enable_pattern_matching']:
                pattern_secrets = await self._detect_patterns_in_line(line, file_path, line_num)
                secrets.extend(pattern_secrets)
            
            # Entropy-based detection
            if self.detection_config['enable_entropy_analysis']:
                entropy_secrets = await self._detect_entropy_in_line(line, file_path, line_num)
                secrets.extend(entropy_secrets)
            
            # Context-aware detection
            if self.detection_config['enable_context_analysis']:
                context_secrets = await self._detect_context_in_line(line, file_path, line_num)
                secrets.extend(context_secrets)
        
        # Post-process and filter
        filtered_secrets = await self._post_process_secrets(secrets, content)
        
        return filtered_secrets
    
    async def analyze_project_secrets(self, file_contents: Dict[str, str]) -> SecretsAnalysisResult:
        """Analyze secrets across multiple files."""
        
        all_secrets = []
        files_scanned = len(file_contents)
        lines_scanned = 0
        
        for file_path, content in file_contents.items():
            lines_scanned += len(content.splitlines())
            file_secrets = await self.detect_secrets_in_content(content, file_path)
            all_secrets.extend(file_secrets)
        
        # Generate analysis result
        result = await self._generate_analysis_result(all_secrets, files_scanned, lines_scanned)
        
        return result
    
    async def _detect_patterns_in_line(self, line: str, file_path: str, line_num: int) -> List[SecretMatch]:
        """Detect secrets using pattern matching."""
        
        secrets = []
        
        for secret_type, patterns in self.secret_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['regex']
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    # Extract the secret value
                    secret_value = match.group(pattern_info.get('group', 0))
                    
                    # Skip if too short or too long
                    if (len(secret_value) < self.detection_config['min_secret_length'] or 
                        len(secret_value) > self.detection_config['max_secret_length']):
                        continue
                    
                    # Calculate confidence
                    confidence = self._calculate_pattern_confidence(secret_value, pattern_info)
                    
                    if confidence >= self.detection_config['confidence_threshold']:
                        secret_match = SecretMatch(
                            secret_type=secret_type,
                            detection_method=DetectionMethod.PATTERN_MATCH,
                            file_path=file_path,
                            line_number=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            matched_text=secret_value,
                            context=line.strip(),
                            confidence=confidence,
                            entropy=self._calculate_entropy(secret_value),
                            false_positive_likelihood=0.0,
                            pattern_name=pattern_info['name'],
                            pattern_regex=pattern,
                            variable_name=self._extract_variable_name(line, match.start()),
                            surrounding_keywords=self._extract_surrounding_keywords(line),
                            remediation_advice=pattern_info.get('remediation', 'Remove or use environment variables')
                        )
                        
                        secrets.append(secret_match)
                        self.stats['pattern_detections'] += 1
        
        return secrets
    
    async def _detect_entropy_in_line(self, line: str, file_path: str, line_num: int) -> List[SecretMatch]:
        """Detect secrets using entropy analysis."""
        
        secrets = []
        
        # Find potential secret strings (alphanumeric sequences)
        potential_secrets = re.finditer(r'[A-Za-z0-9+/=]{' + str(self.detection_config['min_secret_length']) + ',}', line)
        
        for match in potential_secrets:
            secret_value = match.group()
            
            # Skip if too long
            if len(secret_value) > self.detection_config['max_secret_length']:
                continue
            
            # Calculate entropy
            entropy = self._calculate_entropy(secret_value)
            
            if entropy >= self.detection_config['min_entropy_threshold']:
                # Determine likely secret type based on characteristics
                secret_type = self._classify_high_entropy_string(secret_value)
                
                # Calculate confidence based on entropy and characteristics
                confidence = self._calculate_entropy_confidence(secret_value, entropy)
                
                if confidence >= self.detection_config['confidence_threshold']:
                    secret_match = SecretMatch(
                        secret_type=secret_type,
                        detection_method=DetectionMethod.ENTROPY_ANALYSIS,
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        matched_text=secret_value,
                        context=line.strip(),
                        confidence=confidence,
                        entropy=entropy,
                        false_positive_likelihood=0.0,
                        variable_name=self._extract_variable_name(line, match.start()),
                        surrounding_keywords=self._extract_surrounding_keywords(line),
                        remediation_advice='Replace with environment variable or secure vault'
                    )
                    
                    secrets.append(secret_match)
                    self.stats['entropy_detections'] += 1
        
        return secrets
    
    async def _detect_context_in_line(self, line: str, file_path: str, line_num: int) -> List[SecretMatch]:
        """Detect secrets using context analysis."""
        
        secrets = []
        
        # Look for context keywords that suggest secrets
        for secret_type, keywords in self.context_keywords.items():
            for keyword in keywords:
                # Look for patterns like: keyword = "value" or keyword: "value"
                patterns = [
                    rf'{re.escape(keyword)}\s*[:=]\s*["\']([^"\']+)["\']',
                    rf'{re.escape(keyword)}\s*[:=]\s*([A-Za-z0-9+/=_-]+)',
                ]
                
                for pattern in patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    
                    for match in matches:
                        secret_value = match.group(1)
                        
                        # Skip if too short or looks like placeholder
                        if (len(secret_value) < self.detection_config['min_secret_length'] or
                            self._is_likely_placeholder(secret_value)):
                            continue
                        
                        # Calculate confidence based on context and value characteristics
                        confidence = self._calculate_context_confidence(secret_value, keyword, line)
                        
                        if confidence >= self.detection_config['confidence_threshold']:
                            secret_match = SecretMatch(
                                secret_type=secret_type,
                                detection_method=DetectionMethod.CONTEXT_ANALYSIS,
                                file_path=file_path,
                                line_number=line_num,
                                column_start=match.start(1),
                                column_end=match.end(1),
                                matched_text=secret_value,
                                context=line.strip(),
                                confidence=confidence,
                                entropy=self._calculate_entropy(secret_value),
                                false_positive_likelihood=0.0,
                                variable_name=keyword,
                                surrounding_keywords=[keyword],
                                remediation_advice=f'Move {keyword} to environment variables'
                            )
                            
                            secrets.append(secret_match)
                            self.stats['context_detections'] += 1
        
        return secrets
    
    async def _post_process_secrets(self, secrets: List[SecretMatch], content: str) -> List[SecretMatch]:
        """Post-process detected secrets to reduce false positives."""
        
        if not self.detection_config['reduce_false_positives']:
            return secrets
        
        filtered_secrets = []
        
        for secret in secrets:
            # Check for false positive indicators
            false_positive_likelihood = self._calculate_false_positive_likelihood(secret, content)
            secret.false_positive_likelihood = false_positive_likelihood
            
            # Mark test/example indicators
            secret.is_likely_test = self._is_likely_test_secret(secret, content)
            secret.is_likely_example = self._is_likely_example_secret(secret, content)
            secret.is_likely_placeholder = self._is_likely_placeholder(secret.matched_text)
            
            # Adjust confidence based on false positive likelihood
            adjusted_confidence = secret.confidence * (1 - false_positive_likelihood)
            secret.confidence = adjusted_confidence
            
            # Filter based on adjusted confidence
            if adjusted_confidence >= self.detection_config['confidence_threshold']:
                filtered_secrets.append(secret)
            else:
                self.stats['false_positives_filtered'] += 1
        
        return filtered_secrets
    
    def _initialize_secret_patterns(self) -> Dict[SecretType, List[Dict[str, Any]]]:
        """Initialize secret detection patterns."""
        
        return {
            SecretType.AWS_ACCESS_KEY: [{
                'name': 'AWS Access Key ID',
                'regex': r'\b(AKIA[0-9A-Z]{16})\b',
                'group': 1,
                'confidence_base': 0.95,
                'remediation': 'Rotate AWS access key and use IAM roles or environment variables'
            }],
            
            SecretType.AWS_SECRET_KEY: [{
                'name': 'AWS Secret Access Key',
                'regex': r'\b([A-Za-z0-9/+=]{40})\b',
                'group': 1,
                'confidence_base': 0.7,
                'remediation': 'Rotate AWS secret key and use secure credential storage'
            }],
            
            SecretType.GITHUB_TOKEN: [
                {
                    'name': 'GitHub Personal Access Token',
                    'regex': r'\b(ghp_[A-Za-z0-9]{36})\b',
                    'group': 1,
                    'confidence_base': 0.98
                },
                {
                    'name': 'GitHub OAuth Token',
                    'regex': r'\b(gho_[A-Za-z0-9]{36})\b',
                    'group': 1,
                    'confidence_base': 0.98
                },
                {
                    'name': 'GitHub App Token',
                    'regex': r'\b(ghs_[A-Za-z0-9]{36})\b',
                    'group': 1,
                    'confidence_base': 0.98
                }
            ],
            
            SecretType.SLACK_TOKEN: [{
                'name': 'Slack Token',
                'regex': r'\b(xox[baprs]-[A-Za-z0-9-]+)\b',
                'group': 1,
                'confidence_base': 0.95
            }],
            
            SecretType.STRIPE_KEY: [
                {
                    'name': 'Stripe Secret Key',
                    'regex': r'\b(sk_live_[A-Za-z0-9]{24,})\b',
                    'group': 1,
                    'confidence_base': 0.98
                },
                {
                    'name': 'Stripe Test Key',
                    'regex': r'\b(sk_test_[A-Za-z0-9]{24,})\b',
                    'group': 1,
                    'confidence_base': 0.95
                }
            ],
            
            SecretType.JWT_TOKEN: [{
                'name': 'JSON Web Token',
                'regex': r'\b(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b',
                'group': 1,
                'confidence_base': 0.85
            }],
            
            SecretType.PRIVATE_KEY: [
                {
                    'name': 'RSA Private Key',
                    'regex': r'-----BEGIN RSA PRIVATE KEY-----',
                    'group': 0,
                    'confidence_base': 0.99
                },
                {
                    'name': 'Private Key',
                    'regex': r'-----BEGIN PRIVATE KEY-----',
                    'group': 0,
                    'confidence_base': 0.99
                },
                {
                    'name': 'EC Private Key',
                    'regex': r'-----BEGIN EC PRIVATE KEY-----',
                    'group': 0,
                    'confidence_base': 0.99
                }
            ],
            
            SecretType.API_KEY: [{
                'name': 'Generic API Key',
                'regex': r'\b([A-Za-z0-9]{32,})\b',
                'group': 1,
                'confidence_base': 0.6
            }],
            
            SecretType.DATABASE_URL: [{
                'name': 'Database Connection String',
                'regex': r'((?:mysql|postgresql|mongodb|redis)://[^\s]+)',
                'group': 1,
                'confidence_base': 0.9
            }],
            
            SecretType.WEBHOOK_URL: [{
                'name': 'Webhook URL',
                'regex': r'(https://hooks\.[^\s]+)',
                'group': 1,
                'confidence_base': 0.8
            }]
        }
    
    def _initialize_context_keywords(self) -> Dict[SecretType, List[str]]:
        """Initialize context keywords for different secret types."""
        
        return {
            SecretType.PASSWORD: [
                'password', 'passwd', 'pwd', 'pass', 'secret', 'auth_token'
            ],
            SecretType.API_KEY: [
                'api_key', 'apikey', 'api-key', 'key', 'token', 'access_token',
                'client_secret', 'app_secret', 'secret_key'
            ],
            SecretType.AWS_ACCESS_KEY: [
                'aws_access_key_id', 'aws_access_key', 'access_key_id'
            ],
            SecretType.AWS_SECRET_KEY: [
                'aws_secret_access_key', 'aws_secret_key', 'secret_access_key'
            ],
            SecretType.DATABASE_URL: [
                'database_url', 'db_url', 'connection_string', 'conn_str',
                'mongodb_uri', 'postgres_url', 'mysql_url'
            ],
            SecretType.PRIVATE_KEY: [
                'private_key', 'priv_key', 'ssl_key', 'rsa_key', 'ssh_key'
            ],
            SecretType.CERTIFICATE: [
                'certificate', 'cert', 'ssl_cert', 'tls_cert', 'public_key'
            ]
        }
    
    def _initialize_false_positive_indicators(self) -> List[str]:
        """Initialize false positive indicators."""
        
        return [
            # Common placeholders
            'placeholder', 'example', 'sample', 'dummy', 'fake', 'test',
            'your_key_here', 'insert_key', 'replace_with', 'todo',
            
            # Test indicators
            'test_key', 'test_secret', 'test_token', 'mock_', 'stub_',
            'fixture_', 'spec_', 'demo_',
            
            # Documentation indicators
            'docs', 'documentation', 'readme', 'guide', 'tutorial',
            
            # Common non-secrets
            'localhost', '127.0.0.1', '0.0.0.0', 'example.com',
            'null', 'undefined', 'none', 'empty', 'default'
        ]
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        
        if not string:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        string_length = len(string)
        
        for count in char_counts.values():
            probability = count / string_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_pattern_confidence(self, secret_value: str, pattern_info: Dict[str, Any]) -> float:
        """Calculate confidence for pattern-based detection."""
        
        base_confidence = pattern_info.get('confidence_base', 0.8)
        
        # Adjust based on entropy
        entropy = self._calculate_entropy(secret_value)
        entropy_bonus = min(0.2, entropy / 10)
        
        # Adjust based on length
        length_bonus = 0.0
        if len(secret_value) >= 20:
            length_bonus = 0.1
        elif len(secret_value) >= 32:
            length_bonus = 0.15
        
        return min(1.0, base_confidence + entropy_bonus + length_bonus)
    
    def _calculate_entropy_confidence(self, secret_value: str, entropy: float) -> float:
        """Calculate confidence for entropy-based detection."""
        
        # Base confidence from entropy
        base_confidence = min(0.8, entropy / 6)
        
        # Bonus for specific characteristics
        bonus = 0.0
        
        # Mixed case bonus
        if any(c.isupper() for c in secret_value) and any(c.islower() for c in secret_value):
            bonus += 0.1
        
        # Numbers and letters bonus
        if any(c.isdigit() for c in secret_value) and any(c.isalpha() for c in secret_value):
            bonus += 0.1
        
        # Special characters bonus
        if any(c in '+/=' for c in secret_value):
            bonus += 0.05
        
        # Length bonus
        if len(secret_value) >= 32:
            bonus += 0.1
        
        return min(1.0, base_confidence + bonus)
    
    def _calculate_context_confidence(self, secret_value: str, keyword: str, line: str) -> float:
        """Calculate confidence for context-based detection."""
        
        base_confidence = 0.7
        
        # Entropy bonus
        entropy = self._calculate_entropy(secret_value)
        entropy_bonus = min(0.2, entropy / 10)
        
        # Keyword strength bonus
        strong_keywords = ['secret', 'password', 'token', 'key']
        if any(strong_word in keyword.lower() for strong_word in strong_keywords):
            base_confidence += 0.1
        
        # Context clues
        if 'prod' in line.lower() or 'live' in line.lower():
            base_confidence += 0.1
        
        return min(1.0, base_confidence + entropy_bonus)
    
    def _calculate_false_positive_likelihood(self, secret: SecretMatch, content: str) -> float:
        """Calculate likelihood that detection is a false positive."""
        
        likelihood = 0.0
        secret_text = secret.matched_text.lower()
        context = secret.context.lower()
        
        # Check for false positive indicators
        for indicator in self.false_positive_indicators:
            if indicator in secret_text or indicator in context:
                likelihood += 0.3
        
        # Check for test file indicators
        if any(test_indicator in secret.file_path.lower() 
               for test_indicator in ['test', 'spec', 'mock', 'fixture']):
            likelihood += 0.4
        
        # Check for documentation indicators
        if any(doc_indicator in secret.file_path.lower() 
               for doc_indicator in ['readme', 'doc', 'example', 'demo']):
            likelihood += 0.5
        
        # Check for obvious placeholders
        placeholder_patterns = [
            r'xxx+', r'aaa+', r'111+', r'000+', r'your_\w+', r'insert_\w+',
            r'replace_\w+', r'example_\w+', r'sample_\w+'
        ]
        
        for pattern in placeholder_patterns:
            if re.search(pattern, secret_text):
                likelihood += 0.6
        
        # Check for repeated characters (likely placeholder)
        if len(set(secret_text)) <= 3 and len(secret_text) > 10:
            likelihood += 0.7
        
        return min(1.0, likelihood)
    
    def _classify_high_entropy_string(self, secret_value: str) -> SecretType:
        """Classify high-entropy string into likely secret type."""
        
        # Base64 pattern
        if re.match(r'^[A-Za-z0-9+/=]+$', secret_value) and len(secret_value) % 4 == 0:
            if len(secret_value) == 40:
                return SecretType.AWS_SECRET_KEY
            elif len(secret_value) >= 32:
                return SecretType.API_KEY
        
        # Hex pattern
        if re.match(r'^[A-Fa-f0-9]+$', secret_value):
            return SecretType.API_KEY
        
        # JWT pattern
        if '.' in secret_value and secret_value.startswith('eyJ'):
            return SecretType.JWT_TOKEN
        
        return SecretType.GENERIC_SECRET
    
    def _extract_variable_name(self, line: str, position: int) -> str:
        """Extract variable name from line at given position."""
        
        # Look backwards for variable assignment pattern
        prefix = line[:position]
        
        # Common patterns: var = value, "var": value, var: value
        patterns = [
            r'(\w+)\s*[:=]\s*["\']?$',
            r'["\'](\w+)["\']\s*:\s*["\']?$'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, prefix)
            if match:
                return match.group(1)
        
        return ""
    
    def _extract_surrounding_keywords(self, line: str) -> List[str]:
        """Extract keywords from the line that might indicate secret context."""
        
        keywords = []
        
        # Look for common secret-related words
        secret_words = [
            'password', 'secret', 'key', 'token', 'auth', 'credential',
            'api', 'access', 'private', 'public', 'cert', 'ssl', 'tls'
        ]
        
        line_lower = line.lower()
        for word in secret_words:
            if word in line_lower:
                keywords.append(word)
        
        return keywords
    
    def _is_likely_test_secret(self, secret: SecretMatch, content: str) -> bool:
        """Check if secret is likely from test code."""
        
        test_indicators = [
            'test', 'spec', 'mock', 'fixture', 'stub', 'fake',
            'jest', 'mocha', 'jasmine', 'cypress', 'selenium'
        ]
        
        return (any(indicator in secret.file_path.lower() for indicator in test_indicators) or
                any(indicator in secret.context.lower() for indicator in test_indicators))
    
    def _is_likely_example_secret(self, secret: SecretMatch, content: str) -> bool:
        """Check if secret is likely from example/documentation code."""
        
        example_indicators = [
            'example', 'demo', 'sample', 'tutorial', 'guide',
            'readme', 'doc', 'documentation'
        ]
        
        return (any(indicator in secret.file_path.lower() for indicator in example_indicators) or
                any(indicator in content.lower()[:500] for indicator in example_indicators))
    
    def _is_likely_placeholder(self, secret_value: str) -> bool:
        """Check if value is likely a placeholder."""
        
        placeholder_patterns = [
            r'^(xxx+|aaa+|111+|000+)$',
            r'your_\w+',
            r'insert_\w+',
            r'replace_\w+',
            r'example_\w+',
            r'sample_\w+',
            r'placeholder',
            r'todo',
            r'fixme'
        ]
        
        secret_lower = secret_value.lower()
        return any(re.search(pattern, secret_lower) for pattern in placeholder_patterns)
    
    async def _generate_analysis_result(self, secrets: List[SecretMatch], 
                                       files_scanned: int, lines_scanned: int) -> SecretsAnalysisResult:
        """Generate comprehensive secrets analysis result."""
        
        # Count secrets by type
        secrets_by_type = {}
        for secret in secrets:
            secrets_by_type[secret.secret_type] = secrets_by_type.get(secret.secret_type, 0) + 1
        
        # Count secrets by file
        secrets_by_file = {}
        for secret in secrets:
            secrets_by_file[secret.file_path] = secrets_by_file.get(secret.file_path, 0) + 1
        
        # Count high confidence secrets
        high_confidence_secrets = len([s for s in secrets if s.confidence >= 0.8])
        
        # Count likely false positives
        likely_false_positives = len([s for s in secrets if s.false_positive_likelihood >= 0.5])
        
        # Identify critical secrets
        critical_secrets = [s for s in secrets 
                          if s.secret_type in [SecretType.PRIVATE_KEY, SecretType.AWS_SECRET_KEY, 
                                             SecretType.DATABASE_URL] and s.confidence >= 0.8]
        
        # Calculate overall risk score
        risk_score = 0.0
        for secret in secrets:
            if secret.secret_type == SecretType.PRIVATE_KEY:
                risk_score += 30 * secret.confidence
            elif secret.secret_type in [SecretType.AWS_SECRET_KEY, SecretType.DATABASE_URL]:
                risk_score += 25 * secret.confidence
            elif secret.secret_type in [SecretType.API_KEY, SecretType.PASSWORD]:
                risk_score += 15 * secret.confidence
            else:
                risk_score += 10 * secret.confidence
        
        # Count detection method statistics
        patterns_matched = len([s for s in secrets if s.detection_method == DetectionMethod.PATTERN_MATCH])
        entropy_detections = len([s for s in secrets if s.detection_method == DetectionMethod.ENTROPY_ANALYSIS])
        
        return SecretsAnalysisResult(
            total_secrets_found=len(secrets),
            secrets_by_type=secrets_by_type,
            secrets_by_file=secrets_by_file,
            high_confidence_secrets=high_confidence_secrets,
            likely_false_positives=likely_false_positives,
            secret_matches=secrets,
            overall_risk_score=min(100.0, risk_score),
            critical_secrets=critical_secrets,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            patterns_matched=patterns_matched,
            entropy_detections=entropy_detections
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        
        return dict(self.stats)
