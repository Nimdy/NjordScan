"""
AI-Powered Code Understanding Engine

Uses natural language processing concepts and semantic analysis to understand code intent,
detect suspicious patterns, and provide intelligent security insights.
"""

import re
import ast
import json
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import logging

logger = logging.getLogger(__name__)

class CodeIntent(Enum):
    """Detected code intent categories."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    OBFUSCATED = "obfuscated"
    ENCRYPTED = "encrypted"
    UNKNOWN = "unknown"

class CodeComplexity(Enum):
    """Code complexity levels."""
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    HIGHLY_COMPLEX = "highly_complex"

@dataclass
class CodeFeatures:
    """Extracted code features for analysis."""
    # Lexical features
    total_lines: int = 0
    code_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0
    
    # Syntactic features
    function_count: int = 0
    class_count: int = 0
    variable_count: int = 0
    import_count: int = 0
    
    # Semantic features
    cyclomatic_complexity: int = 0
    nesting_depth: int = 0
    api_calls: List[str] = field(default_factory=list)
    external_references: List[str] = field(default_factory=list)
    
    # Security-relevant features
    dynamic_code_execution: List[str] = field(default_factory=list)
    network_operations: List[str] = field(default_factory=list)
    file_operations: List[str] = field(default_factory=list)
    crypto_operations: List[str] = field(default_factory=list)
    
    # String analysis
    string_entropy: float = 0.0
    suspicious_strings: List[str] = field(default_factory=list)
    base64_strings: List[str] = field(default_factory=list)
    hex_strings: List[str] = field(default_factory=list)
    
    # Obfuscation indicators
    obfuscation_score: float = 0.0
    minified: bool = False
    packed: bool = False

@dataclass
class CodeUnderstandingResult:
    """Result of code understanding analysis."""
    file_path: str
    language: str
    
    # Primary analysis
    intent: CodeIntent
    confidence: float
    complexity: CodeComplexity
    
    # Extracted features
    features: CodeFeatures
    
    # Security analysis
    security_score: float  # 0-100, higher = more secure
    risk_factors: List[str]
    suspicious_patterns: List[Dict[str, Any]]
    
    # Semantic analysis
    function_purposes: Dict[str, str]
    data_flows: List[Dict[str, Any]]
    control_flows: List[Dict[str, Any]]
    
    # Natural language insights
    summary: str
    recommendations: List[str]
    
    # Metadata
    analysis_time: float
    analyzer_version: str

class CodeUnderstandingEngine:
    """AI-powered code understanding and analysis engine."""
    
    def __init__(self):
        # Language detection patterns
        self.language_patterns = {
            'javascript': [r'\.js$', r'\.jsx$', r'\.mjs$', r'\.es6$'],
            'typescript': [r'\.ts$', r'\.tsx$'],
            'python': [r'\.py$', r'\.pyw$'],
            'java': [r'\.java$'],
            'php': [r'\.php$', r'\.phtml$'],
            'go': [r'\.go$'],
            'rust': [r'\.rs$'],
            'c': [r'\.c$', r'\.h$'],
            'cpp': [r'\.cpp$', r'\.cxx$', r'\.hpp$'],
            'csharp': [r'\.cs$'],
            'ruby': [r'\.rb$'],
            'shell': [r'\.sh$', r'\.bash$', r'\.zsh$']
        }
        
        # Security-relevant API patterns
        self.security_apis = {
            'javascript': {
                'dynamic_execution': [
                    r'eval\s*\(', r'Function\s*\(', r'setTimeout\s*\([^,]*[\'"`]',
                    r'setInterval\s*\([^,]*[\'"`]', r'new\s+Function\s*\('
                ],
                'network': [
                    r'fetch\s*\(', r'XMLHttpRequest', r'axios\.',
                    r'WebSocket\s*\(', r'navigator\.sendBeacon'
                ],
                'file_ops': [
                    r'fs\.', r'require\s*\(\s*[\'"`]fs[\'"`]',
                    r'readFile', r'writeFile', r'createReadStream'
                ],
                'crypto': [
                    r'crypto\.', r'CryptoJS\.', r'btoa\s*\(',
                    r'atob\s*\(', r'hashCode', r'encrypt', r'decrypt'
                ]
            },
            'python': {
                'dynamic_execution': [
                    r'eval\s*\(', r'exec\s*\(', r'compile\s*\(',
                    r'__import__\s*\(', r'importlib\.'
                ],
                'network': [
                    r'requests\.', r'urllib\.', r'httplib\.',
                    r'socket\.', r'aiohttp\.'
                ],
                'file_ops': [
                    r'open\s*\(', r'os\.', r'pathlib\.',
                    r'shutil\.', r'glob\.'
                ],
                'crypto': [
                    r'hashlib\.', r'cryptography\.', r'Crypto\.',
                    r'base64\.', r'hmac\.'
                ]
            }
        }
        
        # Suspicious string patterns
        self.suspicious_patterns = {
            'base64_like': r'[A-Za-z0-9+/]{20,}={0,2}',
            'hex_encoded': r'(?:0x)?[0-9a-fA-F]{16,}',
            'url_suspicious': r'https?://[^\s]*\.(?:tk|ml|ga|cf|bit)/',
            'shell_commands': r'(?:cmd|powershell|bash|sh)\s+[/-]',
            'sql_injection': r'(?:union|select|insert|update|delete|drop)\s+',
            'xss_patterns': r'<script[^>]*>|javascript:|on\w+\s*=',
            'path_traversal': r'\.\.\/|\.\.\\',
            'command_injection': r'[;&|`$]\s*\w+',
        }
        
        # Obfuscation indicators
        self.obfuscation_indicators = {
            'variable_names': r'[a-zA-Z_$][a-zA-Z0-9_$]*',
            'string_concatenation': r'[\'"`][^\'"`]*[\'"`]\s*\+\s*[\'"`]',
            'char_codes': r'String\.fromCharCode\s*\(',
            'unicode_escape': r'\\u[0-9a-fA-F]{4}',
            'hex_escape': r'\\x[0-9a-fA-F]{2}',
            'array_access': r'\[[0-9]+\]',
        }
        
        # Function purpose inference patterns
        self.function_purpose_patterns = {
            'authentication': [
                r'(?:login|auth|signin|verify|validate).*(?:user|password|token)',
                r'(?:check|verify).*(?:credential|permission|access)'
            ],
            'data_processing': [
                r'(?:process|parse|transform|convert|format).*data',
                r'(?:serialize|deserialize|encode|decode)'
            ],
            'network_communication': [
                r'(?:send|receive|fetch|request|response)',
                r'(?:http|api|rest|graphql|websocket)'
            ],
            'file_handling': [
                r'(?:read|write|create|delete|upload|download).*(?:file|document)',
                r'(?:fs|filesystem|storage|disk)'
            ],
            'cryptographic': [
                r'(?:encrypt|decrypt|hash|sign|verify)',
                r'(?:crypto|cipher|key|certificate)'
            ],
            'validation': [
                r'(?:validate|sanitize|clean|escape|filter)',
                r'(?:input|output|data).*(?:validation|sanitization)'
            ]
        }
        
        # NLP-like keyword analysis
        self.security_keywords = {
            'high_risk': [
                'password', 'secret', 'key', 'token', 'credential',
                'admin', 'root', 'sudo', 'privilege', 'backdoor',
                'exploit', 'payload', 'shellcode', 'malware'
            ],
            'medium_risk': [
                'user', 'session', 'cookie', 'auth', 'login',
                'database', 'sql', 'query', 'connection',
                'network', 'socket', 'http', 'api'
            ],
            'crypto_related': [
                'encrypt', 'decrypt', 'hash', 'cipher', 'crypto',
                'ssl', 'tls', 'certificate', 'signature', 'random'
            ],
            'file_system': [
                'file', 'directory', 'path', 'read', 'write',
                'upload', 'download', 'stream', 'buffer'
            ]
        }
        
        # Statistics
        self.stats = {
            'files_analyzed': 0,
            'total_lines_processed': 0,
            'suspicious_files_detected': 0,
            'malicious_files_detected': 0,
            'obfuscated_files_detected': 0
        }
    
    async def analyze_code(self, file_path: str, content: str, 
                          context: Dict[str, Any] = None) -> CodeUnderstandingResult:
        """Perform comprehensive code understanding analysis."""
        
        import time
        start_time = time.time()
        
        logger.info(f"Analyzing code understanding for: {file_path}")
        
        # Detect language
        language = self._detect_language(file_path, content)
        
        # Extract code features
        features = await self._extract_code_features(content, language)
        
        # Analyze code intent
        intent, confidence = await self._analyze_code_intent(content, features, language)
        
        # Determine complexity
        complexity = self._determine_complexity(features)
        
        # Calculate security score
        security_score = self._calculate_security_score(features, intent)
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(features, intent)
        
        # Find suspicious patterns
        suspicious_patterns = await self._find_suspicious_patterns(content, language)
        
        # Analyze function purposes
        function_purposes = await self._analyze_function_purposes(content, language)
        
        # Analyze data flows
        data_flows = await self._analyze_data_flows(content, language)
        
        # Analyze control flows
        control_flows = await self._analyze_control_flows(content, language)
        
        # Generate natural language summary
        summary = self._generate_summary(intent, features, security_score, risk_factors)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            intent, features, risk_factors, suspicious_patterns
        )
        
        # Create result
        result = CodeUnderstandingResult(
            file_path=file_path,
            language=language,
            intent=intent,
            confidence=confidence,
            complexity=complexity,
            features=features,
            security_score=security_score,
            risk_factors=risk_factors,
            suspicious_patterns=suspicious_patterns,
            function_purposes=function_purposes,
            data_flows=data_flows,
            control_flows=control_flows,
            summary=summary,
            recommendations=recommendations,
            analysis_time=time.time() - start_time,
            analyzer_version="1.0.0"
        )
        
        # Update statistics
        self._update_stats(result)
        
        logger.info(f"Code analysis completed in {result.analysis_time:.2f}s. "
                   f"Intent: {intent.value}, Security Score: {security_score:.1f}")
        
        return result
    
    def _detect_language(self, file_path: str, content: str) -> str:
        """Detect programming language from file path and content."""
        
        # Check file extension first
        for language, patterns in self.language_patterns.items():
            if any(re.search(pattern, file_path, re.IGNORECASE) for pattern in patterns):
                return language
        
        # Analyze content for language indicators
        language_indicators = {
            'javascript': [r'function\s+\w+\s*\(', r'var\s+\w+', r'const\s+\w+', r'let\s+\w+'],
            'python': [r'def\s+\w+\s*\(', r'import\s+\w+', r'from\s+\w+\s+import', r'if\s+__name__'],
            'java': [r'public\s+class\s+\w+', r'public\s+static\s+void\s+main'],
            'php': [r'<\?php', r'\$\w+'],
            'go': [r'package\s+\w+', r'func\s+\w+\s*\('],
            'rust': [r'fn\s+\w+\s*\(', r'let\s+mut\s+\w+'],
        }
        
        for language, patterns in language_indicators.items():
            if any(re.search(pattern, content) for pattern in patterns):
                return language
        
        return 'unknown'
    
    async def _extract_code_features(self, content: str, language: str) -> CodeFeatures:
        """Extract comprehensive code features."""
        
        features = CodeFeatures()
        
        # Basic line statistics
        lines = content.split('\n')
        features.total_lines = len(lines)
        features.blank_lines = sum(1 for line in lines if not line.strip())
        features.comment_lines = self._count_comment_lines(lines, language)
        features.code_lines = features.total_lines - features.blank_lines - features.comment_lines
        
        # Syntactic features
        features.function_count = self._count_functions(content, language)
        features.class_count = self._count_classes(content, language)
        features.variable_count = self._count_variables(content, language)
        features.import_count = self._count_imports(content, language)
        
        # Complexity metrics
        features.cyclomatic_complexity = self._calculate_cyclomatic_complexity(content, language)
        features.nesting_depth = self._calculate_nesting_depth(content, language)
        
        # API and external references
        features.api_calls = self._extract_api_calls(content, language)
        features.external_references = self._extract_external_references(content, language)
        
        # Security-relevant features
        if language in self.security_apis:
            apis = self.security_apis[language]
            features.dynamic_code_execution = self._find_patterns(content, apis.get('dynamic_execution', []))
            features.network_operations = self._find_patterns(content, apis.get('network', []))
            features.file_operations = self._find_patterns(content, apis.get('file_ops', []))
            features.crypto_operations = self._find_patterns(content, apis.get('crypto', []))
        
        # String analysis
        features.string_entropy = self._calculate_string_entropy(content)
        features.suspicious_strings = self._find_suspicious_strings(content)
        features.base64_strings = self._find_base64_strings(content)
        features.hex_strings = self._find_hex_strings(content)
        
        # Obfuscation analysis
        features.obfuscation_score = self._calculate_obfuscation_score(content, language)
        features.minified = self._is_minified(content)
        features.packed = self._is_packed(content)
        
        return features
    
    async def _analyze_code_intent(self, content: str, features: CodeFeatures, 
                                  language: str) -> Tuple[CodeIntent, float]:
        """Analyze the intent of the code using ML-inspired techniques."""
        
        # Feature-based classification (simulating ML model)
        intent_scores = {
            CodeIntent.BENIGN: 0.5,      # Default baseline
            CodeIntent.SUSPICIOUS: 0.0,
            CodeIntent.MALICIOUS: 0.0,
            CodeIntent.OBFUSCATED: 0.0,
            CodeIntent.ENCRYPTED: 0.0
        }
        
        # Obfuscation indicators
        if features.obfuscation_score > 0.7:
            intent_scores[CodeIntent.OBFUSCATED] += 0.4
            intent_scores[CodeIntent.SUSPICIOUS] += 0.2
        
        if features.minified or features.packed:
            intent_scores[CodeIntent.OBFUSCATED] += 0.2
        
        # Dynamic code execution (high risk)
        if features.dynamic_code_execution:
            intent_scores[CodeIntent.SUSPICIOUS] += 0.3
            intent_scores[CodeIntent.MALICIOUS] += 0.1 * len(features.dynamic_code_execution)
        
        # Suspicious strings
        if features.suspicious_strings:
            intent_scores[CodeIntent.SUSPICIOUS] += 0.2
            intent_scores[CodeIntent.MALICIOUS] += 0.05 * len(features.suspicious_strings)
        
        # High entropy strings (possible encryption/encoding)
        if features.string_entropy > 4.5:
            intent_scores[CodeIntent.ENCRYPTED] += 0.3
            intent_scores[CodeIntent.OBFUSCATED] += 0.2
        
        # Network operations with suspicious domains
        suspicious_network_ops = [
            op for op in features.network_operations
            if any(domain in op for domain in ['.tk', '.ml', '.ga', '.cf'])
        ]
        if suspicious_network_ops:
            intent_scores[CodeIntent.MALICIOUS] += 0.4
        
        # Excessive complexity (possible obfuscation)
        if features.cyclomatic_complexity > 20:
            intent_scores[CodeIntent.OBFUSCATED] += 0.1
            intent_scores[CodeIntent.SUSPICIOUS] += 0.1
        
        # Base64 and hex strings (encoding indicators)
        if features.base64_strings or features.hex_strings:
            intent_scores[CodeIntent.ENCRYPTED] += 0.2
            intent_scores[CodeIntent.SUSPICIOUS] += 0.1
        
        # File operations (potential data theft)
        if len(features.file_operations) > 5:
            intent_scores[CodeIntent.SUSPICIOUS] += 0.1
        
        # Normalize scores
        max_score = max(intent_scores.values())
        if max_score > 1.0:
            for intent in intent_scores:
                intent_scores[intent] = min(1.0, intent_scores[intent])
        
        # Determine primary intent
        primary_intent = max(intent_scores, key=intent_scores.get)
        confidence = intent_scores[primary_intent]
        
        # Adjust confidence based on multiple indicators
        total_indicators = sum(1 for score in intent_scores.values() if score > 0.1)
        if total_indicators > 2:
            confidence = min(1.0, confidence * 1.2)  # Higher confidence with multiple indicators
        
        return primary_intent, confidence
    
    def _determine_complexity(self, features: CodeFeatures) -> CodeComplexity:
        """Determine code complexity level."""
        
        # Complexity scoring
        complexity_score = 0
        
        # Cyclomatic complexity contribution
        if features.cyclomatic_complexity > 50:
            complexity_score += 3
        elif features.cyclomatic_complexity > 20:
            complexity_score += 2
        elif features.cyclomatic_complexity > 10:
            complexity_score += 1
        
        # Nesting depth contribution
        if features.nesting_depth > 8:
            complexity_score += 2
        elif features.nesting_depth > 5:
            complexity_score += 1
        
        # Function and class count
        total_constructs = features.function_count + features.class_count
        if total_constructs > 50:
            complexity_score += 2
        elif total_constructs > 20:
            complexity_score += 1
        
        # Lines of code
        if features.code_lines > 1000:
            complexity_score += 2
        elif features.code_lines > 500:
            complexity_score += 1
        
        # Map to complexity enum
        if complexity_score >= 7:
            return CodeComplexity.HIGHLY_COMPLEX
        elif complexity_score >= 4:
            return CodeComplexity.COMPLEX
        elif complexity_score >= 2:
            return CodeComplexity.MODERATE
        else:
            return CodeComplexity.SIMPLE
    
    def _calculate_security_score(self, features: CodeFeatures, intent: CodeIntent) -> float:
        """Calculate security score (0-100, higher = more secure)."""
        
        base_score = 70.0  # Start with neutral score
        
        # Intent-based adjustments
        intent_penalties = {
            CodeIntent.MALICIOUS: -50,
            CodeIntent.SUSPICIOUS: -30,
            CodeIntent.OBFUSCATED: -20,
            CodeIntent.ENCRYPTED: -10,
            CodeIntent.BENIGN: 0,
            CodeIntent.UNKNOWN: -5
        }
        
        base_score += intent_penalties.get(intent, 0)
        
        # Feature-based adjustments
        if features.dynamic_code_execution:
            base_score -= len(features.dynamic_code_execution) * 10
        
        if features.suspicious_strings:
            base_score -= len(features.suspicious_strings) * 5
        
        if features.obfuscation_score > 0.5:
            base_score -= features.obfuscation_score * 20
        
        # Positive security indicators
        if features.crypto_operations and not features.suspicious_strings:
            base_score += 5  # Legitimate crypto usage
        
        # Complexity penalty (overly complex code is harder to audit)
        if features.cyclomatic_complexity > 30:
            base_score -= 10
        
        return max(0.0, min(100.0, base_score))
    
    def _identify_risk_factors(self, features: CodeFeatures, intent: CodeIntent) -> List[str]:
        """Identify specific risk factors in the code."""
        
        risk_factors = []
        
        if intent in [CodeIntent.MALICIOUS, CodeIntent.SUSPICIOUS]:
            risk_factors.append(f"Code classified as {intent.value}")
        
        if features.dynamic_code_execution:
            risk_factors.append(f"Dynamic code execution detected ({len(features.dynamic_code_execution)} instances)")
        
        if features.obfuscation_score > 0.7:
            risk_factors.append("High obfuscation score")
        
        if features.suspicious_strings:
            risk_factors.append(f"Suspicious strings detected ({len(features.suspicious_strings)} instances)")
        
        if features.string_entropy > 4.5:
            risk_factors.append("High string entropy (possible encryption/encoding)")
        
        if features.cyclomatic_complexity > 30:
            risk_factors.append("Excessive cyclomatic complexity")
        
        if features.nesting_depth > 10:
            risk_factors.append("Excessive nesting depth")
        
        if len(features.network_operations) > 10:
            risk_factors.append("Extensive network operations")
        
        return risk_factors
    
    async def _find_suspicious_patterns(self, content: str, language: str) -> List[Dict[str, Any]]:
        """Find suspicious patterns in the code."""
        
        suspicious_patterns = []
        
        for pattern_name, pattern_regex in self.suspicious_patterns.items():
            matches = list(re.finditer(pattern_regex, content, re.IGNORECASE | re.MULTILINE))
            
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                suspicious_patterns.append({
                    'pattern_name': pattern_name,
                    'match': match.group(),
                    'line_number': line_number,
                    'context': self._get_context(content, match.start(), match.end()),
                    'severity': self._get_pattern_severity(pattern_name),
                    'description': self._get_pattern_description(pattern_name)
                })
        
        return suspicious_patterns
    
    async def _analyze_function_purposes(self, content: str, language: str) -> Dict[str, str]:
        """Analyze and infer the purpose of functions."""
        
        function_purposes = {}
        
        # Extract function names and bodies (simplified)
        function_pattern = self._get_function_pattern(language)
        if not function_pattern:
            return function_purposes
        
        matches = re.finditer(function_pattern, content, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            function_name = match.group(1) if match.groups() else "unknown"
            function_body = match.group(0)
            
            # Infer purpose based on name and content
            purpose = self._infer_function_purpose(function_name, function_body)
            function_purposes[function_name] = purpose
        
        return function_purposes
    
    async def _analyze_data_flows(self, content: str, language: str) -> List[Dict[str, Any]]:
        """Analyze data flow patterns."""
        
        data_flows = []
        
        # Simple data flow analysis (would be more sophisticated in real implementation)
        # Look for variable assignments and usage
        
        if language == 'javascript':
            # Find variable declarations and assignments
            var_pattern = r'(?:var|let|const)\s+(\w+)\s*=\s*([^;]+);?'
            assignments = re.finditer(var_pattern, content)
            
            for assignment in assignments:
                var_name = assignment.group(1)
                value = assignment.group(2).strip()
                
                # Check if value comes from user input or external source
                is_external = any(source in value for source in [
                    'req.', 'request.', 'input', 'params', 'query',
                    'fetch(', 'XMLHttpRequest', 'localStorage', 'sessionStorage'
                ])
                
                if is_external:
                    data_flows.append({
                        'variable': var_name,
                        'source': 'external',
                        'value': value[:50] + '...' if len(value) > 50 else value,
                        'line': content[:assignment.start()].count('\n') + 1,
                        'risk_level': 'high' if any(risk in value for risk in ['eval', 'innerHTML']) else 'medium'
                    })
        
        return data_flows
    
    async def _analyze_control_flows(self, content: str, language: str) -> List[Dict[str, Any]]:
        """Analyze control flow patterns."""
        
        control_flows = []
        
        # Find conditional statements and loops
        control_patterns = {
            'javascript': [
                r'if\s*\([^)]+\)\s*{',
                r'for\s*\([^)]+\)\s*{',
                r'while\s*\([^)]+\)\s*{',
                r'switch\s*\([^)]+\)\s*{'
            ],
            'python': [
                r'if\s+[^:]+:',
                r'for\s+[^:]+:',
                r'while\s+[^:]+:',
                r'try\s*:'
            ]
        }
        
        patterns = control_patterns.get(language, [])
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                control_type = match.group().split()[0]  # Get first word (if, for, while, etc.)
                line_number = content[:match.start()].count('\n') + 1
                
                control_flows.append({
                    'type': control_type,
                    'line': line_number,
                    'condition': match.group(),
                    'complexity_contribution': 1
                })
        
        return control_flows
    
    def _generate_summary(self, intent: CodeIntent, features: CodeFeatures, 
                         security_score: float, risk_factors: List[str]) -> str:
        """Generate natural language summary of the analysis."""
        
        # Intent description
        intent_descriptions = {
            CodeIntent.BENIGN: "appears to be legitimate code",
            CodeIntent.SUSPICIOUS: "contains suspicious patterns that warrant investigation",
            CodeIntent.MALICIOUS: "shows strong indicators of malicious intent",
            CodeIntent.OBFUSCATED: "is heavily obfuscated, making analysis difficult",
            CodeIntent.ENCRYPTED: "contains encrypted or encoded content",
            CodeIntent.UNKNOWN: "has unclear intent and requires manual review"
        }
        
        summary = f"This code {intent_descriptions.get(intent, 'requires analysis')}. "
        
        # Security score interpretation
        if security_score >= 80:
            summary += "The security posture is strong with minimal risk indicators. "
        elif security_score >= 60:
            summary += "The security posture is acceptable but has some areas of concern. "
        elif security_score >= 40:
            summary += "The security posture is weak with multiple risk factors identified. "
        else:
            summary += "The security posture is poor with significant security risks. "
        
        # Complexity assessment
        if features.cyclomatic_complexity > 20:
            summary += "The code complexity is high, which may impact maintainability and security auditing. "
        
        # Key concerns
        if risk_factors:
            summary += f"Key concerns include: {', '.join(risk_factors[:3])}."
            if len(risk_factors) > 3:
                summary += f" ({len(risk_factors) - 3} additional concerns identified)"
        
        return summary
    
    def _generate_recommendations(self, intent: CodeIntent, features: CodeFeatures,
                                risk_factors: List[str], suspicious_patterns: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations."""
        
        recommendations = []
        
        # Intent-based recommendations
        if intent == CodeIntent.MALICIOUS:
            recommendations.extend([
                "Quarantine this file immediately",
                "Conduct forensic analysis to determine impact",
                "Review access logs for unauthorized activities",
                "Scan for additional compromised files"
            ])
        
        elif intent == CodeIntent.SUSPICIOUS:
            recommendations.extend([
                "Conduct manual code review",
                "Test in isolated environment",
                "Implement additional monitoring",
                "Consider code refactoring for clarity"
            ])
        
        elif intent == CodeIntent.OBFUSCATED:
            recommendations.extend([
                "Deobfuscate code for proper analysis",
                "Verify code origin and integrity",
                "Implement source code verification",
                "Consider replacing with transparent alternatives"
            ])
        
        # Feature-based recommendations
        if features.dynamic_code_execution:
            recommendations.append("Eliminate or secure dynamic code execution")
        
        if features.obfuscation_score > 0.5:
            recommendations.append("Improve code readability and transparency")
        
        if features.cyclomatic_complexity > 20:
            recommendations.append("Refactor complex functions to improve maintainability")
        
        if features.suspicious_strings:
            recommendations.append("Review and validate suspicious string patterns")
        
        # Pattern-based recommendations
        critical_patterns = [p for p in suspicious_patterns if p.get('severity') == 'critical']
        if critical_patterns:
            recommendations.append("Address critical security patterns immediately")
        
        # General security recommendations
        recommendations.extend([
            "Implement comprehensive input validation",
            "Add security-focused code comments",
            "Include in regular security audits",
            "Monitor runtime behavior"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    # Helper methods
    def _count_comment_lines(self, lines: List[str], language: str) -> int:
        """Count comment lines based on language."""
        comment_patterns = {
            'javascript': [r'^\s*//', r'^\s*/\*', r'\*/\s*$'],
            'python': [r'^\s*#', r'^\s*"""', r'^\s*\'\'\''],
            'java': [r'^\s*//', r'^\s*/\*', r'\*/\s*$'],
            'php': [r'^\s*//', r'^\s*#', r'^\s*/\*'],
            'shell': [r'^\s*#']
        }
        
        patterns = comment_patterns.get(language, [r'^\s*//'])
        comment_count = 0
        
        for line in lines:
            if any(re.search(pattern, line) for pattern in patterns):
                comment_count += 1
        
        return comment_count
    
    def _count_functions(self, content: str, language: str) -> int:
        """Count functions in the code."""
        function_patterns = {
            'javascript': r'function\s+\w+\s*\(|=>\s*{|\w+\s*:\s*function',
            'python': r'def\s+\w+\s*\(',
            'java': r'(?:public|private|protected)?\s*\w+\s+\w+\s*\(',
            'php': r'function\s+\w+\s*\(',
            'go': r'func\s+\w+\s*\(',
            'rust': r'fn\s+\w+\s*\('
        }
        
        pattern = function_patterns.get(language, r'function\s+\w+\s*\(')
        return len(re.findall(pattern, content, re.IGNORECASE))
    
    def _count_classes(self, content: str, language: str) -> int:
        """Count classes in the code."""
        class_patterns = {
            'javascript': r'class\s+\w+',
            'python': r'class\s+\w+\s*[\(:]',
            'java': r'(?:public|private)?\s*class\s+\w+',
            'php': r'class\s+\w+',
            'go': r'type\s+\w+\s+struct',
            'rust': r'struct\s+\w+'
        }
        
        pattern = class_patterns.get(language, r'class\s+\w+')
        return len(re.findall(pattern, content, re.IGNORECASE))
    
    def _count_variables(self, content: str, language: str) -> int:
        """Count variable declarations."""
        var_patterns = {
            'javascript': r'(?:var|let|const)\s+\w+',
            'python': r'^\s*\w+\s*=',
            'java': r'(?:int|String|boolean|double|float)\s+\w+',
            'php': r'\$\w+',
            'go': r'var\s+\w+|:\s*=',
            'rust': r'let\s+\w+'
        }
        
        pattern = var_patterns.get(language, r'(?:var|let|const)\s+\w+')
        return len(re.findall(pattern, content, re.IGNORECASE | re.MULTILINE))
    
    def _count_imports(self, content: str, language: str) -> int:
        """Count import statements."""
        import_patterns = {
            'javascript': r'import\s+.*from|require\s*\(',
            'python': r'(?:import\s+\w+|from\s+\w+\s+import)',
            'java': r'import\s+[\w.]+;',
            'php': r'(?:include|require)(?:_once)?\s*\(',
            'go': r'import\s+',
            'rust': r'use\s+[\w::]+'
        }
        
        pattern = import_patterns.get(language, r'import\s+')
        return len(re.findall(pattern, content, re.IGNORECASE))
    
    def _calculate_cyclomatic_complexity(self, content: str, language: str) -> int:
        """Calculate cyclomatic complexity."""
        # Simplified complexity calculation
        complexity_keywords = {
            'javascript': ['if', 'else', 'while', 'for', 'switch', 'case', 'catch', '&&', '||', '?'],
            'python': ['if', 'elif', 'else', 'while', 'for', 'except', 'and', 'or'],
            'java': ['if', 'else', 'while', 'for', 'switch', 'case', 'catch', '&&', '||', '?']
        }
        
        keywords = complexity_keywords.get(language, ['if', 'else', 'while', 'for'])
        
        complexity = 1  # Base complexity
        for keyword in keywords:
            complexity += len(re.findall(rf'\b{keyword}\b', content, re.IGNORECASE))
        
        return complexity
    
    def _calculate_nesting_depth(self, content: str, language: str) -> int:
        """Calculate maximum nesting depth."""
        # Simplified nesting calculation using braces/indentation
        if language == 'python':
            # Use indentation for Python
            lines = content.split('\n')
            max_depth = 0
            for line in lines:
                if line.strip():
                    depth = (len(line) - len(line.lstrip())) // 4  # Assuming 4-space indentation
                    max_depth = max(max_depth, depth)
            return max_depth
        else:
            # Use braces for other languages
            depth = 0
            max_depth = 0
            for char in content:
                if char == '{':
                    depth += 1
                    max_depth = max(max_depth, depth)
                elif char == '}':
                    depth = max(0, depth - 1)
            return max_depth
    
    def _extract_api_calls(self, content: str, language: str) -> List[str]:
        """Extract API calls from the code."""
        api_patterns = {
            'javascript': r'(\w+(?:\.\w+)*)\s*\(',
            'python': r'(\w+(?:\.\w+)*)\s*\(',
            'java': r'(\w+(?:\.\w+)*)\s*\('
        }
        
        pattern = api_patterns.get(language, r'(\w+(?:\.\w+)*)\s*\(')
        matches = re.findall(pattern, content)
        
        # Filter out common keywords and return unique API calls
        keywords = {'if', 'for', 'while', 'function', 'class', 'return', 'var', 'let', 'const'}
        api_calls = [match for match in matches if match.lower() not in keywords]
        
        return list(set(api_calls))[:50]  # Limit to 50 unique calls
    
    def _extract_external_references(self, content: str, language: str) -> List[str]:
        """Extract external references (URLs, domains, etc.)."""
        url_pattern = r'https?://[^\s\'"`<>]+'
        domain_pattern = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        urls = re.findall(url_pattern, content)
        domains = re.findall(domain_pattern, content)
        
        # Filter out common false positives
        filtered_domains = [
            domain for domain in domains
            if not any(common in domain for common in ['example.com', 'localhost', '127.0.0.1'])
        ]
        
        return list(set(urls + filtered_domains))
    
    def _find_patterns(self, content: str, patterns: List[str]) -> List[str]:
        """Find matches for given patterns."""
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, content, re.IGNORECASE)
            matches.extend(found)
        return matches
    
    def _calculate_string_entropy(self, content: str) -> float:
        """Calculate entropy of strings in the code."""
        import math
        from collections import Counter
        
        # Extract string literals
        string_pattern = r'[\'"`]([^\'"`]*)[\'"`]'
        strings = re.findall(string_pattern, content)
        
        if not strings:
            return 0.0
        
        # Calculate average entropy
        total_entropy = 0.0
        for string in strings:
            if len(string) > 0:
                counter = Counter(string)
                entropy = -sum((count/len(string)) * math.log2(count/len(string)) 
                             for count in counter.values())
                total_entropy += entropy
        
        return total_entropy / len(strings) if strings else 0.0
    
    def _find_suspicious_strings(self, content: str) -> List[str]:
        """Find suspicious string patterns."""
        suspicious = []
        
        for pattern_name, pattern in self.suspicious_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            suspicious.extend(matches)
        
        return list(set(suspicious))[:20]  # Limit results
    
    def _find_base64_strings(self, content: str) -> List[str]:
        """Find potential base64 encoded strings."""
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, content)
        
        # Filter out common false positives
        return [match for match in matches if len(match) > 20][:10]
    
    def _find_hex_strings(self, content: str) -> List[str]:
        """Find hexadecimal strings."""
        hex_pattern = r'(?:0x)?[0-9a-fA-F]{16,}'
        matches = re.findall(hex_pattern, content)
        return matches[:10]
    
    def _calculate_obfuscation_score(self, content: str, language: str) -> float:
        """Calculate obfuscation score."""
        score = 0.0
        
        # Check for various obfuscation indicators
        for indicator_name, pattern in self.obfuscation_indicators.items():
            matches = len(re.findall(pattern, content))
            
            if indicator_name == 'variable_names':
                # Low ratio of readable variable names
                total_vars = max(1, matches)
                readable_vars = len(re.findall(r'[a-zA-Z_$][a-zA-Z0-9_$]{2,}', content))
                if readable_vars / total_vars < 0.3:
                    score += 0.2
            
            elif indicator_name == 'string_concatenation' and matches > 10:
                score += 0.2
            
            elif indicator_name == 'char_codes' and matches > 0:
                score += 0.3
            
            elif indicator_name in ['unicode_escape', 'hex_escape'] and matches > 5:
                score += 0.2
            
            elif indicator_name == 'array_access' and matches > 20:
                score += 0.1
        
        return min(1.0, score)
    
    def _is_minified(self, content: str) -> bool:
        """Check if code appears to be minified."""
        lines = content.split('\n')
        if not lines:
            return False
        
        # Check average line length and lack of formatting
        avg_line_length = sum(len(line) for line in lines) / len(lines)
        long_lines = sum(1 for line in lines if len(line) > 200)
        
        return avg_line_length > 100 and long_lines > len(lines) * 0.3
    
    def _is_packed(self, content: str) -> bool:
        """Check if code appears to be packed."""
        packed_indicators = [
            r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)',  # Dean Edwards packer
            r'eval\s*\(\s*unescape\s*\(',
            r'eval\s*\(\s*decodeURIComponent\s*\(',
            r'String\.fromCharCode\s*\(\s*[0-9,\s]+\s*\)'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in packed_indicators)
    
    def _get_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """Get context around a match."""
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        return content[context_start:context_end]
    
    def _get_pattern_severity(self, pattern_name: str) -> str:
        """Get severity level for a pattern."""
        severity_map = {
            'base64_like': 'medium',
            'hex_encoded': 'medium',
            'url_suspicious': 'high',
            'shell_commands': 'high',
            'sql_injection': 'critical',
            'xss_patterns': 'critical',
            'path_traversal': 'high',
            'command_injection': 'critical'
        }
        return severity_map.get(pattern_name, 'medium')
    
    def _get_pattern_description(self, pattern_name: str) -> str:
        """Get description for a pattern."""
        descriptions = {
            'base64_like': 'Potential base64 encoded data',
            'hex_encoded': 'Hexadecimal encoded data',
            'url_suspicious': 'Suspicious URL or domain',
            'shell_commands': 'Shell command execution',
            'sql_injection': 'Potential SQL injection pattern',
            'xss_patterns': 'Cross-site scripting (XSS) pattern',
            'path_traversal': 'Path traversal attack pattern',
            'command_injection': 'Command injection pattern'
        }
        return descriptions.get(pattern_name, 'Suspicious pattern detected')
    
    def _get_function_pattern(self, language: str) -> Optional[str]:
        """Get regex pattern for extracting functions."""
        patterns = {
            'javascript': r'function\s+(\w+)\s*\([^)]*\)\s*{([^{}]*(?:{[^{}]*}[^{}]*)*)}\s*',
            'python': r'def\s+(\w+)\s*\([^)]*\):[^\n]*\n((?:\s+.*\n)*)',
            'java': r'(?:public|private|protected)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*{([^{}]*(?:{[^{}]*}[^{}]*)*)}'
        }
        return patterns.get(language)
    
    def _infer_function_purpose(self, function_name: str, function_body: str) -> str:
        """Infer the purpose of a function based on its name and body."""
        
        # Check function name patterns
        for purpose, patterns in self.function_purpose_patterns.items():
            if any(re.search(pattern, function_name, re.IGNORECASE) for pattern in patterns):
                return purpose
        
        # Check function body for purpose indicators
        for purpose, patterns in self.function_purpose_patterns.items():
            if any(re.search(pattern, function_body, re.IGNORECASE) for pattern in patterns):
                return purpose
        
        # Default categorization based on common patterns
        if any(keyword in function_body.lower() for keyword in ['return', 'calculate', 'compute']):
            return 'computation'
        elif any(keyword in function_body.lower() for keyword in ['log', 'console', 'print']):
            return 'logging'
        elif any(keyword in function_body.lower() for keyword in ['event', 'click', 'handler']):
            return 'event_handling'
        else:
            return 'general_purpose'
    
    def _update_stats(self, result: CodeUnderstandingResult):
        """Update engine statistics."""
        self.stats['files_analyzed'] += 1
        self.stats['total_lines_processed'] += result.features.total_lines
        
        if result.intent == CodeIntent.SUSPICIOUS:
            self.stats['suspicious_files_detected'] += 1
        elif result.intent == CodeIntent.MALICIOUS:
            self.stats['malicious_files_detected'] += 1
        elif result.intent == CodeIntent.OBFUSCATED:
            self.stats['obfuscated_files_detected'] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return dict(self.stats)
