"""
Advanced Pattern Engine for Security Detection

Implements sophisticated pattern matching with context awareness and machine learning.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class PatternType(Enum):
    """Types of security patterns."""
    REGEX = "regex"
    SEMANTIC = "semantic"
    STRUCTURAL = "structural"
    BEHAVIORAL = "behavioral"
    CONTEXTUAL = "contextual"

class Severity(Enum):
    """Pattern severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class SecurityPattern:
    """Represents a security detection pattern."""
    id: str
    name: str
    description: str
    pattern_type: PatternType
    severity: Severity
    confidence: float
    
    # Pattern definitions
    regex_patterns: List[str] = field(default_factory=list)
    semantic_rules: Dict[str, Any] = field(default_factory=dict)
    context_requirements: List[str] = field(default_factory=list)
    exclusion_patterns: List[str] = field(default_factory=list)
    
    # Framework and language specificity
    frameworks: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=list)
    
    # Metadata
    cwe_ids: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    # Detection logic
    requires_data_flow: bool = False
    requires_function_context: bool = False
    max_false_positive_rate: float = 0.1

@dataclass
class PatternMatch:
    """Represents a pattern match result."""
    pattern_id: str
    pattern_name: str
    severity: str
    confidence: float
    line_number: int
    column: int
    matched_text: str
    context: str
    file_path: str
    
    # Additional context
    function_name: Optional[str] = None
    data_flow_path: List[str] = field(default_factory=list)
    related_matches: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class PatternEngine:
    """Advanced pattern engine for security detection."""
    
    def __init__(self):
        self.patterns: Dict[str, SecurityPattern] = {}
        self.pattern_cache: Dict[str, List[re.Pattern]] = {}
        self.context_cache: Dict[str, Any] = {}
        
        # Load built-in patterns
        self._load_builtin_patterns()
    
    def _load_builtin_patterns(self):
        """Load built-in security patterns."""
        
        # XSS Patterns
        self.add_pattern(SecurityPattern(
            id="xss_innerHTML",
            name="XSS via innerHTML",
            description="Potential XSS vulnerability through innerHTML assignment",
            pattern_type=PatternType.REGEX,
            severity=Severity.HIGH,
            confidence=0.8,
            regex_patterns=[
                r'\.innerHTML\s*=\s*.*\$\{.*\}',
                r'\.innerHTML\s*=\s*.*\+.*',
                r'\.innerHTML\s*=\s*[\'"`].*[\'"`]\s*\+',
            ],
            context_requirements=['user_input'],
            frameworks=['react', 'nextjs', 'vite'],
            languages=['javascript', 'typescript'],
            cwe_ids=['CWE-79'],
            owasp_categories=['A03:2021-Injection']
        ))
        
        self.add_pattern(SecurityPattern(
            id="xss_dangerously_set_inner_html",
            name="XSS via dangerouslySetInnerHTML",
            description="Potential XSS through React's dangerouslySetInnerHTML",
            pattern_type=PatternType.CONTEXTUAL,
            severity=Severity.HIGH,
            confidence=0.9,
            regex_patterns=[
                r'dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*.*\}',
            ],
            context_requirements=['jsx_context', 'user_input'],
            frameworks=['react', 'nextjs'],
            languages=['javascript', 'typescript'],
            cwe_ids=['CWE-79'],
            owasp_categories=['A03:2021-Injection']
        ))
        
        # SQL Injection Patterns
        self.add_pattern(SecurityPattern(
            id="sql_injection_string_concat",
            name="SQL Injection via String Concatenation",
            description="SQL injection through string concatenation with user input",
            pattern_type=PatternType.CONTEXTUAL,
            severity=Severity.CRITICAL,
            confidence=0.9,
            regex_patterns=[
                r'(query|execute|exec)\s*\(\s*[\'"`].*[\'"`]\s*\+',
                r'(query|execute|exec)\s*\(\s*.*\$\{.*\}',
                r'(SELECT|INSERT|UPDATE|DELETE).*\$\{.*\}',
            ],
            context_requirements=['database_context', 'user_input'],
            frameworks=['nextjs', 'react', 'vite'],
            languages=['javascript', 'typescript'],
            cwe_ids=['CWE-89'],
            owasp_categories=['A03:2021-Injection']
        ))
        
        # Command Injection Patterns
        self.add_pattern(SecurityPattern(
            id="command_injection_exec",
            name="Command Injection via exec",
            description="Command injection through exec functions with user input",
            pattern_type=PatternType.CONTEXTUAL,
            severity=Severity.CRITICAL,
            confidence=0.85,
            regex_patterns=[
                r'(exec|spawn|execSync|spawnSync)\s*\([\'"`].*\$\{.*\}',
                r'child_process\.(exec|spawn)\s*\([\'"`].*\+',
                r'require\([\'"]child_process[\'\"]\)\.(exec|spawn)',
            ],
            context_requirements=['user_input'],
            frameworks=['nextjs'],
            languages=['javascript', 'typescript'],
            cwe_ids=['CWE-78'],
            owasp_categories=['A03:2021-Injection']
        ))
        
        # Path Traversal Patterns
        self.add_pattern(SecurityPattern(
            id="path_traversal_fs",
            name="Path Traversal via File System Operations",
            description="Path traversal through file system operations with user input",
            pattern_type=PatternType.CONTEXTUAL,
            severity=Severity.HIGH,
            confidence=0.8,
            regex_patterns=[
                r'fs\.(readFile|writeFile|createReadStream)\s*\([\'"`]?.*\$\{.*\}',
                r'fs\.(readFile|writeFile|createReadStream)\s*\([\'"`]?.*\+',
                r'require\s*\([\'"`]?.*\$\{.*\}',
            ],
            context_requirements=['user_input'],
            frameworks=['nextjs'],
            languages=['javascript', 'typescript'],
            cwe_ids=['CWE-22'],
            owasp_categories=['A01:2021-Broken Access Control']
        ))
        
        # Hardcoded Secrets Patterns
        self.add_pattern(SecurityPattern(
            id="hardcoded_api_key",
            name="Hardcoded API Key",
            description="Hardcoded API key or secret in source code",
            pattern_type=PatternType.REGEX,
            severity=Severity.CRITICAL,
            confidence=0.9,
            regex_patterns=[
                r'sk-[a-zA-Z0-9]{48}',  # OpenAI keys
                r'sk-ant-[a-zA-Z0-9\-_]{95,}',  # Anthropic keys
                r'AKIA[A-Z0-9]{16}',  # AWS keys
                r'ghp_[a-zA-Z0-9]{36}',  # GitHub tokens
                r'AIza[0-9A-Za-z_\-]{35}',  # Google API keys
            ],
            exclusion_patterns=[
                r'(example|sample|test|demo|placeholder)',
                r'YOUR_API_KEY',
                r'sk-[x]{48}',
            ],
            frameworks=['nextjs', 'react', 'vite'],
            languages=['javascript', 'typescript'],
            cwe_ids=['CWE-798'],
            owasp_categories=['A07:2021-Identification and Authentication Failures']
        ))
        
        # Crypto Issues
        self.add_pattern(SecurityPattern(
            id="weak_random",
            name="Weak Random Number Generation",
            description="Use of cryptographically weak random number generation",
            pattern_type=PatternType.REGEX,
            severity=Severity.MEDIUM,
            confidence=0.7,
            regex_patterns=[
                r'Math\.random\(\)',
                r'crypto\.pseudoRandomBytes',
            ],
            context_requirements=['crypto_context'],
            frameworks=['nextjs', 'react', 'vite'],
            languages=['javascript', 'typescript'],
            cwe_ids=['CWE-338'],
            owasp_categories=['A02:2021-Cryptographic Failures']
        ))
        
        # Next.js Specific Patterns
        self.add_pattern(SecurityPattern(
            id="nextjs_ssrf_image",
            name="Next.js Image SSRF",
            description="Potential SSRF through Next.js Image component",
            pattern_type=PatternType.CONTEXTUAL,
            severity=Severity.HIGH,
            confidence=0.8,
            regex_patterns=[
                r'<Image\s+.*src\s*=\s*\{.*\$\{.*\}.*\}',
                r'<Image\s+.*src\s*=\s*\{.*req\.(query|body|params)',
            ],
            context_requirements=['nextjs_context', 'user_input'],
            frameworks=['nextjs'],
            languages=['javascript', 'typescript'],
            file_patterns=['*.jsx', '*.tsx'],
            cwe_ids=['CWE-918'],
            owasp_categories=['A10:2021-Server-Side Request Forgery']
        ))
        
        # React Specific Patterns
        self.add_pattern(SecurityPattern(
            id="react_ref_xss",
            name="React Ref XSS",
            description="Potential XSS through React ref manipulation",
            pattern_type=PatternType.CONTEXTUAL,
            severity=Severity.MEDIUM,
            confidence=0.7,
            regex_patterns=[
                r'useRef\(\)\.current\.(innerHTML|outerHTML)',
                r'ref\.current\.(innerHTML|outerHTML)\s*=',
            ],
            context_requirements=['react_context', 'user_input'],
            frameworks=['react', 'nextjs'],
            languages=['javascript', 'typescript'],
            cwe_ids=['CWE-79'],
            owasp_categories=['A03:2021-Injection']
        ))
    
    def add_pattern(self, pattern: SecurityPattern):
        """Add a new security pattern."""
        self.patterns[pattern.id] = pattern
        
        # Pre-compile regex patterns for performance
        if pattern.regex_patterns:
            compiled_patterns = []
            for regex_pattern in pattern.regex_patterns:
                try:
                    compiled_patterns.append(re.compile(regex_pattern, re.IGNORECASE | re.MULTILINE))
                except re.error as e:
                    logger.warning(f"Invalid regex pattern in {pattern.id}: {regex_pattern} - {e}")
            
            self.pattern_cache[pattern.id] = compiled_patterns
    
    def analyze_file(self, file_path: Path, content: str, context: Dict[str, Any] = None) -> List[PatternMatch]:
        """Analyze a file for security patterns."""
        matches = []
        file_context = context or {}
        
        # Determine file context
        file_context.update(self._analyze_file_context(file_path, content))
        
        # Test each pattern
        for pattern_id, pattern in self.patterns.items():
            if not self._pattern_applies_to_file(pattern, file_path, file_context):
                continue
            
            pattern_matches = self._test_pattern(pattern, content, file_path, file_context)
            matches.extend(pattern_matches)
        
        # Post-process matches
        matches = self._post_process_matches(matches, content, file_context)
        
        return matches
    
    def _analyze_file_context(self, file_path: Path, content: str) -> Dict[str, Any]:
        """Analyze file to determine context information."""
        context = {}
        
        # File type detection
        suffix = file_path.suffix.lower()
        context['file_extension'] = suffix
        context['is_javascript'] = suffix in ['.js', '.jsx', '.mjs']
        context['is_typescript'] = suffix in ['.ts', '.tsx']
        context['is_jsx'] = suffix in ['.jsx', '.tsx']
        
        # Framework detection
        context['is_nextjs'] = self._detect_nextjs_context(content)
        context['is_react'] = self._detect_react_context(content)
        context['is_vite'] = self._detect_vite_context(content)
        
        # Content analysis
        context['has_user_input'] = self._detect_user_input_sources(content)
        context['has_database_operations'] = self._detect_database_operations(content)
        context['has_file_operations'] = self._detect_file_operations(content)
        context['has_crypto_operations'] = self._detect_crypto_operations(content)
        context['jsx_context'] = self._detect_jsx_usage(content)
        
        # API route detection
        context['is_api_route'] = 'api/' in str(file_path) or '/api/' in str(file_path)
        context['is_middleware'] = file_path.name.startswith('middleware')
        context['is_config'] = any(config_name in file_path.name for config_name in ['config', 'next.config', 'vite.config'])
        
        return context
    
    def _detect_nextjs_context(self, content: str) -> bool:
        """Detect Next.js specific context."""
        nextjs_indicators = [
            'next/', 'getServerSideProps', 'getStaticProps', 'getStaticPaths',
            'useRouter', 'next/router', 'next/image', 'next/head',
            'export default function', 'NextApiRequest', 'NextApiResponse'
        ]
        return any(indicator in content for indicator in nextjs_indicators)
    
    def _detect_react_context(self, content: str) -> bool:
        """Detect React specific context."""
        react_indicators = [
            'react', 'useState', 'useEffect', 'useContext', 'useRef',
            'React.', 'ReactDOM', 'jsx', 'createElement'
        ]
        return any(indicator in content for indicator in react_indicators)
    
    def _detect_vite_context(self, content: str) -> bool:
        """Detect Vite specific context."""
        vite_indicators = [
            'import.meta.env', 'import.meta.hot', 'vite/', '@vite/'
        ]
        return any(indicator in content for indicator in vite_indicators)
    
    def _detect_user_input_sources(self, content: str) -> bool:
        """Detect user input sources in content."""
        user_input_patterns = [
            r'req\.(body|query|params|headers)',
            r'request\.(body|query|params|headers)',
            r'window\.location',
            r'document\.location',
            r'location\.(search|hash)',
            r'process\.argv',
            r'process\.env',
            r'router\.(query|params)',
            r'searchParams\.',
            r'formData\.',
            r'event\.target\.value'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in user_input_patterns)
    
    def _detect_database_operations(self, content: str) -> bool:
        """Detect database operations."""
        db_patterns = [
            r'(query|execute|exec|prepare)\s*\(',
            r'(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)',
            r'(mongoose|sequelize|prisma|knex)',
            r'db\.',
            r'connection\.',
            r'\.find\(',
            r'\.create\(',
            r'\.update\(',
            r'\.delete\('
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in db_patterns)
    
    def _detect_file_operations(self, content: str) -> bool:
        """Detect file system operations."""
        file_patterns = [
            r'fs\.(readFile|writeFile|createReadStream|createWriteStream)',
            r'require\s*\([\'"]fs[\'\"]\)',
            r'import.*from\s+[\'"]fs[\'"]',
            r'path\.(join|resolve)',
            r'__dirname',
            r'__filename'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in file_patterns)
    
    def _detect_crypto_operations(self, content: str) -> bool:
        """Detect cryptographic operations."""
        crypto_patterns = [
            r'crypto\.',
            r'bcrypt',
            r'jwt\.',
            r'encrypt',
            r'decrypt',
            r'hash',
            r'sign',
            r'verify',
            r'Math\.random',
            r'random'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in crypto_patterns)
    
    def _detect_jsx_usage(self, content: str) -> bool:
        """Detect JSX usage in content."""
        jsx_patterns = [
            r'<[A-Z][a-zA-Z0-9]*',  # JSX components
            r'<[a-z]+\s+[^>]*>',    # JSX elements with attributes
            r'\{.*\}',              # JSX expressions
            r'dangerouslySetInnerHTML'
        ]
        
        return any(re.search(pattern, content) for pattern in jsx_patterns)
    
    def _pattern_applies_to_file(self, pattern: SecurityPattern, file_path: Path, context: Dict[str, Any]) -> bool:
        """Check if pattern applies to the given file."""
        
        # Check file extension
        if pattern.languages:
            file_ext = file_path.suffix.lower()
            lang_extensions = {
                'javascript': ['.js', '.jsx', '.mjs'],
                'typescript': ['.ts', '.tsx'],
                'python': ['.py'],
                'json': ['.json'],
                'yaml': ['.yaml', '.yml']
            }
            
            applicable_extensions = []
            for lang in pattern.languages:
                applicable_extensions.extend(lang_extensions.get(lang, []))
            
            if file_ext not in applicable_extensions:
                return False
        
        # Check framework compatibility
        if pattern.frameworks:
            framework_match = False
            for framework in pattern.frameworks:
                if context.get(f'is_{framework}', False):
                    framework_match = True
                    break
            
            if not framework_match:
                return False
        
        # Check file pattern matching
        if pattern.file_patterns:
            file_match = False
            for file_pattern in pattern.file_patterns:
                if file_path.match(file_pattern):
                    file_match = True
                    break
            
            if not file_match:
                return False
        
        return True
    
    def _test_pattern(self, pattern: SecurityPattern, content: str, file_path: Path, context: Dict[str, Any]) -> List[PatternMatch]:
        """Test a specific pattern against content."""
        matches = []
        
        if pattern.pattern_type == PatternType.REGEX:
            matches.extend(self._test_regex_pattern(pattern, content, file_path, context))
        elif pattern.pattern_type == PatternType.CONTEXTUAL:
            matches.extend(self._test_contextual_pattern(pattern, content, file_path, context))
        elif pattern.pattern_type == PatternType.SEMANTIC:
            matches.extend(self._test_semantic_pattern(pattern, content, file_path, context))
        
        return matches
    
    def _test_regex_pattern(self, pattern: SecurityPattern, content: str, file_path: Path, context: Dict[str, Any]) -> List[PatternMatch]:
        """Test regex-based pattern."""
        matches = []
        
        if pattern.id not in self.pattern_cache:
            return matches
        
        lines = content.split('\n')
        compiled_patterns = self.pattern_cache[pattern.id]
        
        for compiled_pattern in compiled_patterns:
            for line_num, line in enumerate(lines, 1):
                for match in compiled_pattern.finditer(line):
                    # Check exclusion patterns
                    if self._matches_exclusion_pattern(pattern, line):
                        continue
                    
                    # Check context requirements
                    if not self._meets_context_requirements(pattern, context, line, lines, line_num):
                        continue
                    
                    matches.append(PatternMatch(
                        pattern_id=pattern.id,
                        pattern_name=pattern.name,
                        severity=pattern.severity.value,
                        confidence=pattern.confidence,
                        line_number=line_num,
                        column=match.start(),
                        matched_text=match.group(),
                        context=self._get_context_lines(lines, line_num),
                        file_path=str(file_path),
                        metadata={
                            'pattern_type': pattern.pattern_type.value,
                            'cwe_ids': pattern.cwe_ids,
                            'owasp_categories': pattern.owasp_categories
                        }
                    ))
        
        return matches
    
    def _test_contextual_pattern(self, pattern: SecurityPattern, content: str, file_path: Path, context: Dict[str, Any]) -> List[PatternMatch]:
        """Test contextual pattern that requires specific context."""
        # First check if context requirements are met globally
        if not self._meets_global_context_requirements(pattern, context):
            return []
        
        # Then perform regex matching with enhanced context checking
        return self._test_regex_pattern(pattern, content, file_path, context)
    
    def _test_semantic_pattern(self, pattern: SecurityPattern, content: str, file_path: Path, context: Dict[str, Any]) -> List[PatternMatch]:
        """Test semantic pattern (placeholder for future ML-based detection)."""
        # TODO: Implement semantic analysis using NLP/ML models
        return []
    
    def _matches_exclusion_pattern(self, pattern: SecurityPattern, line: str) -> bool:
        """Check if line matches any exclusion patterns."""
        for exclusion_pattern in pattern.exclusion_patterns:
            if re.search(exclusion_pattern, line, re.IGNORECASE):
                return True
        return False
    
    def _meets_context_requirements(self, pattern: SecurityPattern, context: Dict[str, Any], line: str, lines: List[str], line_num: int) -> bool:
        """Check if context requirements are met for this specific line."""
        for requirement in pattern.context_requirements:
            if requirement == 'user_input':
                # Check if line contains user input or if user input is nearby
                if not (self._line_contains_user_input(line) or 
                       self._nearby_lines_contain_user_input(lines, line_num)):
                    return False
            
            elif requirement == 'jsx_context':
                if not context.get('jsx_context', False):
                    return False
            
            elif requirement == 'database_context':
                if not context.get('has_database_operations', False):
                    return False
            
            elif requirement == 'nextjs_context':
                if not context.get('is_nextjs', False):
                    return False
            
            elif requirement == 'react_context':
                if not context.get('is_react', False):
                    return False
            
            elif requirement == 'crypto_context':
                if not context.get('has_crypto_operations', False):
                    return False
        
        return True
    
    def _meets_global_context_requirements(self, pattern: SecurityPattern, context: Dict[str, Any]) -> bool:
        """Check if global context requirements are met."""
        for requirement in pattern.context_requirements:
            if requirement == 'user_input':
                if not context.get('has_user_input', False):
                    return False
            elif requirement == 'jsx_context':
                if not context.get('jsx_context', False):
                    return False
            elif requirement == 'database_context':
                if not context.get('has_database_operations', False):
                    return False
            # Add other global context checks as needed
        
        return True
    
    def _line_contains_user_input(self, line: str) -> bool:
        """Check if a specific line contains user input."""
        user_input_patterns = [
            r'req\.(body|query|params|headers)',
            r'request\.(body|query|params|headers)',
            r'router\.(query|params)',
            r'searchParams\.',
            r'formData\.',
            r'event\.target\.value'
        ]
        
        return any(re.search(pattern, line, re.IGNORECASE) for pattern in user_input_patterns)
    
    def _nearby_lines_contain_user_input(self, lines: List[str], line_num: int, window: int = 5) -> bool:
        """Check if nearby lines contain user input."""
        start = max(0, line_num - window - 1)
        end = min(len(lines), line_num + window)
        
        for i in range(start, end):
            if self._line_contains_user_input(lines[i]):
                return True
        
        return False
    
    def _get_context_lines(self, lines: List[str], line_num: int, context_size: int = 2) -> str:
        """Get context lines around the match."""
        start = max(0, line_num - context_size - 1)
        end = min(len(lines), line_num + context_size)
        
        context_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            context_lines.append(f"{prefix}{lines[i]}")
        
        return '\n'.join(context_lines)
    
    def _post_process_matches(self, matches: List[PatternMatch], content: str, context: Dict[str, Any]) -> List[PatternMatch]:
        """Post-process matches to reduce false positives and enhance results."""
        processed_matches = []
        
        for match in matches:
            # Calculate enhanced confidence based on context
            enhanced_confidence = self._calculate_enhanced_confidence(match, content, context)
            match.confidence = enhanced_confidence
            
            # Filter out low-confidence matches
            if enhanced_confidence < 0.3:
                continue
            
            # Add function context if available
            match.function_name = self._extract_function_context(content, match.line_number)
            
            processed_matches.append(match)
        
        # Remove duplicate matches
        processed_matches = self._deduplicate_matches(processed_matches)
        
        return processed_matches
    
    def _calculate_enhanced_confidence(self, match: PatternMatch, content: str, context: Dict[str, Any]) -> float:
        """Calculate enhanced confidence based on additional factors."""
        base_confidence = match.confidence
        
        # Adjust confidence based on context
        confidence_adjustments = 0.0
        
        # Higher confidence if in API routes
        if context.get('is_api_route', False):
            confidence_adjustments += 0.1
        
        # Higher confidence if user input is definitely present
        if context.get('has_user_input', False):
            confidence_adjustments += 0.1
        
        # Lower confidence if in test files
        if 'test' in match.file_path.lower() or 'spec' in match.file_path.lower():
            confidence_adjustments -= 0.2
        
        # Lower confidence if in comments
        lines = content.split('\n')
        if match.line_number <= len(lines):
            line = lines[match.line_number - 1]
            if line.strip().startswith('//') or line.strip().startswith('/*'):
                confidence_adjustments -= 0.3
        
        return max(0.0, min(1.0, base_confidence + confidence_adjustments))
    
    def _extract_function_context(self, content: str, line_number: int) -> Optional[str]:
        """Extract function name containing the match."""
        lines = content.split('\n')
        
        # Look backwards for function declaration
        for i in range(line_number - 1, max(0, line_number - 20), -1):
            line = lines[i].strip()
            
            # Function declaration patterns
            function_patterns = [
                r'function\s+(\w+)',
                r'const\s+(\w+)\s*=\s*(?:async\s+)?\(',
                r'(\w+)\s*:\s*(?:async\s+)?function',
                r'async\s+(\w+)\s*\(',
                r'export\s+(?:default\s+)?function\s+(\w+)'
            ]
            
            for pattern in function_patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
        
        return None
    
    def _deduplicate_matches(self, matches: List[PatternMatch]) -> List[PatternMatch]:
        """Remove duplicate matches based on location and pattern."""
        seen = set()
        unique_matches = []
        
        for match in matches:
            key = (match.file_path, match.line_number, match.pattern_id, match.matched_text)
            if key not in seen:
                seen.add(key)
                unique_matches.append(match)
        
        return unique_matches
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded patterns."""
        stats = {
            'total_patterns': len(self.patterns),
            'patterns_by_type': {},
            'patterns_by_severity': {},
            'patterns_by_framework': {},
        }
        
        for pattern in self.patterns.values():
            # Count by type
            pattern_type = pattern.pattern_type.value
            stats['patterns_by_type'][pattern_type] = stats['patterns_by_type'].get(pattern_type, 0) + 1
            
            # Count by severity
            severity = pattern.severity.value
            stats['patterns_by_severity'][severity] = stats['patterns_by_severity'].get(severity, 0) + 1
            
            # Count by framework
            for framework in pattern.frameworks:
                stats['patterns_by_framework'][framework] = stats['patterns_by_framework'].get(framework, 0) + 1
        
        return stats
