"""
Base Framework Analyzer

Provides common functionality for all framework-specific analyzers.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)

@dataclass
class FrameworkVulnerability:
    """Framework-specific vulnerability."""
    id: str
    title: str
    description: str
    severity: str
    confidence: str
    framework: str
    category: str  # e.g., 'ssr', 'routing', 'api', 'build', 'security'
    
    file_path: str
    line_number: int = 0
    code_snippet: str = ""
    
    # Framework-specific metadata
    framework_version: Optional[str] = None
    component_type: Optional[str] = None  # e.g., 'page', 'api_route', 'middleware'
    attack_vector: Optional[str] = None
    
    # Remediation
    fix_suggestion: str = ""
    references: List[str] = field(default_factory=list)
    
    # Context
    requires_user_input: bool = False
    affects_server_side: bool = False
    affects_client_side: bool = False
    requires_authentication: bool = False

@dataclass
class FrameworkContext:
    """Context information about the framework application."""
    framework_name: str
    framework_version: Optional[str] = None
    
    # Project structure
    project_root: Path = None
    config_files: List[Path] = field(default_factory=list)
    package_json: Optional[Dict[str, Any]] = None
    
    # Dependencies
    dependencies: Dict[str, str] = field(default_factory=dict)
    dev_dependencies: Dict[str, str] = field(default_factory=dict)
    
    # Framework-specific features
    features_detected: Set[str] = field(default_factory=set)
    routing_type: Optional[str] = None  # e.g., 'pages', 'app', 'file-based'
    build_tool: Optional[str] = None
    
    # Security configurations
    security_headers_config: Dict[str, Any] = field(default_factory=dict)
    authentication_method: Optional[str] = None
    deployment_target: Optional[str] = None

class BaseFrameworkAnalyzer(ABC):
    """Base class for framework-specific analyzers."""
    
    def __init__(self, framework_name: str):
        self.framework_name = framework_name
        self.vulnerabilities: List[FrameworkVulnerability] = []
        
        # Common patterns across frameworks
        self.common_security_patterns = {
            'xss_patterns': [
                r'dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*([^}]+)\}',
                r'innerHTML\s*=\s*([^;]+)',
                r'document\.write\s*\(\s*([^)]+)\)',
                r'eval\s*\(\s*([^)]+)\)'
            ],
            'injection_patterns': [
                r'(query|execute|exec)\s*\(\s*[\'"`].*\$\{[^}]+\}.*[\'"`]\s*\)',
                r'(SELECT|INSERT|UPDATE|DELETE).*\$\{[^}]+\}',
                r'child_process\.(exec|spawn)\s*\([\'"`][^\'"`]*\$\{[^}]+\}[^\'"`]*[\'"`]'
            ],
            'hardcoded_secrets': [
                r'(api[_-]?key|secret|password|token)\s*[:=]\s*[\'"`][a-zA-Z0-9+/=]{20,}[\'"`]',
                r'sk-[a-zA-Z0-9]{48}',  # OpenAI keys
                r'AKIA[A-Z0-9]{16}',    # AWS keys
                r'ghp_[a-zA-Z0-9]{36}' # GitHub tokens
            ],
            'insecure_randomness': [
                r'Math\.random\(\)',
                r'crypto\.pseudoRandomBytes'
            ]
        }
        
        # Framework-specific file patterns
        self.file_patterns = {
            'config': [],
            'pages': [],
            'components': [],
            'api': [],
            'middleware': [],
            'build': []
        }
        
        # Security best practices checklist
        self.security_checklist = {
            'csp_headers': False,
            'secure_cookies': False,
            'https_redirect': False,
            'input_validation': False,
            'output_encoding': False,
            'authentication': False,
            'authorization': False,
            'rate_limiting': False,
            'error_handling': False,
            'logging': False
        }
    
    @abstractmethod
    def analyze_project(self, project_path: Path) -> List[FrameworkVulnerability]:
        """Analyze the entire project for framework-specific vulnerabilities."""
        pass
    
    @abstractmethod
    def detect_framework_features(self, context: FrameworkContext) -> Set[str]:
        """Detect framework-specific features in use."""
        pass
    
    def analyze_file(self, file_path: Path, content: str, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze a single file for vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Common security pattern analysis
            vulnerabilities.extend(self._analyze_common_patterns(file_path, content, context))
            
            # Framework-specific analysis
            vulnerabilities.extend(self._analyze_framework_specific(file_path, content, context))
            
            # Configuration analysis
            if self._is_config_file(file_path):
                vulnerabilities.extend(self._analyze_config_file(file_path, content, context))
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
        
        return vulnerabilities
    
    def _analyze_common_patterns(self, file_path: Path, content: str, 
                                context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze common security patterns across frameworks."""
        vulnerabilities = []
        
        # XSS vulnerabilities
        for pattern in self.common_security_patterns['xss_patterns']:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"xss_{hash(str(match.group()))}",
                    title="Potential Cross-Site Scripting (XSS)",
                    description=f"Potential XSS vulnerability detected in {self.framework_name} application",
                    severity="high",
                    confidence="medium",
                    framework=self.framework_name,
                    category="security",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    affects_client_side=True,
                    fix_suggestion="Sanitize user input and use safe DOM manipulation methods"
                ))
        
        # Injection vulnerabilities
        for pattern in self.common_security_patterns['injection_patterns']:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"injection_{hash(str(match.group()))}",
                    title="Potential Code/SQL Injection",
                    description=f"Potential injection vulnerability in {self.framework_name} application",
                    severity="critical",
                    confidence="high",
                    framework=self.framework_name,
                    category="security",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    affects_server_side=True,
                    requires_user_input=True,
                    fix_suggestion="Use parameterized queries and avoid dynamic code execution"
                ))
        
        # Hardcoded secrets
        for pattern in self.common_security_patterns['hardcoded_secrets']:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"secret_{hash(str(match.group()))}",
                    title="Hardcoded Secret Detected",
                    description=f"Hardcoded secret or API key found in {self.framework_name} application",
                    severity="critical",
                    confidence="high",
                    framework=self.framework_name,
                    category="security",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet="***REDACTED***",  # Don't expose the secret
                    fix_suggestion="Move secrets to environment variables"
                ))
        
        # Insecure randomness
        for pattern in self.common_security_patterns['insecure_randomness']:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"random_{hash(str(match.group()))}",
                    title="Insecure Random Number Generation",
                    description="Use of cryptographically weak random number generation",
                    severity="medium",
                    confidence="high",
                    framework=self.framework_name,
                    category="cryptography",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    fix_suggestion="Use crypto.getRandomValues() or crypto.randomBytes() for secure randomness"
                ))
        
        return vulnerabilities
    
    @abstractmethod
    def _analyze_framework_specific(self, file_path: Path, content: str, 
                                  context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze framework-specific patterns. Override in subclasses."""
        pass
    
    def _analyze_config_file(self, file_path: Path, content: str, 
                           context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze configuration files for security issues."""
        vulnerabilities = []
        
        try:
            # Try to parse as JSON first
            if file_path.suffix == '.json':
                config_data = json.loads(content)
                vulnerabilities.extend(self._analyze_json_config(file_path, config_data, context))
            
            # Analyze as text for other formats
            vulnerabilities.extend(self._analyze_text_config(file_path, content, context))
            
        except json.JSONDecodeError:
            # If JSON parsing fails, analyze as text
            vulnerabilities.extend(self._analyze_text_config(file_path, content, context))
        
        return vulnerabilities
    
    def _analyze_json_config(self, file_path: Path, config_data: Dict[str, Any], 
                           context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze JSON configuration for security issues."""
        vulnerabilities = []
        
        # Check for debug mode in production
        if self._is_debug_enabled(config_data):
            vulnerabilities.append(FrameworkVulnerability(
                id=f"debug_mode_{file_path.name}",
                title="Debug Mode Enabled",
                description="Debug mode appears to be enabled in configuration",
                severity="medium",
                confidence="medium",
                framework=self.framework_name,
                category="configuration",
                file_path=str(file_path),
                fix_suggestion="Disable debug mode in production environments"
            ))
        
        # Check for insecure configurations
        insecure_configs = self._find_insecure_config_values(config_data)
        for config_path, issue in insecure_configs:
            vulnerabilities.append(FrameworkVulnerability(
                id=f"insecure_config_{hash(config_path)}",
                title="Insecure Configuration",
                description=f"Insecure configuration detected: {issue}",
                severity="medium",
                confidence="high",
                framework=self.framework_name,
                category="configuration",
                file_path=str(file_path),
                fix_suggestion=f"Review and secure configuration: {config_path}"
            ))
        
        return vulnerabilities
    
    def _analyze_text_config(self, file_path: Path, content: str, 
                           context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze text-based configuration files."""
        vulnerabilities = []
        
        # Check for exposed secrets in config files
        secret_patterns = [
            r'(password|secret|key|token)\s*[:=]\s*[\'"]?([a-zA-Z0-9+/=]{10,})[\'"]?',
            r'(api[_-]?key|auth[_-]?token)\s*[:=]\s*[\'"]?([a-zA-Z0-9+/=]{10,})[\'"]?'
        ]
        
        for pattern in secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"config_secret_{hash(str(match.group()))}",
                    title="Secret in Configuration File",
                    description="Potential secret or credential found in configuration file",
                    severity="high",
                    confidence="medium",
                    framework=self.framework_name,
                    category="configuration",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet="***REDACTED***",
                    fix_suggestion="Move secrets to environment variables or secure vault"
                ))
        
        return vulnerabilities
    
    def _is_config_file(self, file_path: Path) -> bool:
        """Check if file is a configuration file."""
        config_patterns = [
            r'.*\.config\.(js|ts|mjs|json)$',
            r'package\.json$',
            r'\.env.*$',
            r'.*rc$',
            r'.*\.config$'
        ]
        
        return any(re.match(pattern, file_path.name, re.IGNORECASE) 
                  for pattern in config_patterns)
    
    def _is_debug_enabled(self, config_data: Dict[str, Any]) -> bool:
        """Check if debug mode is enabled in configuration."""
        debug_indicators = [
            'debug', 'development', 'dev', 'verbose'
        ]
        
        def check_nested(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    if any(indicator in key.lower() for indicator in debug_indicators):
                        if value is True or (isinstance(value, str) and value.lower() in ['true', 'on', 'yes']):
                            return True
                    
                    if check_nested(value, current_path):
                        return True
            
            return False
        
        return check_nested(config_data)
    
    def _find_insecure_config_values(self, config_data: Dict[str, Any]) -> List[tuple]:
        """Find insecure configuration values."""
        issues = []
        
        def check_nested(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check for insecure values
                    if isinstance(value, str):
                        if key.lower() in ['cors', 'origin'] and value == '*':
                            issues.append((current_path, "Wildcard CORS origin"))
                        elif key.lower() in ['ssl', 'tls', 'https'] and value is False:
                            issues.append((current_path, "SSL/TLS disabled"))
                        elif 'password' in key.lower() and value in ['', 'password', '123456']:
                            issues.append((current_path, "Weak default password"))
                    
                    elif isinstance(value, bool):
                        if key.lower() in ['verify', 'validate', 'secure'] and value is False:
                            issues.append((current_path, f"Security feature disabled: {key}"))
                    
                    # Recurse into nested objects
                    check_nested(value, current_path)
        
        check_nested(config_data)
        return issues
    
    def create_framework_context(self, project_path: Path) -> FrameworkContext:
        """Create framework context from project analysis."""
        context = FrameworkContext(
            framework_name=self.framework_name,
            project_root=project_path
        )
        
        # Load package.json if available
        package_json_path = project_path / 'package.json'
        if package_json_path.exists():
            try:
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    context.package_json = json.load(f)
                    
                    # Extract dependencies
                    context.dependencies = context.package_json.get('dependencies', {})
                    context.dev_dependencies = context.package_json.get('devDependencies', {})
                    
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load package.json: {e}")
        
        # Find configuration files
        context.config_files = self._find_config_files(project_path)
        
        # Detect framework features
        context.features_detected = self.detect_framework_features(context)
        
        return context
    
    def _find_config_files(self, project_path: Path) -> List[Path]:
        """Find all configuration files in the project."""
        config_files = []
        
        config_patterns = [
            '*.config.js', '*.config.ts', '*.config.mjs',
            'package.json', '.env*', '.*rc', '*.json'
        ]
        
        for pattern in config_patterns:
            config_files.extend(project_path.glob(pattern))
            config_files.extend(project_path.rglob(pattern))
        
        # Remove duplicates and sort
        config_files = list(set(config_files))
        config_files.sort()
        
        return config_files
    
    def generate_security_report(self, vulnerabilities: List[FrameworkVulnerability]) -> Dict[str, Any]:
        """Generate a comprehensive security report for the framework."""
        
        if not vulnerabilities:
            return {
                'framework': self.framework_name,
                'total_vulnerabilities': 0,
                'security_score': 100,
                'summary': 'No vulnerabilities detected'
            }
        
        # Categorize vulnerabilities
        categories = {}
        severities = {}
        
        for vuln in vulnerabilities:
            # Count by category
            categories[vuln.category] = categories.get(vuln.category, 0) + 1
            
            # Count by severity
            severities[vuln.severity] = severities.get(vuln.severity, 0) + 1
        
        # Calculate security score (0-100, higher is better)
        security_score = self._calculate_security_score(vulnerabilities)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities)
        
        return {
            'framework': self.framework_name,
            'total_vulnerabilities': len(vulnerabilities),
            'categories': categories,
            'severities': severities,
            'security_score': security_score,
            'recommendations': recommendations,
            'vulnerabilities': [self._vuln_to_dict(v) for v in vulnerabilities]
        }
    
    def _calculate_security_score(self, vulnerabilities: List[FrameworkVulnerability]) -> int:
        """Calculate security score based on vulnerabilities."""
        
        if not vulnerabilities:
            return 100
        
        # Severity weights
        severity_weights = {
            'critical': 20,
            'high': 10,
            'medium': 5,
            'low': 2,
            'info': 1
        }
        
        # Calculate penalty
        total_penalty = sum(severity_weights.get(v.severity, 1) for v in vulnerabilities)
        
        # Base score is 100, subtract penalties
        score = max(0, 100 - total_penalty)
        
        return score
    
    def _generate_recommendations(self, vulnerabilities: List[FrameworkVulnerability]) -> List[str]:
        """Generate security recommendations based on vulnerabilities."""
        
        recommendations = []
        
        # Count vulnerability types
        categories = {}
        for vuln in vulnerabilities:
            categories[vuln.category] = categories.get(vuln.category, 0) + 1
        
        # Generate category-specific recommendations
        if 'security' in categories:
            recommendations.append("Implement comprehensive input validation and output encoding")
            recommendations.append("Use framework-provided security features and middleware")
        
        if 'configuration' in categories:
            recommendations.append("Review and harden all configuration files")
            recommendations.append("Use environment variables for sensitive configuration")
        
        if 'cryptography' in categories:
            recommendations.append("Use cryptographically secure random number generation")
            recommendations.append("Implement proper key management practices")
        
        # General recommendations
        recommendations.extend([
            f"Regularly update {self.framework_name} and its dependencies",
            "Implement security headers and Content Security Policy",
            "Use HTTPS in production environments",
            "Implement proper error handling and logging",
            "Conduct regular security audits and penetration testing"
        ])
        
        return recommendations
    
    def _vuln_to_dict(self, vulnerability: FrameworkVulnerability) -> Dict[str, Any]:
        """Convert vulnerability to dictionary for serialization."""
        
        return {
            'id': vulnerability.id,
            'title': vulnerability.title,
            'description': vulnerability.description,
            'severity': vulnerability.severity,
            'confidence': vulnerability.confidence,
            'framework': vulnerability.framework,
            'category': vulnerability.category,
            'file_path': vulnerability.file_path,
            'line_number': vulnerability.line_number,
            'code_snippet': vulnerability.code_snippet,
            'framework_version': vulnerability.framework_version,
            'component_type': vulnerability.component_type,
            'attack_vector': vulnerability.attack_vector,
            'fix_suggestion': vulnerability.fix_suggestion,
            'references': vulnerability.references,
            'requires_user_input': vulnerability.requires_user_input,
            'affects_server_side': vulnerability.affects_server_side,
            'affects_client_side': vulnerability.affects_client_side,
            'requires_authentication': vulnerability.requires_authentication
        }
