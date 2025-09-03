"""
Advanced Configuration Analyzer

Comprehensive configuration file analysis including security misconfigurations,
secrets detection, and best practices validation across multiple formats.
"""

import re
import json
import yaml
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ConfigurationType(Enum):
    """Types of configuration files."""
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"
    XML = "xml"
    INI = "ini"
    PROPERTIES = "properties"
    ENV = "env"
    DOCKERFILE = "dockerfile"
    DOCKER_COMPOSE = "docker_compose"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    ANSIBLE = "ansible"
    NGINX = "nginx"
    APACHE = "apache"
    DATABASE = "database"
    APPLICATION = "application"

class SecuritySeverity(Enum):
    """Security issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ConfigurationFinding:
    """Security finding in configuration."""
    finding_id: str
    file_path: str
    line_number: int
    column_number: int
    
    # Issue details
    rule_id: str
    rule_name: str
    severity: SecuritySeverity
    category: str
    
    # Content
    finding_text: str
    context: str
    
    # Description and remediation
    description: str
    impact: str
    remediation: str
    references: List[str] = field(default_factory=list)
    
    # Metadata
    config_type: ConfigurationType
    confidence: float = 1.0
    false_positive_likelihood: float = 0.0
    
    # CWE and compliance mappings
    cwe_ids: List[int] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)

@dataclass
class ConfigurationFile:
    """Parsed configuration file."""
    file_path: Path
    config_type: ConfigurationType
    content: str
    parsed_content: Any
    
    # Metadata
    file_size: int
    line_count: int
    encoding: str = "utf-8"
    
    # Analysis results
    findings: List[ConfigurationFinding] = field(default_factory=list)
    secrets_found: List[Dict[str, Any]] = field(default_factory=list)
    
    # Security metrics
    security_score: float = 0.0
    risk_level: str = "unknown"

@dataclass
class ConfigurationAnalysisResult:
    """Complete configuration analysis result."""
    analysis_id: str
    project_path: str
    analysis_time: float
    
    # Files analyzed
    configuration_files: List[ConfigurationFile]
    total_files_analyzed: int
    
    # Findings summary
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    
    # Security summary
    secrets_found: int
    misconfigurations_found: int
    compliance_violations: int
    
    # Risk assessment
    overall_security_score: float
    overall_risk_level: str
    
    # Categories
    findings_by_category: Dict[str, int]
    findings_by_file_type: Dict[str, int]
    
    # Recommendations
    immediate_actions: List[str]
    security_recommendations: List[str]

class ConfigurationAnalyzer:
    """Advanced configuration security analyzer."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Analysis configuration
        self.analysis_config = {
            'max_file_size': self.config.get('max_file_size', 10 * 1024 * 1024),  # 10MB
            'recursive_scan': self.config.get('recursive_scan', True),
            'follow_symlinks': self.config.get('follow_symlinks', False),
            'include_hidden_files': self.config.get('include_hidden_files', False),
            'max_depth': self.config.get('max_depth', 10),
            'enable_secrets_detection': self.config.get('enable_secrets_detection', True),
            'enable_compliance_checks': self.config.get('enable_compliance_checks', True)
        }
        
        # File type mappings
        self.file_extensions = {
            '.json': ConfigurationType.JSON,
            '.yaml': ConfigurationType.YAML,
            '.yml': ConfigurationType.YAML,
            '.toml': ConfigurationType.TOML,
            '.xml': ConfigurationType.XML,
            '.ini': ConfigurationType.INI,
            '.cfg': ConfigurationType.INI,
            '.conf': ConfigurationType.INI,
            '.properties': ConfigurationType.PROPERTIES,
            '.env': ConfigurationType.ENV,
            '.dockerfile': ConfigurationType.DOCKERFILE,
            'dockerfile': ConfigurationType.DOCKERFILE,
            'docker-compose.yml': ConfigurationType.DOCKER_COMPOSE,
            'docker-compose.yaml': ConfigurationType.DOCKER_COMPOSE,
            '.tf': ConfigurationType.TERRAFORM,
            '.tfvars': ConfigurationType.TERRAFORM,
            'nginx.conf': ConfigurationType.NGINX,
            'httpd.conf': ConfigurationType.APACHE,
            'my.cnf': ConfigurationType.DATABASE,
            'postgresql.conf': ConfigurationType.DATABASE
        }
        
        # Kubernetes file patterns
        self.kubernetes_patterns = [
            r'.*\.k8s\.ya?ml$',
            r'.*kubernetes.*\.ya?ml$',
            r'.*deployment\.ya?ml$',
            r'.*service\.ya?ml$',
            r'.*ingress\.ya?ml$',
            r'.*configmap\.ya?ml$',
            r'.*secret\.ya?ml$'
        ]
        
        # Security rules (would be loaded from external files in real implementation)
        self.security_rules = self._initialize_security_rules()
        
        # Statistics
        self.stats = {
            'files_analyzed': 0,
            'findings_detected': 0,
            'secrets_found': 0,
            'critical_issues': 0,
            'compliance_violations': 0
        }
    
    async def analyze_configurations(self, project_path: Path) -> ConfigurationAnalysisResult:
        """Analyze all configuration files in project."""
        
        logger.info(f"Starting configuration analysis for: {project_path}")
        
        analysis_start_time = time.time()
        analysis_id = f"config_analysis_{int(analysis_start_time)}"
        
        # Discover configuration files
        config_files = await self._discover_configuration_files(project_path)
        
        logger.info(f"Found {len(config_files)} configuration files")
        
        # Parse and analyze each file
        analyzed_files = []
        for file_path in config_files:
            try:
                config_file = await self._analyze_configuration_file(file_path)
                if config_file:
                    analyzed_files.append(config_file)
            except Exception as e:
                logger.error(f"Failed to analyze {file_path}: {str(e)}")
        
        # Generate analysis result
        result = await self._generate_analysis_result(
            analysis_id, str(project_path), analysis_start_time, analyzed_files
        )
        
        # Update statistics
        self._update_statistics(result)
        
        logger.info(f"Configuration analysis completed: {result.total_findings} findings across {len(analyzed_files)} files")
        
        return result
    
    async def _discover_configuration_files(self, project_path: Path) -> List[Path]:
        """Discover all configuration files in project."""
        
        config_files = []
        
        def should_analyze_file(file_path: Path) -> bool:
            # Check file size
            if file_path.stat().st_size > self.analysis_config['max_file_size']:
                return False
            
            # Check hidden files
            if not self.analysis_config['include_hidden_files'] and file_path.name.startswith('.'):
                return False
            
            # Check if it's a configuration file
            return self._is_configuration_file(file_path)
        
        if self.analysis_config['recursive_scan']:
            for file_path in project_path.rglob('*'):
                if file_path.is_file() and should_analyze_file(file_path):
                    config_files.append(file_path)
        else:
            for file_path in project_path.iterdir():
                if file_path.is_file() and should_analyze_file(file_path):
                    config_files.append(file_path)
        
        return config_files
    
    def _is_configuration_file(self, file_path: Path) -> bool:
        """Check if file is a configuration file."""
        
        # Check by extension
        if file_path.suffix.lower() in self.file_extensions:
            return True
        
        # Check by filename
        if file_path.name.lower() in self.file_extensions:
            return True
        
        # Check Kubernetes patterns
        for pattern in self.kubernetes_patterns:
            if re.match(pattern, file_path.name.lower()):
                return True
        
        # Check common config file names
        config_names = [
            'config', 'configuration', 'settings', 'options',
            'package.json', 'tsconfig.json', 'webpack.config.js',
            'next.config.js', 'tailwind.config.js', 'jest.config.js',
            '.env', '.env.local', '.env.production', '.env.development',
            'docker-compose.yml', 'docker-compose.yaml',
            'Dockerfile', 'dockerfile'
        ]
        
        return any(name in file_path.name.lower() for name in config_names)
    
    async def _analyze_configuration_file(self, file_path: Path) -> Optional[ConfigurationFile]:
        """Analyze a single configuration file."""
        
        try:
            # Read file content
            content = file_path.read_text(encoding='utf-8')
            
            # Determine configuration type
            config_type = self._determine_config_type(file_path)
            
            # Parse content
            parsed_content = await self._parse_configuration(content, config_type)
            
            # Create configuration file object
            config_file = ConfigurationFile(
                file_path=file_path,
                config_type=config_type,
                content=content,
                parsed_content=parsed_content,
                file_size=file_path.stat().st_size,
                line_count=len(content.splitlines())
            )
            
            # Apply security rules
            await self._apply_security_rules(config_file)
            
            # Detect secrets if enabled
            if self.analysis_config['enable_secrets_detection']:
                await self._detect_secrets(config_file)
            
            # Calculate security metrics
            await self._calculate_security_metrics(config_file)
            
            return config_file
            
        except Exception as e:
            logger.error(f"Error analyzing configuration file {file_path}: {str(e)}")
            return None
    
    def _determine_config_type(self, file_path: Path) -> ConfigurationType:
        """Determine configuration type from file path."""
        
        # Check by extension first
        if file_path.suffix.lower() in self.file_extensions:
            return self.file_extensions[file_path.suffix.lower()]
        
        # Check by filename
        if file_path.name.lower() in self.file_extensions:
            return self.file_extensions[file_path.name.lower()]
        
        # Check Kubernetes patterns
        for pattern in self.kubernetes_patterns:
            if re.match(pattern, file_path.name.lower()):
                return ConfigurationType.KUBERNETES
        
        # Check content-based detection
        try:
            content = file_path.read_text(encoding='utf-8')[:1000]  # First 1000 chars
            
            if content.strip().startswith('{') and '"' in content:
                return ConfigurationType.JSON
            elif any(yaml_indicator in content for yaml_indicator in ['---', 'apiVersion:', 'kind:']):
                return ConfigurationType.YAML
            elif content.strip().startswith('[') or '=' in content:
                return ConfigurationType.TOML if '[' in content else ConfigurationType.INI
            elif content.strip().startswith('<?xml'):
                return ConfigurationType.XML
            elif content.strip().upper().startswith('FROM '):
                return ConfigurationType.DOCKERFILE
        except:
            pass
        
        return ConfigurationType.APPLICATION  # Default
    
    async def _parse_configuration(self, content: str, config_type: ConfigurationType) -> Any:
        """Parse configuration content based on type."""
        
        try:
            if config_type == ConfigurationType.JSON:
                return json.loads(content)
            
            elif config_type in [ConfigurationType.YAML, ConfigurationType.KUBERNETES, ConfigurationType.DOCKER_COMPOSE]:
                return yaml.safe_load(content)
            
            elif config_type == ConfigurationType.XML:
                return ET.fromstring(content)
            
            elif config_type == ConfigurationType.TOML:
                # Would use tomllib/tomli in real implementation
                return self._parse_toml_simple(content)
            
            elif config_type in [ConfigurationType.INI, ConfigurationType.PROPERTIES]:
                return self._parse_ini_properties(content)
            
            elif config_type == ConfigurationType.ENV:
                return self._parse_env_file(content)
            
            elif config_type == ConfigurationType.DOCKERFILE:
                return self._parse_dockerfile(content)
            
            else:
                return {'raw_content': content}
                
        except Exception as e:
            logger.warning(f"Failed to parse {config_type.value} content: {str(e)}")
            return {'raw_content': content, 'parse_error': str(e)}
    
    def _parse_toml_simple(self, content: str) -> Dict[str, Any]:
        """Simple TOML parser (would use proper library in production)."""
        
        result = {}
        current_section = result
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('[') and line.endswith(']'):
                section_name = line[1:-1]
                current_section = result.setdefault(section_name, {})
            elif '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"\'')
                current_section[key] = value
        
        return result
    
    def _parse_ini_properties(self, content: str) -> Dict[str, Any]:
        """Parse INI/Properties file."""
        
        result = {}
        current_section = result
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            if line.startswith('[') and line.endswith(']'):
                section_name = line[1:-1]
                current_section = result.setdefault(section_name, {})
            elif '=' in line or ':' in line:
                separator = '=' if '=' in line else ':'
                key, value = line.split(separator, 1)
                current_section[key.strip()] = value.strip()
        
        return result
    
    def _parse_env_file(self, content: str) -> Dict[str, str]:
        """Parse environment file."""
        
        result = {}
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                result[key.strip()] = value.strip().strip('"\'')
        
        return result
    
    def _parse_dockerfile(self, content: str) -> Dict[str, Any]:
        """Parse Dockerfile."""
        
        instructions = []
        
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split(None, 1)
            if parts:
                instruction = parts[0].upper()
                args = parts[1] if len(parts) > 1 else ""
                instructions.append({
                    'line': line_num,
                    'instruction': instruction,
                    'args': args
                })
        
        return {'instructions': instructions}
    
    async def _apply_security_rules(self, config_file: ConfigurationFile):
        """Apply security rules to configuration file."""
        
        applicable_rules = self._get_applicable_rules(config_file.config_type)
        
        for rule in applicable_rules:
            findings = await self._apply_security_rule(config_file, rule)
            config_file.findings.extend(findings)
    
    def _get_applicable_rules(self, config_type: ConfigurationType) -> List[Dict[str, Any]]:
        """Get security rules applicable to configuration type."""
        
        return [rule for rule in self.security_rules 
                if config_type.value in rule.get('applicable_types', [])]
    
    async def _apply_security_rule(self, config_file: ConfigurationFile, 
                                 rule: Dict[str, Any]) -> List[ConfigurationFinding]:
        """Apply single security rule to configuration file."""
        
        findings = []
        
        rule_type = rule.get('type', 'pattern')
        
        if rule_type == 'pattern':
            findings.extend(await self._apply_pattern_rule(config_file, rule))
        elif rule_type == 'structural':
            findings.extend(await self._apply_structural_rule(config_file, rule))
        elif rule_type == 'value':
            findings.extend(await self._apply_value_rule(config_file, rule))
        
        return findings
    
    async def _apply_pattern_rule(self, config_file: ConfigurationFile, 
                                rule: Dict[str, Any]) -> List[ConfigurationFinding]:
        """Apply pattern-based security rule."""
        
        findings = []
        patterns = rule.get('patterns', [])
        
        for line_num, line in enumerate(config_file.content.splitlines(), 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    finding = ConfigurationFinding(
                        finding_id=f"{rule['id']}_{config_file.file_path.name}_{line_num}",
                        file_path=str(config_file.file_path),
                        line_number=line_num,
                        column_number=1,
                        rule_id=rule['id'],
                        rule_name=rule['name'],
                        severity=SecuritySeverity(rule['severity']),
                        category=rule['category'],
                        finding_text=line.strip(),
                        context=self._get_context(config_file.content, line_num),
                        description=rule['description'],
                        impact=rule['impact'],
                        remediation=rule['remediation'],
                        references=rule.get('references', []),
                        config_type=config_file.config_type,
                        confidence=rule.get('confidence', 0.8),
                        cwe_ids=rule.get('cwe_ids', []),
                        compliance_frameworks=rule.get('compliance', [])
                    )
                    findings.append(finding)
        
        return findings
    
    async def _apply_structural_rule(self, config_file: ConfigurationFile, 
                                   rule: Dict[str, Any]) -> List[ConfigurationFinding]:
        """Apply structural security rule."""
        
        findings = []
        
        if not isinstance(config_file.parsed_content, dict):
            return findings
        
        checks = rule.get('checks', [])
        
        for check in checks:
            path = check.get('path', '')
            condition = check.get('condition', '')
            
            if self._evaluate_structural_condition(config_file.parsed_content, path, condition):
                finding = ConfigurationFinding(
                    finding_id=f"{rule['id']}_{config_file.file_path.name}_structural",
                    file_path=str(config_file.file_path),
                    line_number=1,  # Would need better line tracking for structured data
                    column_number=1,
                    rule_id=rule['id'],
                    rule_name=rule['name'],
                    severity=SecuritySeverity(rule['severity']),
                    category=rule['category'],
                    finding_text=f"Path: {path}",
                    context="Structural issue in configuration",
                    description=rule['description'],
                    impact=rule['impact'],
                    remediation=rule['remediation'],
                    references=rule.get('references', []),
                    config_type=config_file.config_type,
                    confidence=rule.get('confidence', 0.9),
                    cwe_ids=rule.get('cwe_ids', []),
                    compliance_frameworks=rule.get('compliance', [])
                )
                findings.append(finding)
        
        return findings
    
    def _evaluate_structural_condition(self, data: Any, path: str, condition: str) -> bool:
        """Evaluate structural condition on parsed data."""
        
        try:
            # Navigate to path
            current = data
            for part in path.split('.'):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return False
            
            # Evaluate condition
            if condition == 'exists':
                return True
            elif condition == 'missing':
                return False
            elif condition.startswith('equals:'):
                expected = condition.split(':', 1)[1]
                return str(current) == expected
            elif condition.startswith('contains:'):
                search_term = condition.split(':', 1)[1]
                return search_term in str(current)
            
        except:
            pass
        
        return False
    
    async def _apply_value_rule(self, config_file: ConfigurationFile, 
                              rule: Dict[str, Any]) -> List[ConfigurationFinding]:
        """Apply value-based security rule."""
        
        findings = []
        
        if not isinstance(config_file.parsed_content, dict):
            return findings
        
        value_checks = rule.get('value_checks', [])
        
        for check in value_checks:
            findings.extend(self._check_values_recursive(
                config_file, rule, check, config_file.parsed_content, ""
            ))
        
        return findings
    
    def _check_values_recursive(self, config_file: ConfigurationFile, rule: Dict[str, Any],
                              check: Dict[str, Any], data: Any, path: str) -> List[ConfigurationFinding]:
        """Recursively check values in configuration data."""
        
        findings = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check key patterns
                key_patterns = check.get('key_patterns', [])
                for pattern in key_patterns:
                    if re.search(pattern, key, re.IGNORECASE):
                        # Check value conditions
                        if self._check_value_condition(value, check):
                            finding = self._create_value_finding(
                                config_file, rule, current_path, str(value)
                            )
                            findings.append(finding)
                
                # Recurse into nested structures
                findings.extend(self._check_values_recursive(
                    config_file, rule, check, value, current_path
                ))
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                findings.extend(self._check_values_recursive(
                    config_file, rule, check, item, current_path
                ))
        
        return findings
    
    def _check_value_condition(self, value: Any, check: Dict[str, Any]) -> bool:
        """Check if value meets condition criteria."""
        
        conditions = check.get('conditions', [])
        
        for condition in conditions:
            condition_type = condition.get('type', '')
            
            if condition_type == 'insecure_value':
                insecure_values = condition.get('values', [])
                if str(value).lower() in [v.lower() for v in insecure_values]:
                    return True
            
            elif condition_type == 'weak_password':
                if isinstance(value, str) and len(value) < 8:
                    return True
            
            elif condition_type == 'hardcoded_secret':
                if isinstance(value, str) and self._looks_like_secret(value):
                    return True
        
        return False
    
    def _looks_like_secret(self, value: str) -> bool:
        """Check if value looks like a hardcoded secret."""
        
        # Simple heuristics for secret detection
        if len(value) < 8:
            return False
        
        # Check for common secret patterns
        secret_patterns = [
            r'^[A-Za-z0-9+/]{40,}={0,2}$',  # Base64
            r'^[A-Fa-f0-9]{32,}$',           # Hex
            r'^[A-Z0-9]{20,}$',              # API key pattern
            r'sk_[a-z]{2}_[A-Za-z0-9]{48}',  # Stripe key
            r'AKIA[0-9A-Z]{16}',             # AWS Access Key
        ]
        
        return any(re.match(pattern, value) for pattern in secret_patterns)
    
    def _create_value_finding(self, config_file: ConfigurationFile, rule: Dict[str, Any],
                            path: str, value: str) -> ConfigurationFinding:
        """Create finding for value-based rule violation."""
        
        return ConfigurationFinding(
            finding_id=f"{rule['id']}_{config_file.file_path.name}_{hash(path)}",
            file_path=str(config_file.file_path),
            line_number=1,  # Would need better line tracking
            column_number=1,
            rule_id=rule['id'],
            rule_name=rule['name'],
            severity=SecuritySeverity(rule['severity']),
            category=rule['category'],
            finding_text=f"{path}: {value[:50]}{'...' if len(value) > 50 else ''}",
            context=f"Configuration path: {path}",
            description=rule['description'],
            impact=rule['impact'],
            remediation=rule['remediation'],
            references=rule.get('references', []),
            config_type=config_file.config_type,
            confidence=rule.get('confidence', 0.8),
            cwe_ids=rule.get('cwe_ids', []),
            compliance_frameworks=rule.get('compliance', [])
        )
    
    async def _detect_secrets(self, config_file: ConfigurationFile):
        """Detect secrets in configuration file."""
        
        # This would integrate with a proper secrets detection library
        secrets_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
            'github_token': r'ghp_[A-Za-z0-9]{36}',
            'slack_token': r'xox[baprs]-[A-Za-z0-9-]+',
            'stripe_key': r'sk_[a-z]{2}_[A-Za-z0-9]{48}',
            'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'private_key': r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
            'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\\s]+)',
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9-_]{16,})',
        }
        
        for line_num, line in enumerate(config_file.content.splitlines(), 1):
            for secret_type, pattern in secrets_patterns.items():
                matches = re.finditer(pattern, line)
                for match in matches:
                    secret_info = {
                        'type': secret_type,
                        'line': line_num,
                        'column': match.start(),
                        'value': match.group()[:20] + '...' if len(match.group()) > 20 else match.group(),
                        'confidence': 0.8
                    }
                    config_file.secrets_found.append(secret_info)
    
    async def _calculate_security_metrics(self, config_file: ConfigurationFile):
        """Calculate security metrics for configuration file."""
        
        # Calculate security score based on findings
        base_score = 100.0
        
        for finding in config_file.findings:
            if finding.severity == SecuritySeverity.CRITICAL:
                base_score -= 25
            elif finding.severity == SecuritySeverity.HIGH:
                base_score -= 15
            elif finding.severity == SecuritySeverity.MEDIUM:
                base_score -= 10
            elif finding.severity == SecuritySeverity.LOW:
                base_score -= 5
        
        # Deduct for secrets
        base_score -= len(config_file.secrets_found) * 20
        
        config_file.security_score = max(0.0, base_score)
        
        # Determine risk level
        if config_file.security_score >= 80:
            config_file.risk_level = "low"
        elif config_file.security_score >= 60:
            config_file.risk_level = "medium"
        elif config_file.security_score >= 40:
            config_file.risk_level = "high"
        else:
            config_file.risk_level = "critical"
    
    def _get_context(self, content: str, line_num: int, context_lines: int = 3) -> str:
        """Get context around a specific line."""
        
        lines = content.splitlines()
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        
        context_lines_list = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            context_lines_list.append(f"{prefix}{i+1:3d}: {lines[i]}")
        
        return "\n".join(context_lines_list)
    
    async def _generate_analysis_result(self, analysis_id: str, project_path: str,
                                      analysis_time: float, 
                                      analyzed_files: List[ConfigurationFile]) -> ConfigurationAnalysisResult:
        """Generate comprehensive analysis result."""
        
        # Count findings by severity
        total_findings = sum(len(f.findings) for f in analyzed_files)
        critical_findings = sum(len([finding for finding in f.findings if finding.severity == SecuritySeverity.CRITICAL]) for f in analyzed_files)
        high_findings = sum(len([finding for finding in f.findings if finding.severity == SecuritySeverity.HIGH]) for f in analyzed_files)
        medium_findings = sum(len([finding for finding in f.findings if finding.severity == SecuritySeverity.MEDIUM]) for f in analyzed_files)
        low_findings = sum(len([finding for finding in f.findings if finding.severity == SecuritySeverity.LOW]) for f in analyzed_files)
        info_findings = sum(len([finding for finding in f.findings if finding.severity == SecuritySeverity.INFO]) for f in analyzed_files)
        
        # Count secrets and other metrics
        secrets_found = sum(len(f.secrets_found) for f in analyzed_files)
        
        # Group findings by category
        findings_by_category = {}
        for config_file in analyzed_files:
            for finding in config_file.findings:
                findings_by_category[finding.category] = findings_by_category.get(finding.category, 0) + 1
        
        # Group findings by file type
        findings_by_file_type = {}
        for config_file in analyzed_files:
            file_type = config_file.config_type.value
            findings_by_file_type[file_type] = findings_by_file_type.get(file_type, 0) + len(config_file.findings)
        
        # Calculate overall security score
        if analyzed_files:
            overall_security_score = sum(f.security_score for f in analyzed_files) / len(analyzed_files)
        else:
            overall_security_score = 100.0
        
        # Determine overall risk level
        if overall_security_score >= 80:
            overall_risk_level = "low"
        elif overall_security_score >= 60:
            overall_risk_level = "medium"
        elif overall_security_score >= 40:
            overall_risk_level = "high"
        else:
            overall_risk_level = "critical"
        
        # Generate recommendations
        immediate_actions = []
        security_recommendations = []
        
        if critical_findings > 0:
            immediate_actions.append(f"Address {critical_findings} critical configuration issues immediately")
        
        if secrets_found > 0:
            immediate_actions.append(f"Remove {secrets_found} hardcoded secrets from configuration files")
        
        if high_findings > 5:
            immediate_actions.append("Review and fix high-severity configuration issues")
        
        security_recommendations.extend([
            "Implement configuration management best practices",
            "Use environment variables for sensitive configuration",
            "Enable configuration validation in CI/CD pipeline",
            "Regular security review of configuration changes",
            "Implement least privilege principles in configurations"
        ])
        
        return ConfigurationAnalysisResult(
            analysis_id=analysis_id,
            project_path=project_path,
            analysis_time=analysis_time,
            configuration_files=analyzed_files,
            total_files_analyzed=len(analyzed_files),
            total_findings=total_findings,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            info_findings=info_findings,
            secrets_found=secrets_found,
            misconfigurations_found=total_findings,
            compliance_violations=sum(len([f for f in cf.findings if f.compliance_frameworks]) for cf in analyzed_files),
            overall_security_score=overall_security_score,
            overall_risk_level=overall_risk_level,
            findings_by_category=findings_by_category,
            findings_by_file_type=findings_by_file_type,
            immediate_actions=immediate_actions,
            security_recommendations=security_recommendations
        )
    
    def _initialize_security_rules(self) -> List[Dict[str, Any]]:
        """Initialize security rules for configuration analysis."""
        
        return [
            {
                'id': 'HARDCODED_PASSWORD',
                'name': 'Hardcoded Password Detection',
                'type': 'pattern',
                'severity': 'critical',
                'category': 'secrets',
                'applicable_types': ['json', 'yaml', 'env', 'ini', 'properties'],
                'patterns': [
                    r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^"\'\\s]{8,}',
                    r'(?i)(secret|token|key)\s*[:=]\s*["\']?[A-Za-z0-9+/]{20,}'
                ],
                'description': 'Hardcoded password or secret detected in configuration',
                'impact': 'Credentials exposure could lead to unauthorized access',
                'remediation': 'Use environment variables or secure credential management',
                'references': ['CWE-798', 'OWASP-A07'],
                'confidence': 0.9,
                'cwe_ids': [798],
                'compliance': ['SOC2', 'PCI-DSS']
            },
            {
                'id': 'INSECURE_HTTP',
                'name': 'Insecure HTTP URLs',
                'type': 'pattern',
                'severity': 'medium',
                'category': 'communication',
                'applicable_types': ['json', 'yaml', 'xml', 'properties'],
                'patterns': [
                    r'http://[^\\s"\'<>]+',
                    r'(?i)secure\s*[:=]\s*false',
                    r'(?i)ssl\s*[:=]\s*false'
                ],
                'description': 'Insecure HTTP communication detected',
                'impact': 'Data transmitted over HTTP can be intercepted',
                'remediation': 'Use HTTPS for all external communications',
                'references': ['CWE-319'],
                'confidence': 0.8,
                'cwe_ids': [319],
                'compliance': ['PCI-DSS']
            },
            {
                'id': 'DEBUG_MODE_ENABLED',
                'name': 'Debug Mode Enabled',
                'type': 'value',
                'severity': 'high',
                'category': 'configuration',
                'applicable_types': ['json', 'yaml', 'properties'],
                'value_checks': [{
                    'key_patterns': [r'(?i)debug', r'(?i)development'],
                    'conditions': [{
                        'type': 'insecure_value',
                        'values': ['true', '1', 'yes', 'on', 'enabled']
                    }]
                }],
                'description': 'Debug mode is enabled in configuration',
                'impact': 'Debug mode can expose sensitive information and increase attack surface',
                'remediation': 'Disable debug mode in production environments',
                'references': ['CWE-489'],
                'confidence': 0.9,
                'cwe_ids': [489]
            },
            {
                'id': 'WEAK_ENCRYPTION',
                'name': 'Weak Encryption Configuration',
                'type': 'pattern',
                'severity': 'high',
                'category': 'cryptography',
                'applicable_types': ['json', 'yaml', 'xml', 'properties'],
                'patterns': [
                    r'(?i)(md5|sha1|des|3des|rc4)',
                    r'(?i)cipher.*\b(null|none|weak)\b',
                    r'(?i)ssl.*v[12]\.',
                    r'(?i)tls.*v1\.[01]'
                ],
                'description': 'Weak encryption algorithm or protocol detected',
                'impact': 'Weak cryptography can be broken by attackers',
                'remediation': 'Use strong encryption algorithms (AES-256, SHA-256) and modern TLS versions',
                'references': ['CWE-327'],
                'confidence': 0.85,
                'cwe_ids': [327],
                'compliance': ['PCI-DSS', 'FIPS-140']
            },
            {
                'id': 'DOCKER_PRIVILEGED',
                'name': 'Docker Privileged Mode',
                'type': 'structural',
                'severity': 'critical',
                'category': 'container',
                'applicable_types': ['docker_compose', 'kubernetes'],
                'checks': [{
                    'path': 'services.*.privileged',
                    'condition': 'equals:true'
                }, {
                    'path': 'spec.containers.*.securityContext.privileged',
                    'condition': 'equals:true'
                }],
                'description': 'Container running in privileged mode',
                'impact': 'Privileged containers have full access to host system',
                'remediation': 'Run containers with minimal required privileges',
                'references': ['CWE-250'],
                'confidence': 1.0,
                'cwe_ids': [250]
            },
            {
                'id': 'KUBERNETES_DEFAULT_NAMESPACE',
                'name': 'Kubernetes Default Namespace Usage',
                'type': 'structural',
                'severity': 'medium',
                'category': 'kubernetes',
                'applicable_types': ['kubernetes'],
                'checks': [{
                    'path': 'metadata.namespace',
                    'condition': 'missing'
                }, {
                    'path': 'metadata.namespace',
                    'condition': 'equals:default'
                }],
                'description': 'Resource deployed to default namespace',
                'impact': 'Using default namespace reduces security isolation',
                'remediation': 'Use dedicated namespaces for applications',
                'references': ['Kubernetes Security Best Practices'],
                'confidence': 0.7
            }
        ]
    
    def _update_statistics(self, result: ConfigurationAnalysisResult):
        """Update analyzer statistics."""
        
        self.stats['files_analyzed'] += result.total_files_analyzed
        self.stats['findings_detected'] += result.total_findings
        self.stats['secrets_found'] += result.secrets_found
        self.stats['critical_issues'] += result.critical_findings
        self.stats['compliance_violations'] += result.compliance_violations
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        
        return dict(self.stats)
