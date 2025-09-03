"""
Configuration Security Orchestrator

Coordinates comprehensive configuration security analysis including:
- Multi-format configuration file analysis
- Advanced secrets detection
- Infrastructure as Code (IaC) security scanning
- Cloud configuration analysis
- Compliance validation
"""

import asyncio
import time
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

from .config_analyzer import ConfigurationAnalyzer, ConfigurationAnalysisResult, ConfigurationFinding
from .secrets_detector import SecretsDetector, SecretsAnalysisResult, SecretMatch

logger = logging.getLogger(__name__)

@dataclass
class ConfigurationSecurityConfiguration:
    """Configuration for comprehensive configuration security analysis."""
    project_path: Path
    
    # Analysis scope
    include_hidden_files: bool = False
    recursive_scan: bool = True
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    max_depth: int = 10
    
    # Analysis types
    enable_config_analysis: bool = True
    enable_secrets_detection: bool = True
    enable_iac_analysis: bool = True
    enable_cloud_config_analysis: bool = True
    
    # Security settings
    secrets_confidence_threshold: float = 0.7
    config_severity_threshold: str = "medium"  # minimum severity to report
    
    # Compliance frameworks
    compliance_frameworks: List[str] = None
    
    # Output settings
    output_directory: Optional[Path] = None
    export_formats: List[str] = None  # json, sarif, csv
    
    def __post_init__(self):
        if self.compliance_frameworks is None:
            self.compliance_frameworks = ['SOC2', 'PCI-DSS', 'GDPR']
        if self.export_formats is None:
            self.export_formats = ['json']

@dataclass
class ConfigurationSecurityResult:
    """Comprehensive configuration security analysis result."""
    analysis_id: str
    project_path: str
    analysis_time: float
    analysis_duration: float
    
    # Component results
    config_analysis_result: Optional[ConfigurationAnalysisResult]
    secrets_analysis_result: Optional[SecretsAnalysisResult]
    iac_analysis_results: List[Dict[str, Any]]
    cloud_config_results: List[Dict[str, Any]]
    
    # Aggregated findings
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    
    # Security summary
    secrets_found: int
    misconfigurations_found: int
    iac_violations: int
    cloud_security_issues: int
    
    # Risk assessment
    overall_risk_score: float
    risk_level: str
    critical_issues: List[str]
    
    # Compliance
    compliance_status: Dict[str, str]  # framework -> status
    compliance_violations: List[Dict[str, Any]]
    
    # Categories
    findings_by_category: Dict[str, int]
    findings_by_severity: Dict[str, int]
    findings_by_file_type: Dict[str, int]
    
    # Recommendations
    immediate_actions: List[str]
    security_recommendations: List[str]
    remediation_priorities: List[Dict[str, Any]]
    
    # Statistics
    files_analyzed: int
    lines_analyzed: int
    config_files_found: int
    secret_patterns_matched: int
    
    # Metadata
    configuration: ConfigurationSecurityConfiguration
    orchestrator_version: str

class ConfigurationSecurityOrchestrator:
    """Orchestrates comprehensive configuration security analysis."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize analysis components
        self.config_analyzer = ConfigurationAnalyzer(config.get('config_analysis', {}))
        self.secrets_detector = SecretsDetector(config.get('secrets_detection', {}))
        
        # Orchestration configuration
        self.orchestration_config = {
            'parallel_analysis': self.config.get('parallel_analysis', True),
            'analysis_timeout': self.config.get('analysis_timeout', 1800),  # 30 minutes
            'detailed_reporting': self.config.get('detailed_reporting', True),
            'cache_results': self.config.get('cache_results', True)
        }
        
        # Risk scoring weights
        self.risk_weights = {
            'critical_secrets': 40,
            'critical_misconfig': 35,
            'high_secrets': 25,
            'high_misconfig': 20,
            'medium_issues': 10,
            'low_issues': 5,
            'iac_violations': 15,
            'cloud_issues': 20
        }
        
        # Compliance frameworks configuration
        self.compliance_frameworks = {
            'SOC2': {
                'name': 'SOC 2',
                'categories': ['access_control', 'encryption', 'monitoring', 'change_management'],
                'required_controls': ['password_policy', 'encryption_at_rest', 'access_logging']
            },
            'PCI-DSS': {
                'name': 'PCI DSS',
                'categories': ['network_security', 'encryption', 'access_control', 'monitoring'],
                'required_controls': ['strong_cryptography', 'secure_protocols', 'access_restrictions']
            },
            'GDPR': {
                'name': 'GDPR',
                'categories': ['data_protection', 'privacy', 'consent', 'breach_notification'],
                'required_controls': ['data_encryption', 'access_controls', 'audit_logging']
            },
            'NIST': {
                'name': 'NIST Cybersecurity Framework',
                'categories': ['identify', 'protect', 'detect', 'respond', 'recover'],
                'required_controls': ['asset_management', 'access_control', 'data_security']
            }
        }
        
        # Analysis cache
        self.analysis_cache = {}
        
        # Statistics
        self.stats = {
            'analyses_performed': 0,
            'total_findings': 0,
            'secrets_detected': 0,
            'config_issues_found': 0,
            'compliance_violations': 0,
            'average_analysis_time': 0.0
        }
    
    async def perform_comprehensive_analysis(self, config: ConfigurationSecurityConfiguration) -> ConfigurationSecurityResult:
        """Perform comprehensive configuration security analysis."""
        
        analysis_start_time = time.time()
        analysis_id = f"config_security_{int(analysis_start_time)}"
        
        logger.info(f"Starting comprehensive configuration security analysis: {analysis_id}")
        logger.info(f"Project: {config.project_path}")
        
        try:
            # Initialize result structure
            result = ConfigurationSecurityResult(
                analysis_id=analysis_id,
                project_path=str(config.project_path),
                analysis_time=analysis_start_time,
                analysis_duration=0.0,
                config_analysis_result=None,
                secrets_analysis_result=None,
                iac_analysis_results=[],
                cloud_config_results=[],
                total_findings=0,
                critical_findings=0,
                high_findings=0,
                medium_findings=0,
                low_findings=0,
                secrets_found=0,
                misconfigurations_found=0,
                iac_violations=0,
                cloud_security_issues=0,
                overall_risk_score=0.0,
                risk_level="unknown",
                critical_issues=[],
                compliance_status={},
                compliance_violations=[],
                findings_by_category={},
                findings_by_severity={},
                findings_by_file_type={},
                immediate_actions=[],
                security_recommendations=[],
                remediation_priorities=[],
                files_analyzed=0,
                lines_analyzed=0,
                config_files_found=0,
                secret_patterns_matched=0,
                configuration=config,
                orchestrator_version="1.0.0"
            )
            
            # Execute analysis components
            if self.orchestration_config['parallel_analysis']:
                await self._execute_parallel_analysis(config, result)
            else:
                await self._execute_sequential_analysis(config, result)
            
            # Aggregate and correlate results
            await self._aggregate_results(result)
            
            # Perform risk assessment
            await self._assess_risks(result)
            
            # Validate compliance
            await self._validate_compliance(result, config)
            
            # Generate recommendations
            await self._generate_recommendations(result)
            
            # Export results if configured
            if config.output_directory:
                await self._export_results(result, config)
            
            # Finalize result
            result.analysis_duration = time.time() - analysis_start_time
            
            # Update statistics
            self._update_statistics(result)
            
            logger.info(f"Configuration security analysis completed: {analysis_id} "
                       f"({result.total_findings} findings, {result.secrets_found} secrets, "
                       f"risk level: {result.risk_level})")
            
            return result
            
        except Exception as e:
            logger.error(f"Configuration security analysis failed: {analysis_id} - {str(e)}")
            raise
    
    async def _execute_parallel_analysis(self, config: ConfigurationSecurityConfiguration, 
                                        result: ConfigurationSecurityResult):
        """Execute analysis components in parallel."""
        
        tasks = []
        
        # Configuration analysis
        if config.enable_config_analysis:
            tasks.append(self._run_config_analysis(config, result))
        
        # Secrets detection
        if config.enable_secrets_detection:
            tasks.append(self._run_secrets_analysis(config, result))
        
        # IaC analysis
        if config.enable_iac_analysis:
            tasks.append(self._run_iac_analysis(config, result))
        
        # Cloud configuration analysis
        if config.enable_cloud_config_analysis:
            tasks.append(self._run_cloud_config_analysis(config, result))
        
        # Execute all tasks
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.orchestration_config['analysis_timeout']
            )
        except asyncio.TimeoutError:
            logger.warning("Some analysis components timed out")
    
    async def _execute_sequential_analysis(self, config: ConfigurationSecurityConfiguration, 
                                          result: ConfigurationSecurityResult):
        """Execute analysis components sequentially."""
        
        if config.enable_config_analysis:
            await self._run_config_analysis(config, result)
        
        if config.enable_secrets_detection:
            await self._run_secrets_analysis(config, result)
        
        if config.enable_iac_analysis:
            await self._run_iac_analysis(config, result)
        
        if config.enable_cloud_config_analysis:
            await self._run_cloud_config_analysis(config, result)
    
    async def _run_config_analysis(self, config: ConfigurationSecurityConfiguration, 
                                  result: ConfigurationSecurityResult):
        """Run configuration file analysis."""
        
        logger.info("Running configuration file analysis")
        
        try:
            # Configure analyzer
            self.config_analyzer.analysis_config.update({
                'recursive_scan': config.recursive_scan,
                'include_hidden_files': config.include_hidden_files,
                'max_file_size': config.max_file_size,
                'max_depth': config.max_depth
            })
            
            # Run analysis
            config_result = await self.config_analyzer.analyze_configurations(config.project_path)
            result.config_analysis_result = config_result
            
            logger.info(f"Configuration analysis completed: {config_result.total_findings} findings")
            
        except Exception as e:
            logger.error(f"Configuration analysis failed: {str(e)}")
    
    async def _run_secrets_analysis(self, config: ConfigurationSecurityConfiguration, 
                                   result: ConfigurationSecurityResult):
        """Run secrets detection analysis."""
        
        logger.info("Running secrets detection analysis")
        
        try:
            # Gather file contents
            file_contents = await self._gather_file_contents(config.project_path, config)
            
            # Configure detector
            self.secrets_detector.detection_config.update({
                'confidence_threshold': config.secrets_confidence_threshold
            })
            
            # Run analysis
            secrets_result = await self.secrets_detector.analyze_project_secrets(file_contents)
            result.secrets_analysis_result = secrets_result
            
            logger.info(f"Secrets analysis completed: {secrets_result.total_secrets_found} secrets found")
            
        except Exception as e:
            logger.error(f"Secrets analysis failed: {str(e)}")
    
    async def _run_iac_analysis(self, config: ConfigurationSecurityConfiguration, 
                               result: ConfigurationSecurityResult):
        """Run Infrastructure as Code analysis."""
        
        logger.info("Running IaC security analysis")
        
        try:
            # Find IaC files
            iac_files = await self._find_iac_files(config.project_path)
            
            iac_results = []
            for iac_file in iac_files:
                iac_result = await self._analyze_iac_file(iac_file)
                if iac_result:
                    iac_results.append(iac_result)
            
            result.iac_analysis_results = iac_results
            
            logger.info(f"IaC analysis completed: {len(iac_results)} files analyzed")
            
        except Exception as e:
            logger.error(f"IaC analysis failed: {str(e)}")
    
    async def _run_cloud_config_analysis(self, config: ConfigurationSecurityConfiguration, 
                                        result: ConfigurationSecurityResult):
        """Run cloud configuration analysis."""
        
        logger.info("Running cloud configuration analysis")
        
        try:
            # Find cloud config files
            cloud_files = await self._find_cloud_config_files(config.project_path)
            
            cloud_results = []
            for cloud_file in cloud_files:
                cloud_result = await self._analyze_cloud_config_file(cloud_file)
                if cloud_result:
                    cloud_results.append(cloud_result)
            
            result.cloud_config_results = cloud_results
            
            logger.info(f"Cloud config analysis completed: {len(cloud_results)} files analyzed")
            
        except Exception as e:
            logger.error(f"Cloud config analysis failed: {str(e)}")
    
    async def _gather_file_contents(self, project_path: Path, 
                                   config: ConfigurationSecurityConfiguration) -> Dict[str, str]:
        """Gather file contents for analysis."""
        
        file_contents = {}
        
        def should_include_file(file_path: Path) -> bool:
            if file_path.stat().st_size > config.max_file_size:
                return False
            
            if not config.include_hidden_files and file_path.name.startswith('.'):
                return False
            
            # Include text files that might contain secrets
            text_extensions = {'.txt', '.md', '.json', '.yaml', '.yml', '.toml', 
                             '.ini', '.cfg', '.conf', '.env', '.properties', '.xml'}
            
            return (file_path.suffix.lower() in text_extensions or 
                    file_path.name.lower() in ['dockerfile', 'makefile', 'readme'])
        
        if config.recursive_scan:
            for file_path in project_path.rglob('*'):
                if file_path.is_file() and should_include_file(file_path):
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        file_contents[str(file_path)] = content
                    except Exception as e:
                        logger.warning(f"Could not read file {file_path}: {str(e)}")
        else:
            for file_path in project_path.iterdir():
                if file_path.is_file() and should_include_file(file_path):
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        file_contents[str(file_path)] = content
                    except Exception as e:
                        logger.warning(f"Could not read file {file_path}: {str(e)}")
        
        return file_contents
    
    async def _find_iac_files(self, project_path: Path) -> List[Path]:
        """Find Infrastructure as Code files."""
        
        iac_patterns = [
            '*.tf',           # Terraform
            '*.tfvars',       # Terraform variables
            '*.yml',          # Ansible/K8s
            '*.yaml',         # Ansible/K8s
            'Dockerfile',     # Docker
            'docker-compose.yml',
            'docker-compose.yaml',
            '*.json',         # CloudFormation/ARM
            '*.template',     # CloudFormation
            'Pulumi.yaml',    # Pulumi
            'serverless.yml', # Serverless Framework
            'serverless.yaml'
        ]
        
        iac_files = []
        
        for pattern in iac_patterns:
            if '*' in pattern:
                for file_path in project_path.rglob(pattern):
                    if file_path.is_file():
                        iac_files.append(file_path)
            else:
                for file_path in project_path.rglob(pattern):
                    if file_path.is_file():
                        iac_files.append(file_path)
        
        return iac_files
    
    async def _find_cloud_config_files(self, project_path: Path) -> List[Path]:
        """Find cloud configuration files."""
        
        cloud_patterns = [
            '.aws/config',
            '.aws/credentials',
            'gcp-service-account.json',
            'azure-credentials.json',
            'k8s-config.yaml',
            'kubeconfig',
            'helm-values.yaml',
            'skaffold.yaml'
        ]
        
        cloud_files = []
        
        for pattern in cloud_patterns:
            for file_path in project_path.rglob(pattern):
                if file_path.is_file():
                    cloud_files.append(file_path)
        
        return cloud_files
    
    async def _analyze_iac_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze Infrastructure as Code file."""
        
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # Simulate IaC analysis (would use specialized tools like tfsec, checkov, etc.)
            violations = []
            
            # Check for common IaC security issues
            if file_path.suffix == '.tf':
                violations.extend(self._check_terraform_security(content))
            elif file_path.name.lower().startswith('dockerfile'):
                violations.extend(self._check_dockerfile_security(content))
            elif file_path.suffix in ['.yml', '.yaml']:
                violations.extend(self._check_kubernetes_security(content))
            
            return {
                'file_path': str(file_path),
                'file_type': 'terraform' if file_path.suffix == '.tf' else 'kubernetes',
                'violations': violations,
                'risk_score': len([v for v in violations if v['severity'] in ['critical', 'high']]) * 10
            }
            
        except Exception as e:
            logger.error(f"Error analyzing IaC file {file_path}: {str(e)}")
            return None
    
    def _check_terraform_security(self, content: str) -> List[Dict[str, Any]]:
        """Check Terraform configuration for security issues."""
        
        violations = []
        
        # Check for hardcoded secrets
        if re.search(r'password\s*=\s*"[^"]{8,}"', content, re.IGNORECASE):
            violations.append({
                'rule': 'hardcoded_password',
                'severity': 'critical',
                'message': 'Hardcoded password found in Terraform configuration',
                'remediation': 'Use variables or AWS Secrets Manager'
            })
        
        # Check for public S3 buckets
        if re.search(r'acl\s*=\s*"public-read"', content, re.IGNORECASE):
            violations.append({
                'rule': 'public_s3_bucket',
                'severity': 'high',
                'message': 'S3 bucket configured with public read access',
                'remediation': 'Use private ACL and configure bucket policies'
            })
        
        # Check for unencrypted resources
        if 'aws_db_instance' in content and 'encrypted' not in content:
            violations.append({
                'rule': 'unencrypted_database',
                'severity': 'high',
                'message': 'RDS instance not configured for encryption',
                'remediation': 'Enable encryption at rest for RDS instances'
            })
        
        return violations
    
    def _check_dockerfile_security(self, content: str) -> List[Dict[str, Any]]:
        """Check Dockerfile for security issues."""
        
        violations = []
        
        # Check for root user
        if not re.search(r'USER\s+(?!root)', content, re.IGNORECASE):
            violations.append({
                'rule': 'dockerfile_root_user',
                'severity': 'high',
                'message': 'Container runs as root user',
                'remediation': 'Create and use a non-root user'
            })
        
        # Check for ADD instead of COPY
        if re.search(r'^ADD\s+', content, re.MULTILINE):
            violations.append({
                'rule': 'dockerfile_add_usage',
                'severity': 'medium',
                'message': 'ADD instruction used instead of COPY',
                'remediation': 'Use COPY instead of ADD for better security'
            })
        
        # Check for latest tag
        if re.search(r'FROM\s+\w+:latest', content, re.IGNORECASE):
            violations.append({
                'rule': 'dockerfile_latest_tag',
                'severity': 'medium',
                'message': 'Base image uses latest tag',
                'remediation': 'Use specific version tags for base images'
            })
        
        return violations
    
    def _check_kubernetes_security(self, content: str) -> List[Dict[str, Any]]:
        """Check Kubernetes configuration for security issues."""
        
        violations = []
        
        # Check for privileged containers
        if re.search(r'privileged:\s*true', content, re.IGNORECASE):
            violations.append({
                'rule': 'k8s_privileged_container',
                'severity': 'critical',
                'message': 'Container configured to run in privileged mode',
                'remediation': 'Remove privileged: true or use specific capabilities'
            })
        
        # Check for host network
        if re.search(r'hostNetwork:\s*true', content, re.IGNORECASE):
            violations.append({
                'rule': 'k8s_host_network',
                'severity': 'high',
                'message': 'Pod configured to use host network',
                'remediation': 'Remove hostNetwork: true unless absolutely necessary'
            })
        
        # Check for default namespace
        if 'namespace:' not in content and 'kind: Namespace' not in content:
            violations.append({
                'rule': 'k8s_default_namespace',
                'severity': 'medium',
                'message': 'Resource deployed to default namespace',
                'remediation': 'Use dedicated namespaces for applications'
            })
        
        return violations
    
    async def _analyze_cloud_config_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze cloud configuration file."""
        
        try:
            content = file_path.read_text(encoding='utf-8')
            
            issues = []
            
            # Check for hardcoded credentials
            if re.search(r'aws_access_key_id\s*=\s*AKIA[0-9A-Z]{16}', content):
                issues.append({
                    'type': 'hardcoded_credentials',
                    'severity': 'critical',
                    'message': 'AWS access key found in configuration file'
                })
            
            # Check for insecure configurations
            if 'ssl_verify = false' in content.lower():
                issues.append({
                    'type': 'insecure_ssl',
                    'severity': 'high',
                    'message': 'SSL verification disabled'
                })
            
            return {
                'file_path': str(file_path),
                'file_type': 'cloud_config',
                'issues': issues,
                'risk_score': len([i for i in issues if i['severity'] in ['critical', 'high']]) * 15
            }
            
        except Exception as e:
            logger.error(f"Error analyzing cloud config file {file_path}: {str(e)}")
            return None
    
    async def _aggregate_results(self, result: ConfigurationSecurityResult):
        """Aggregate results from all analysis components."""
        
        total_findings = 0
        critical_findings = 0
        high_findings = 0
        medium_findings = 0
        low_findings = 0
        
        findings_by_category = {}
        findings_by_severity = {}
        findings_by_file_type = {}
        
        # Aggregate configuration analysis results
        if result.config_analysis_result:
            config_result = result.config_analysis_result
            total_findings += config_result.total_findings
            critical_findings += config_result.critical_findings
            high_findings += config_result.high_findings
            medium_findings += config_result.medium_findings
            low_findings += config_result.low_findings
            
            result.misconfigurations_found = config_result.total_findings
            result.files_analyzed = config_result.total_files_analyzed
            
            # Merge category counts
            for category, count in config_result.findings_by_category.items():
                findings_by_category[category] = findings_by_category.get(category, 0) + count
            
            # Merge file type counts
            for file_type, count in config_result.findings_by_file_type.items():
                findings_by_file_type[file_type] = findings_by_file_type.get(file_type, 0) + count
        
        # Aggregate secrets analysis results
        if result.secrets_analysis_result:
            secrets_result = result.secrets_analysis_result
            result.secrets_found = secrets_result.total_secrets_found
            result.secret_patterns_matched = secrets_result.patterns_matched
            result.lines_analyzed = secrets_result.lines_scanned
            
            # Count secrets by severity
            for secret in secrets_result.secret_matches:
                if secret.confidence >= 0.9:
                    critical_findings += 1
                elif secret.confidence >= 0.8:
                    high_findings += 1
                elif secret.confidence >= 0.7:
                    medium_findings += 1
                else:
                    low_findings += 1
                
                total_findings += 1
            
            findings_by_category['secrets'] = secrets_result.total_secrets_found
        
        # Aggregate IaC analysis results
        iac_violations = 0
        for iac_result in result.iac_analysis_results:
            violations = iac_result.get('violations', [])
            iac_violations += len(violations)
            
            for violation in violations:
                severity = violation.get('severity', 'medium')
                if severity == 'critical':
                    critical_findings += 1
                elif severity == 'high':
                    high_findings += 1
                elif severity == 'medium':
                    medium_findings += 1
                else:
                    low_findings += 1
                
                total_findings += 1
        
        result.iac_violations = iac_violations
        findings_by_category['iac'] = iac_violations
        
        # Aggregate cloud config results
        cloud_issues = 0
        for cloud_result in result.cloud_config_results:
            issues = cloud_result.get('issues', [])
            cloud_issues += len(issues)
            
            for issue in issues:
                severity = issue.get('severity', 'medium')
                if severity == 'critical':
                    critical_findings += 1
                elif severity == 'high':
                    high_findings += 1
                elif severity == 'medium':
                    medium_findings += 1
                else:
                    low_findings += 1
                
                total_findings += 1
        
        result.cloud_security_issues = cloud_issues
        findings_by_category['cloud_config'] = cloud_issues
        
        # Update result totals
        result.total_findings = total_findings
        result.critical_findings = critical_findings
        result.high_findings = high_findings
        result.medium_findings = medium_findings
        result.low_findings = low_findings
        
        result.findings_by_category = findings_by_category
        result.findings_by_severity = {
            'critical': critical_findings,
            'high': high_findings,
            'medium': medium_findings,
            'low': low_findings
        }
        result.findings_by_file_type = findings_by_file_type
        
        # Count config files
        result.config_files_found = len([f for f in result.config_analysis_result.configuration_files]) if result.config_analysis_result else 0
    
    async def _assess_risks(self, result: ConfigurationSecurityResult):
        """Assess overall security risks."""
        
        # Calculate risk score
        risk_score = 0.0
        
        risk_score += result.critical_findings * self.risk_weights['critical_secrets']
        risk_score += result.high_findings * self.risk_weights['high_secrets']
        risk_score += result.medium_findings * self.risk_weights['medium_issues']
        risk_score += result.low_findings * self.risk_weights['low_issues']
        risk_score += result.iac_violations * self.risk_weights['iac_violations']
        risk_score += result.cloud_security_issues * self.risk_weights['cloud_issues']
        
        result.overall_risk_score = min(100.0, risk_score)
        
        # Determine risk level
        if result.overall_risk_score >= 80:
            result.risk_level = "critical"
        elif result.overall_risk_score >= 60:
            result.risk_level = "high"
        elif result.overall_risk_score >= 40:
            result.risk_level = "medium"
        else:
            result.risk_level = "low"
        
        # Identify critical issues
        critical_issues = []
        
        if result.critical_findings > 0:
            critical_issues.append(f"{result.critical_findings} critical security findings")
        
        if result.secrets_found > 0:
            critical_issues.append(f"{result.secrets_found} hardcoded secrets detected")
        
        if result.iac_violations > 5:
            critical_issues.append(f"{result.iac_violations} Infrastructure as Code violations")
        
        if result.cloud_security_issues > 0:
            critical_issues.append(f"{result.cloud_security_issues} cloud configuration issues")
        
        result.critical_issues = critical_issues
    
    async def _validate_compliance(self, result: ConfigurationSecurityResult, 
                                  config: ConfigurationSecurityConfiguration):
        """Validate compliance with security frameworks."""
        
        compliance_status = {}
        compliance_violations = []
        
        for framework in config.compliance_frameworks:
            if framework in self.compliance_frameworks:
                framework_info = self.compliance_frameworks[framework]
                
                # Simulate compliance validation
                violations = 0
                
                # Check for framework-specific violations
                if framework == 'SOC2':
                    if result.secrets_found > 0:
                        violations += result.secrets_found
                        compliance_violations.append({
                            'framework': framework,
                            'control': 'CC6.1 - Logical Access',
                            'violation': 'Hardcoded secrets detected',
                            'severity': 'high'
                        })
                
                elif framework == 'PCI-DSS':
                    if result.critical_findings > 0:
                        violations += result.critical_findings
                        compliance_violations.append({
                            'framework': framework,
                            'control': 'Requirement 3 - Protect stored cardholder data',
                            'violation': 'Critical security misconfigurations',
                            'severity': 'critical'
                        })
                
                elif framework == 'GDPR':
                    if result.secrets_found > 0 or result.critical_findings > 0:
                        violations += 1
                        compliance_violations.append({
                            'framework': framework,
                            'control': 'Article 32 - Security of processing',
                            'violation': 'Inadequate security measures',
                            'severity': 'high'
                        })
                
                # Determine compliance status
                if violations == 0:
                    compliance_status[framework] = "compliant"
                elif violations <= 3:
                    compliance_status[framework] = "partially_compliant"
                else:
                    compliance_status[framework] = "non_compliant"
        
        result.compliance_status = compliance_status
        result.compliance_violations = compliance_violations
    
    async def _generate_recommendations(self, result: ConfigurationSecurityResult):
        """Generate actionable recommendations."""
        
        immediate_actions = []
        security_recommendations = []
        remediation_priorities = []
        
        # Immediate actions for critical issues
        if result.critical_findings > 0:
            immediate_actions.append("Address critical configuration security findings immediately")
        
        if result.secrets_found > 0:
            immediate_actions.append(f"Remove {result.secrets_found} hardcoded secrets from configuration files")
        
        if result.iac_violations > 0:
            immediate_actions.append("Fix Infrastructure as Code security violations")
        
        if result.cloud_security_issues > 0:
            immediate_actions.append("Resolve cloud configuration security issues")
        
        # Security recommendations
        security_recommendations.extend([
            "Implement configuration security scanning in CI/CD pipeline",
            "Use environment variables and secret management systems",
            "Regular security review of configuration changes",
            "Implement least privilege principles in all configurations",
            "Enable configuration drift detection and monitoring",
            "Establish configuration security policies and standards"
        ])
        
        if result.iac_violations > 0:
            security_recommendations.extend([
                "Implement Infrastructure as Code security scanning",
                "Use policy as code for infrastructure compliance",
                "Regular security audits of infrastructure templates"
            ])
        
        # Remediation priorities
        if result.secrets_analysis_result:
            for secret in result.secrets_analysis_result.critical_secrets:
                remediation_priorities.append({
                    'priority': 'critical',
                    'type': 'secret_removal',
                    'description': f"Remove {secret.secret_type.value} from {secret.file_path}",
                    'effort': 'low',
                    'impact': 'high'
                })
        
        if result.config_analysis_result:
            critical_config_findings = [f for f in result.config_analysis_result.configuration_files 
                                       for finding in f.findings if finding.severity.value == 'critical']
            
            for i, finding in enumerate(critical_config_findings[:5]):  # Top 5
                remediation_priorities.append({
                    'priority': 'high',
                    'type': 'configuration_fix',
                    'description': finding.description,
                    'effort': 'medium',
                    'impact': 'high'
                })
        
        result.immediate_actions = immediate_actions
        result.security_recommendations = security_recommendations
        result.remediation_priorities = remediation_priorities
    
    async def _export_results(self, result: ConfigurationSecurityResult, 
                             config: ConfigurationSecurityConfiguration):
        """Export analysis results."""
        
        output_dir = config.output_directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for export_format in config.export_formats:
            if export_format == 'json':
                await self._export_json(result, output_dir)
            elif export_format == 'sarif':
                await self._export_sarif(result, output_dir)
            elif export_format == 'csv':
                await self._export_csv(result, output_dir)
    
    async def _export_json(self, result: ConfigurationSecurityResult, output_dir: Path):
        """Export results in JSON format."""
        
        output_file = output_dir / f"config_security_report_{result.analysis_id}.json"
        
        # Create exportable result (excluding complex objects)
        export_data = {
            'analysis_id': result.analysis_id,
            'project_path': result.project_path,
            'analysis_time': result.analysis_time,
            'analysis_duration': result.analysis_duration,
            'summary': {
                'total_findings': result.total_findings,
                'critical_findings': result.critical_findings,
                'high_findings': result.high_findings,
                'medium_findings': result.medium_findings,
                'low_findings': result.low_findings,
                'secrets_found': result.secrets_found,
                'misconfigurations_found': result.misconfigurations_found,
                'iac_violations': result.iac_violations,
                'cloud_security_issues': result.cloud_security_issues
            },
            'risk_assessment': {
                'overall_risk_score': result.overall_risk_score,
                'risk_level': result.risk_level,
                'critical_issues': result.critical_issues
            },
            'compliance': {
                'status': result.compliance_status,
                'violations': result.compliance_violations
            },
            'recommendations': {
                'immediate_actions': result.immediate_actions,
                'security_recommendations': result.security_recommendations,
                'remediation_priorities': result.remediation_priorities
            },
            'statistics': {
                'files_analyzed': result.files_analyzed,
                'lines_analyzed': result.lines_analyzed,
                'config_files_found': result.config_files_found,
                'secret_patterns_matched': result.secret_patterns_matched
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report exported to: {output_file}")
    
    async def _export_sarif(self, result: ConfigurationSecurityResult, output_dir: Path):
        """Export results in SARIF format."""
        
        # SARIF (Static Analysis Results Interchange Format) export
        # This would generate a proper SARIF document
        logger.info("SARIF export not implemented yet")
    
    async def _export_csv(self, result: ConfigurationSecurityResult, output_dir: Path):
        """Export results in CSV format."""
        
        # CSV export for findings
        logger.info("CSV export not implemented yet")
    
    def _update_statistics(self, result: ConfigurationSecurityResult):
        """Update orchestrator statistics."""
        
        self.stats['analyses_performed'] += 1
        self.stats['total_findings'] += result.total_findings
        self.stats['secrets_detected'] += result.secrets_found
        self.stats['config_issues_found'] += result.misconfigurations_found
        self.stats['compliance_violations'] += len(result.compliance_violations)
        
        # Update average analysis time
        if self.stats['analyses_performed'] == 1:
            self.stats['average_analysis_time'] = result.analysis_duration
        else:
            current_avg = self.stats['average_analysis_time']
            total_analyses = self.stats['analyses_performed']
            self.stats['average_analysis_time'] = (
                (current_avg * (total_analyses - 1) + result.analysis_duration) / total_analyses
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        
        return dict(self.stats)
