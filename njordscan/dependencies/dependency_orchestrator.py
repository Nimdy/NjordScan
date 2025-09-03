"""
Dependency Security Orchestrator

Coordinates all dependency security analysis components including dependency analysis,
SBOM generation, vulnerability scanning, supply chain analysis, and license compliance.
"""

import asyncio
import time
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

from .dependency_analyzer import DependencyAnalyzer, DependencyGraph
from .sbom_generator import SBOMGenerator, SBOMFormat, SBOM

logger = logging.getLogger(__name__)

@dataclass
class DependencySecurityConfiguration:
    """Configuration for dependency security analysis."""
    project_path: Path
    project_info: Dict[str, Any]
    
    # Analysis scope
    include_dev_dependencies: bool = True
    include_transitive_dependencies: bool = True
    max_dependency_depth: int = 10
    
    # Security analysis
    vulnerability_scanning: bool = True
    supply_chain_analysis: bool = True
    license_compliance_check: bool = True
    outdated_package_detection: bool = True
    
    # SBOM generation
    generate_sbom: bool = True
    sbom_formats: List[SBOMFormat] = None
    
    # Risk assessment
    risk_threshold: str = "medium"  # low, medium, high, critical
    fail_on_high_risk: bool = False
    
    # Output configuration
    output_directory: Optional[Path] = None
    
    def __post_init__(self):
        if self.sbom_formats is None:
            self.sbom_formats = [SBOMFormat.CYCLONE_DX_JSON]

@dataclass
class DependencySecurityResult:
    """Comprehensive dependency security analysis result."""
    analysis_id: str
    project_path: str
    analysis_time: float
    analysis_duration: float
    
    # Core analysis results
    dependency_graph: DependencyGraph
    sboms: Dict[SBOMFormat, SBOM]
    
    # Security findings
    vulnerability_summary: Dict[str, int]
    supply_chain_risks: List[Dict[str, Any]]
    license_issues: List[Dict[str, Any]]
    outdated_packages: List[Dict[str, Any]]
    
    # Risk assessment
    overall_risk_score: float  # 0-100
    risk_level: str
    critical_issues: List[str]
    
    # Compliance status
    license_compliance_status: str
    policy_violations: List[Dict[str, Any]]
    
    # Recommendations
    immediate_actions: List[str]
    security_recommendations: List[str]
    upgrade_recommendations: List[Dict[str, Any]]
    
    # Statistics
    total_dependencies: int
    direct_dependencies: int
    transitive_dependencies: int
    vulnerable_dependencies: int
    outdated_dependencies_count: int
    
    # Metadata
    configuration: DependencySecurityConfiguration
    orchestrator_version: str

class DependencySecurityOrchestrator:
    """Orchestrates comprehensive dependency security analysis."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize analysis components
        self.dependency_analyzer = DependencyAnalyzer(config.get('dependency_analysis', {}))
        self.sbom_generator = SBOMGenerator(config.get('sbom_generation', {}))
        
        # Orchestration configuration
        self.orchestration_config = {
            'parallel_analysis': self.config.get('parallel_analysis', True),
            'analysis_timeout': self.config.get('analysis_timeout', 1800),  # 30 minutes
            'cache_results': self.config.get('cache_results', True),
            'detailed_reporting': self.config.get('detailed_reporting', True)
        }
        
        # Risk assessment configuration
        self.risk_config = {
            'critical_vuln_weight': 40,
            'high_vuln_weight': 25,
            'medium_vuln_weight': 15,
            'low_vuln_weight': 5,
            'outdated_weight': 10,
            'supply_chain_weight': 20,
            'license_weight': 15
        }
        
        # License policies
        self.license_policies = {
            'approved_licenses': [
                'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC',
                'MPL-2.0', 'LGPL-2.1', 'LGPL-3.0', 'CC0-1.0'
            ],
            'forbidden_licenses': [
                'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'
            ],
            'review_required_licenses': [
                'EPL-2.0', 'EUPL-1.2', 'CDDL-1.0'
            ]
        }
        
        # Analysis cache
        self.analysis_cache = {}
        
        # Statistics
        self.stats = {
            'analyses_performed': 0,
            'vulnerabilities_found': 0,
            'sboms_generated': 0,
            'policy_violations_detected': 0,
            'average_analysis_time': 0.0
        }
    
    async def perform_comprehensive_analysis(self, config: DependencySecurityConfiguration) -> DependencySecurityResult:
        """Perform comprehensive dependency security analysis."""
        
        analysis_start_time = time.time()
        analysis_id = f"dep_security_{int(analysis_start_time)}"
        
        logger.info(f"Starting comprehensive dependency security analysis: {analysis_id}")
        logger.info(f"Project: {config.project_path}")
        
        try:
            # Initialize result structure
            result = DependencySecurityResult(
                analysis_id=analysis_id,
                project_path=str(config.project_path),
                analysis_time=analysis_start_time,
                analysis_duration=0.0,
                dependency_graph=None,
                sboms={},
                vulnerability_summary={},
                supply_chain_risks=[],
                license_issues=[],
                outdated_packages=[],
                overall_risk_score=0.0,
                risk_level="unknown",
                critical_issues=[],
                license_compliance_status="unknown",
                policy_violations=[],
                immediate_actions=[],
                security_recommendations=[],
                upgrade_recommendations=[],
                total_dependencies=0,
                direct_dependencies=0,
                transitive_dependencies=0,
                vulnerable_dependencies=0,
                outdated_dependencies_count=0,
                configuration=config,
                orchestrator_version="1.0.0"
            )
            
            # Check cache first
            cache_key = self._generate_cache_key(config)
            if self.orchestration_config['cache_results'] and cache_key in self.analysis_cache:
                cached_result = self.analysis_cache[cache_key]
                if time.time() - cached_result.analysis_time < 3600:  # 1 hour cache
                    logger.info("Returning cached analysis result")
                    return cached_result
            
            # Step 1: Analyze dependencies
            logger.info("Step 1: Analyzing project dependencies")
            dependency_graph = await self._analyze_dependencies(config)
            result.dependency_graph = dependency_graph
            
            # Step 2: Generate SBOMs
            if config.generate_sbom:
                logger.info("Step 2: Generating Software Bill of Materials (SBOM)")
                sboms = await self._generate_sboms(dependency_graph, config)
                result.sboms = sboms
            
            # Step 3: Perform security analysis
            logger.info("Step 3: Performing security analysis")
            await self._perform_security_analysis(result, config)
            
            # Step 4: Assess risks and compliance
            logger.info("Step 4: Assessing risks and compliance")
            await self._assess_risks_and_compliance(result, config)
            
            # Step 5: Generate recommendations
            logger.info("Step 5: Generating recommendations")
            await self._generate_recommendations(result)
            
            # Step 6: Export results if configured
            if config.output_directory:
                logger.info("Step 6: Exporting results")
                await self._export_results(result, config)
            
            # Finalize result
            result.analysis_duration = time.time() - analysis_start_time
            
            # Update statistics
            self._update_statistics(result)
            
            # Cache result
            if self.orchestration_config['cache_results']:
                self.analysis_cache[cache_key] = result
            
            logger.info(f"Dependency security analysis completed: {analysis_id} "
                       f"({result.total_dependencies} dependencies, "
                       f"{result.vulnerable_dependencies} vulnerable, "
                       f"risk level: {result.risk_level})")
            
            return result
            
        except Exception as e:
            logger.error(f"Dependency security analysis failed: {analysis_id} - {str(e)}")
            raise
    
    async def _analyze_dependencies(self, config: DependencySecurityConfiguration) -> DependencyGraph:
        """Analyze project dependencies."""
        
        # Configure dependency analyzer
        analyzer_config = {
            'include_dev_dependencies': config.include_dev_dependencies,
            'enable_transitive_analysis': config.include_transitive_dependencies,
            'max_depth': config.max_dependency_depth,
            'vulnerability_check': config.vulnerability_scanning,
            'supply_chain_analysis': config.supply_chain_analysis,
            'outdated_check': config.outdated_package_detection
        }
        
        self.dependency_analyzer.analysis_config.update(analyzer_config)
        
        # Perform analysis
        dependency_graph = await self.dependency_analyzer.analyze_project_dependencies(config.project_path)
        
        return dependency_graph
    
    async def _generate_sboms(self, dependency_graph: DependencyGraph, 
                            config: DependencySecurityConfiguration) -> Dict[SBOMFormat, SBOM]:
        """Generate Software Bill of Materials."""
        
        sboms = await self.sbom_generator.generate_sbom(
            dependency_graph, 
            config.project_info,
            config.sbom_formats
        )
        
        return sboms
    
    async def _perform_security_analysis(self, result: DependencySecurityResult, 
                                       config: DependencySecurityConfiguration):
        """Perform comprehensive security analysis."""
        
        dependency_graph = result.dependency_graph
        
        # Analyze vulnerabilities
        vulnerability_summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': 0
        }
        
        vulnerable_deps = 0
        
        for dep_key, dep_info in dependency_graph.all_dependencies.items():
            if dep_info.known_vulnerabilities:
                vulnerable_deps += 1
                for vuln in dep_info.known_vulnerabilities:
                    severity = vuln.get('severity', 'unknown').lower()
                    if severity in vulnerability_summary:
                        vulnerability_summary[severity] += 1
                        vulnerability_summary['total'] += 1
        
        result.vulnerability_summary = vulnerability_summary
        result.vulnerable_dependencies = vulnerable_deps
        
        # Analyze supply chain risks
        supply_chain_risks = []
        for dep_key, dep_info in dependency_graph.all_dependencies.items():
            risk_factors = []
            
            if len(dep_info.maintainers) < 2:
                risk_factors.append('Limited maintainers')
            
            if dep_info.download_count < 1000:
                risk_factors.append('Low adoption')
            
            if dep_info.age_days < 30:
                risk_factors.append('Very new package')
            
            if risk_factors:
                supply_chain_risks.append({
                    'package': dep_info.name,
                    'version': dep_info.version,
                    'risk_factors': risk_factors,
                    'risk_level': dep_info.risk_level
                })
        
        result.supply_chain_risks = supply_chain_risks
        
        # Analyze outdated packages
        outdated_packages = []
        outdated_count = 0
        
        for dep_key, dep_info in dependency_graph.all_dependencies.items():
            if dep_info.is_outdated:
                outdated_count += 1
                outdated_packages.append({
                    'package': dep_info.name,
                    'current_version': dep_info.version,
                    'latest_version': dep_info.latest_version,
                    'versions_behind': dep_info.version_behind
                })
        
        result.outdated_packages = outdated_packages
        result.outdated_dependencies_count = outdated_count
        
        # Update statistics
        result.total_dependencies = dependency_graph.total_dependencies
        result.direct_dependencies = dependency_graph.direct_dependencies
        result.transitive_dependencies = dependency_graph.transitive_dependencies
    
    async def _assess_risks_and_compliance(self, result: DependencySecurityResult, 
                                         config: DependencySecurityConfiguration):
        """Assess overall risks and compliance status."""
        
        # Calculate overall risk score
        risk_score = 100.0  # Start with perfect score
        
        # Deduct points for vulnerabilities
        vuln_summary = result.vulnerability_summary
        risk_score -= vuln_summary['critical'] * self.risk_config['critical_vuln_weight']
        risk_score -= vuln_summary['high'] * self.risk_config['high_vuln_weight']
        risk_score -= vuln_summary['medium'] * self.risk_config['medium_vuln_weight']
        risk_score -= vuln_summary['low'] * self.risk_config['low_vuln_weight']
        
        # Deduct points for outdated packages
        risk_score -= min(result.outdated_dependencies_count * 2, self.risk_config['outdated_weight'])
        
        # Deduct points for supply chain risks
        high_risk_supply_chain = len([r for r in result.supply_chain_risks if r['risk_level'] == 'high'])
        risk_score -= min(high_risk_supply_chain * 5, self.risk_config['supply_chain_weight'])
        
        # Ensure score is within bounds
        result.overall_risk_score = max(0.0, min(100.0, risk_score))
        
        # Determine risk level
        if result.overall_risk_score >= 80:
            result.risk_level = "low"
        elif result.overall_risk_score >= 60:
            result.risk_level = "medium"
        elif result.overall_risk_score >= 40:
            result.risk_level = "high"
        else:
            result.risk_level = "critical"
        
        # Identify critical issues
        critical_issues = []
        
        if vuln_summary['critical'] > 0:
            critical_issues.append(f"{vuln_summary['critical']} critical vulnerabilities found")
        
        if vuln_summary['high'] > 5:
            critical_issues.append(f"{vuln_summary['high']} high-severity vulnerabilities found")
        
        high_risk_packages = len([r for r in result.supply_chain_risks if r['risk_level'] in ['high', 'critical']])
        if high_risk_packages > 0:
            critical_issues.append(f"{high_risk_packages} high-risk packages in supply chain")
        
        result.critical_issues = critical_issues
        
        # Assess license compliance
        await self._assess_license_compliance(result)
    
    async def _assess_license_compliance(self, result: DependencySecurityResult):
        """Assess license compliance status."""
        
        license_issues = []
        policy_violations = []
        
        for dep_key, dep_info in result.dependency_graph.all_dependencies.items():
            if not dep_info.license:
                license_issues.append({
                    'package': dep_info.name,
                    'version': dep_info.version,
                    'issue': 'No license information available',
                    'severity': 'medium'
                })
                continue
            
            license_id = dep_info.license
            
            # Check against forbidden licenses
            if license_id in self.license_policies['forbidden_licenses']:
                policy_violations.append({
                    'package': dep_info.name,
                    'version': dep_info.version,
                    'license': license_id,
                    'violation_type': 'forbidden_license',
                    'severity': 'high'
                })
                license_issues.append({
                    'package': dep_info.name,
                    'version': dep_info.version,
                    'issue': f'Forbidden license: {license_id}',
                    'severity': 'high'
                })
            
            # Check against review required licenses
            elif license_id in self.license_policies['review_required_licenses']:
                license_issues.append({
                    'package': dep_info.name,
                    'version': dep_info.version,
                    'issue': f'License requires review: {license_id}',
                    'severity': 'medium'
                })
        
        result.license_issues = license_issues
        result.policy_violations = policy_violations
        
        # Determine compliance status
        if policy_violations:
            result.license_compliance_status = "non_compliant"
        elif license_issues:
            result.license_compliance_status = "review_required"
        else:
            result.license_compliance_status = "compliant"
    
    async def _generate_recommendations(self, result: DependencySecurityResult):
        """Generate actionable recommendations."""
        
        immediate_actions = []
        security_recommendations = []
        upgrade_recommendations = []
        
        # Immediate actions for critical issues
        if result.vulnerability_summary['critical'] > 0:
            immediate_actions.append("Address critical vulnerabilities immediately")
            immediate_actions.append("Review and patch affected packages")
        
        if result.policy_violations:
            immediate_actions.append("Resolve license policy violations")
        
        if result.risk_level == "critical":
            immediate_actions.append("Conduct emergency security review")
        
        # Security recommendations
        if result.vulnerability_summary['high'] > 0:
            security_recommendations.append("Prioritize high-severity vulnerability remediation")
        
        if result.supply_chain_risks:
            security_recommendations.append("Review supply chain risk factors")
            security_recommendations.append("Consider alternative packages for high-risk dependencies")
        
        if result.outdated_dependencies_count > result.total_dependencies * 0.3:
            security_recommendations.append("Implement regular dependency update schedule")
        
        security_recommendations.extend([
            "Enable automated vulnerability scanning in CI/CD",
            "Implement dependency pinning strategy",
            "Regular security audits of dependencies",
            "Monitor security advisories for used packages"
        ])
        
        # Upgrade recommendations
        for outdated_pkg in result.outdated_packages[:10]:  # Top 10 most outdated
            upgrade_recommendations.append({
                'package': outdated_pkg['package'],
                'current_version': outdated_pkg['current_version'],
                'recommended_version': outdated_pkg['latest_version'],
                'priority': 'high' if outdated_pkg['versions_behind'] > 5 else 'medium',
                'reason': 'Security and feature updates available'
            })
        
        result.immediate_actions = immediate_actions
        result.security_recommendations = security_recommendations
        result.upgrade_recommendations = upgrade_recommendations
    
    async def _export_results(self, result: DependencySecurityResult, 
                            config: DependencySecurityConfiguration):
        """Export analysis results to files."""
        
        output_dir = config.output_directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Export dependency graph as JSON
        dep_graph_file = output_dir / f"dependency_graph_{result.analysis_id}.json"
        with open(dep_graph_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(result.dependency_graph), f, indent=2, default=str)
        
        # Export SBOMs
        for format_type, sbom in result.sboms.items():
            sbom_file = output_dir / f"sbom_{result.analysis_id}.{format_type.value.split('_')[-1]}"
            await self.sbom_generator.export_sbom(sbom, format_type, sbom_file)
        
        # Export security report
        security_report = {
            'analysis_id': result.analysis_id,
            'analysis_time': result.analysis_time,
            'project_path': result.project_path,
            'risk_assessment': {
                'overall_risk_score': result.overall_risk_score,
                'risk_level': result.risk_level,
                'critical_issues': result.critical_issues
            },
            'vulnerability_summary': result.vulnerability_summary,
            'supply_chain_risks': result.supply_chain_risks,
            'license_compliance': {
                'status': result.license_compliance_status,
                'issues': result.license_issues,
                'policy_violations': result.policy_violations
            },
            'recommendations': {
                'immediate_actions': result.immediate_actions,
                'security_recommendations': result.security_recommendations,
                'upgrade_recommendations': result.upgrade_recommendations
            },
            'statistics': {
                'total_dependencies': result.total_dependencies,
                'vulnerable_dependencies': result.vulnerable_dependencies,
                'outdated_dependencies': result.outdated_dependencies_count
            }
        }
        
        security_report_file = output_dir / f"security_report_{result.analysis_id}.json"
        with open(security_report_file, 'w', encoding='utf-8') as f:
            json.dump(security_report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results exported to: {output_dir}")
    
    def _generate_cache_key(self, config: DependencySecurityConfiguration) -> str:
        """Generate cache key for analysis configuration."""
        
        key_data = {
            'project_path': str(config.project_path),
            'include_dev': config.include_dev_dependencies,
            'include_transitive': config.include_transitive_dependencies,
            'max_depth': config.max_dependency_depth,
            'vuln_scan': config.vulnerability_scanning,
            'supply_chain': config.supply_chain_analysis
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _update_statistics(self, result: DependencySecurityResult):
        """Update orchestrator statistics."""
        
        self.stats['analyses_performed'] += 1
        self.stats['vulnerabilities_found'] += result.vulnerability_summary['total']
        self.stats['sboms_generated'] += len(result.sboms)
        self.stats['policy_violations_detected'] += len(result.policy_violations)
        
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
    
    async def validate_project_compliance(self, config: DependencySecurityConfiguration) -> Dict[str, Any]:
        """Validate project compliance against security policies."""
        
        result = await self.perform_comprehensive_analysis(config)
        
        compliance_result = {
            'compliant': True,
            'risk_level': result.risk_level,
            'violations': [],
            'recommendations': result.immediate_actions
        }
        
        # Check risk threshold
        risk_levels = ['low', 'medium', 'high', 'critical']
        threshold_index = risk_levels.index(config.risk_threshold)
        result_index = risk_levels.index(result.risk_level)
        
        if result_index > threshold_index:
            compliance_result['compliant'] = False
            compliance_result['violations'].append(f"Risk level {result.risk_level} exceeds threshold {config.risk_threshold}")
        
        # Check for critical vulnerabilities
        if result.vulnerability_summary['critical'] > 0:
            compliance_result['compliant'] = False
            compliance_result['violations'].append(f"{result.vulnerability_summary['critical']} critical vulnerabilities found")
        
        # Check license compliance
        if result.license_compliance_status == 'non_compliant':
            compliance_result['compliant'] = False
            compliance_result['violations'].append("License policy violations detected")
        
        # Fail on high risk if configured
        if config.fail_on_high_risk and result.risk_level in ['high', 'critical']:
            compliance_result['compliant'] = False
            compliance_result['violations'].append(f"High risk level detected: {result.risk_level}")
        
        return compliance_result
