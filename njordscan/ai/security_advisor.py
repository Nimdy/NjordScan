"""
AI-Powered Security Advisor

Provides intelligent security recommendations, remediation guidance,
and strategic security insights based on analysis results.
"""

import re
import json
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import logging

logger = logging.getLogger(__name__)

class RecommendationType(Enum):
    """Types of security recommendations."""
    IMMEDIATE_ACTION = "immediate_action"
    REMEDIATION = "remediation"
    PREVENTION = "prevention"
    MONITORING = "monitoring"
    POLICY = "policy"
    ARCHITECTURE = "architecture"
    TRAINING = "training"

class RecommendationPriority(Enum):
    """Priority levels for recommendations."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ImplementationComplexity(Enum):
    """Implementation complexity levels."""
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    ARCHITECTURAL = "architectural"

@dataclass
class SecurityRecommendation:
    """Individual security recommendation."""
    recommendation_id: str
    title: str
    description: str
    
    # Classification
    recommendation_type: RecommendationType
    priority: RecommendationPriority
    complexity: ImplementationComplexity
    
    # Context
    affected_components: List[str]
    related_vulnerabilities: List[str]
    security_domains: List[str]  # OWASP categories, etc.
    
    # Implementation details
    implementation_steps: List[str]
    estimated_effort: str  # e.g., "2-4 hours", "1-2 weeks"
    required_skills: List[str]
    dependencies: List[str]
    
    # Impact assessment
    risk_reduction: float  # 0-100 scale
    business_impact: str
    technical_impact: str
    
    # Resources and references
    references: List[str]
    tools_suggested: List[str]
    code_examples: List[Dict[str, str]]
    
    # Metadata
    confidence: float
    created_time: float
    advisor_version: str

@dataclass
class SecurityStrategy:
    """Comprehensive security strategy."""
    strategy_id: str
    title: str
    description: str
    
    # Strategic elements
    short_term_goals: List[str]
    long_term_goals: List[str]
    quick_wins: List[SecurityRecommendation]
    strategic_initiatives: List[SecurityRecommendation]
    
    # Risk assessment
    current_risk_level: str
    target_risk_level: str
    risk_reduction_timeline: Dict[str, str]
    
    # Resource planning
    budget_considerations: List[str]
    team_requirements: List[str]
    timeline_milestones: List[Dict[str, Any]]
    
    # Metrics and KPIs
    success_metrics: List[str]
    monitoring_requirements: List[str]
    
    # Metadata
    created_time: float
    last_updated: float

class SecurityAdvisor:
    """AI-powered security advisor and recommendation engine."""
    
    def __init__(self):
        # Knowledge base of security patterns and solutions
        self.security_knowledge = self._initialize_security_knowledge()
        
        # Recommendation templates
        self.recommendation_templates = self._initialize_recommendation_templates()
        
        # Security frameworks and standards
        self.security_frameworks = {
            'owasp_top10': {
                'A01': 'Broken Access Control',
                'A02': 'Cryptographic Failures',
                'A03': 'Injection',
                'A04': 'Insecure Design',
                'A05': 'Security Misconfiguration',
                'A06': 'Vulnerable and Outdated Components',
                'A07': 'Identification and Authentication Failures',
                'A08': 'Software and Data Integrity Failures',
                'A09': 'Security Logging and Monitoring Failures',
                'A10': 'Server-Side Request Forgery (SSRF)'
            },
            'nist_csf': {
                'identify': 'Identify',
                'protect': 'Protect',
                'detect': 'Detect',
                'respond': 'Respond',
                'recover': 'Recover'
            },
            'sans_top25': [
                'Improper Input Validation',
                'Out-of-bounds Write',
                'Out-of-bounds Read',
                'Improper Neutralization of Special Elements',
                'Cross-site Scripting'
            ]
        }
        
        # Industry-specific considerations
        self.industry_considerations = {
            'healthcare': ['HIPAA compliance', 'Patient data protection', 'Medical device security'],
            'finance': ['PCI DSS compliance', 'SOX compliance', 'Financial data protection'],
            'education': ['FERPA compliance', 'Student data protection'],
            'government': ['FedRAMP compliance', 'FISMA compliance', 'Classified data handling'],
            'retail': ['PCI DSS compliance', 'Customer data protection', 'E-commerce security']
        }
        
        # Statistics
        self.stats = {
            'recommendations_generated': 0,
            'strategies_created': 0,
            'implementations_tracked': 0,
            'success_rate': 0.0
        }
    
    def _initialize_security_knowledge(self) -> Dict[str, Any]:
        """Initialize security knowledge base."""
        
        return {
            'vulnerability_patterns': {
                'injection': {
                    'description': 'Code injection vulnerabilities',
                    'common_causes': ['Unsanitized input', 'Dynamic code execution', 'Unsafe deserialization'],
                    'remediation_strategies': ['Input validation', 'Parameterized queries', 'Code review'],
                    'prevention_measures': ['Security training', 'Static analysis', 'WAF deployment']
                },
                'authentication': {
                    'description': 'Authentication and authorization flaws',
                    'common_causes': ['Weak passwords', 'Session management issues', 'Privilege escalation'],
                    'remediation_strategies': ['Strong authentication', 'MFA implementation', 'Session security'],
                    'prevention_measures': ['Identity management', 'Access controls', 'Regular audits']
                },
                'data_exposure': {
                    'description': 'Sensitive data exposure',
                    'common_causes': ['Unencrypted data', 'Weak encryption', 'Data leakage'],
                    'remediation_strategies': ['Encryption at rest', 'Encryption in transit', 'Data classification'],
                    'prevention_measures': ['Data governance', 'Privacy by design', 'Regular assessments']
                }
            },
            
            'security_controls': {
                'preventive': {
                    'access_control': ['Authentication', 'Authorization', 'Role-based access'],
                    'input_validation': ['Sanitization', 'Validation rules', 'Encoding'],
                    'encryption': ['Data encryption', 'Transport encryption', 'Key management']
                },
                'detective': {
                    'monitoring': ['Security monitoring', 'Log analysis', 'Anomaly detection'],
                    'scanning': ['Vulnerability scanning', 'Code analysis', 'Penetration testing'],
                    'auditing': ['Security audits', 'Compliance checks', 'Risk assessments']
                },
                'corrective': {
                    'incident_response': ['Response procedures', 'Containment', 'Recovery'],
                    'patching': ['Patch management', 'Vulnerability remediation', 'Updates'],
                    'remediation': ['Security fixes', 'Configuration changes', 'Process improvements']
                }
            },
            
            'technology_specific': {
                'web_applications': {
                    'common_issues': ['XSS', 'CSRF', 'SQL injection', 'Insecure direct object references'],
                    'security_measures': ['WAF', 'Security headers', 'Input validation', 'Output encoding'],
                    'frameworks': ['OWASP ASVS', 'OWASP Testing Guide', 'NIST Web App Security']
                },
                'apis': {
                    'common_issues': ['Broken authentication', 'Excessive data exposure', 'Rate limiting'],
                    'security_measures': ['API gateway', 'OAuth/JWT', 'Rate limiting', 'Input validation'],
                    'frameworks': ['OWASP API Security Top 10', 'OpenAPI Security']
                },
                'cloud': {
                    'common_issues': ['Misconfigurations', 'Weak identity management', 'Data breaches'],
                    'security_measures': ['IAM', 'Encryption', 'Network security', 'Monitoring'],
                    'frameworks': ['Cloud Security Alliance', 'NIST Cloud Security', 'CSA CCM']
                }
            }
        }
    
    def _initialize_recommendation_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize recommendation templates."""
        
        return {
            'input_validation': {
                'title': 'Implement Input Validation',
                'type': RecommendationType.REMEDIATION,
                'priority': RecommendationPriority.HIGH,
                'complexity': ImplementationComplexity.MODERATE,
                'implementation_steps': [
                    'Identify all input points',
                    'Define validation rules',
                    'Implement server-side validation',
                    'Add client-side validation for UX',
                    'Test validation logic'
                ],
                'estimated_effort': '1-2 weeks',
                'required_skills': ['Backend development', 'Security knowledge'],
                'risk_reduction': 70.0
            },
            
            'authentication_hardening': {
                'title': 'Strengthen Authentication Mechanisms',
                'type': RecommendationType.REMEDIATION,
                'priority': RecommendationPriority.CRITICAL,
                'complexity': ImplementationComplexity.COMPLEX,
                'implementation_steps': [
                    'Implement multi-factor authentication',
                    'Strengthen password policies',
                    'Add account lockout mechanisms',
                    'Implement session management',
                    'Add login monitoring'
                ],
                'estimated_effort': '2-4 weeks',
                'required_skills': ['Identity management', 'Security architecture'],
                'risk_reduction': 85.0
            },
            
            'encryption_implementation': {
                'title': 'Implement Data Encryption',
                'type': RecommendationType.REMEDIATION,
                'priority': RecommendationPriority.HIGH,
                'complexity': ImplementationComplexity.COMPLEX,
                'implementation_steps': [
                    'Classify sensitive data',
                    'Choose appropriate encryption algorithms',
                    'Implement encryption at rest',
                    'Implement encryption in transit',
                    'Establish key management procedures'
                ],
                'estimated_effort': '3-6 weeks',
                'required_skills': ['Cryptography', 'System architecture'],
                'risk_reduction': 80.0
            },
            
            'security_monitoring': {
                'title': 'Implement Security Monitoring',
                'type': RecommendationType.MONITORING,
                'priority': RecommendationPriority.MEDIUM,
                'complexity': ImplementationComplexity.COMPLEX,
                'implementation_steps': [
                    'Deploy logging infrastructure',
                    'Configure security event monitoring',
                    'Set up alerting rules',
                    'Create incident response procedures',
                    'Train security team'
                ],
                'estimated_effort': '4-8 weeks',
                'required_skills': ['Security operations', 'SIEM management'],
                'risk_reduction': 60.0
            }
        }
    
    async def generate_recommendations(self, analysis_results: Dict[str, Any], 
                                     context: Dict[str, Any] = None) -> List[SecurityRecommendation]:
        """Generate comprehensive security recommendations."""
        
        logger.info("Generating security recommendations")
        
        context = context or {}
        recommendations = []
        
        # Extract vulnerabilities and findings
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        anomalies = analysis_results.get('anomalies', [])
        threat_assessment = analysis_results.get('threat_assessment', {})
        code_analysis = analysis_results.get('code_analysis', {})
        
        # Generate vulnerability-specific recommendations
        vuln_recommendations = await self._generate_vulnerability_recommendations(
            vulnerabilities, context
        )
        recommendations.extend(vuln_recommendations)
        
        # Generate anomaly-based recommendations
        anomaly_recommendations = await self._generate_anomaly_recommendations(
            anomalies, context
        )
        recommendations.extend(anomaly_recommendations)
        
        # Generate threat-based recommendations
        threat_recommendations = await self._generate_threat_recommendations(
            threat_assessment, context
        )
        recommendations.extend(threat_recommendations)
        
        # Generate code quality recommendations
        code_recommendations = await self._generate_code_recommendations(
            code_analysis, context
        )
        recommendations.extend(code_recommendations)
        
        # Generate strategic recommendations
        strategic_recommendations = await self._generate_strategic_recommendations(
            analysis_results, context
        )
        recommendations.extend(strategic_recommendations)
        
        # Post-process recommendations
        recommendations = await self._post_process_recommendations(recommendations, context)
        
        # Update statistics
        self.stats['recommendations_generated'] += len(recommendations)
        
        logger.info(f"Generated {len(recommendations)} security recommendations")
        
        return recommendations
    
    async def create_security_strategy(self, analysis_results: Dict[str, Any], 
                                     recommendations: List[SecurityRecommendation],
                                     context: Dict[str, Any] = None) -> SecurityStrategy:
        """Create a comprehensive security strategy."""
        
        logger.info("Creating security strategy")
        
        context = context or {}
        
        # Analyze current security posture
        current_risk_level = self._assess_current_risk_level(analysis_results)
        target_risk_level = context.get('target_risk_level', 'low')
        
        # Categorize recommendations
        quick_wins = [r for r in recommendations 
                     if r.complexity in [ImplementationComplexity.SIMPLE, ImplementationComplexity.MODERATE]
                     and r.priority in [RecommendationPriority.CRITICAL, RecommendationPriority.HIGH]]
        
        strategic_initiatives = [r for r in recommendations 
                               if r.complexity in [ImplementationComplexity.COMPLEX, ImplementationComplexity.ARCHITECTURAL]]
        
        # Define goals
        short_term_goals = self._define_short_term_goals(analysis_results, quick_wins)
        long_term_goals = self._define_long_term_goals(analysis_results, strategic_initiatives, context)
        
        # Create timeline
        timeline_milestones = self._create_timeline_milestones(recommendations)
        
        # Define success metrics
        success_metrics = self._define_success_metrics(analysis_results, recommendations)
        
        # Create strategy
        strategy = SecurityStrategy(
            strategy_id=f"strategy_{int(time.time())}",
            title="Comprehensive Security Improvement Strategy",
            description="Strategic plan to enhance security posture based on current analysis",
            short_term_goals=short_term_goals,
            long_term_goals=long_term_goals,
            quick_wins=quick_wins[:10],  # Top 10 quick wins
            strategic_initiatives=strategic_initiatives,
            current_risk_level=current_risk_level,
            target_risk_level=target_risk_level,
            risk_reduction_timeline=self._create_risk_reduction_timeline(recommendations),
            budget_considerations=self._assess_budget_considerations(recommendations),
            team_requirements=self._assess_team_requirements(recommendations),
            timeline_milestones=timeline_milestones,
            success_metrics=success_metrics,
            monitoring_requirements=self._define_monitoring_requirements(recommendations),
            created_time=time.time(),
            last_updated=time.time()
        )
        
        self.stats['strategies_created'] += 1
        
        logger.info("Security strategy created successfully")
        
        return strategy
    
    async def _generate_vulnerability_recommendations(self, vulnerabilities: List[Dict[str, Any]], 
                                                    context: Dict[str, Any]) -> List[SecurityRecommendation]:
        """Generate recommendations based on identified vulnerabilities."""
        
        recommendations = []
        
        # Group vulnerabilities by type
        vuln_groups = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_type = vuln.get('category', 'unknown')
            vuln_groups[vuln_type].append(vuln)
        
        # Generate recommendations for each vulnerability type
        for vuln_type, vulns in vuln_groups.items():
            severity_counts = Counter(v.get('severity', 'unknown') for v in vulns)
            
            # Determine priority based on severity
            priority = RecommendationPriority.MEDIUM
            if severity_counts.get('critical', 0) > 0:
                priority = RecommendationPriority.CRITICAL
            elif severity_counts.get('high', 0) > 0:
                priority = RecommendationPriority.HIGH
            
            # Get vulnerability-specific recommendations
            vuln_recommendations = self._get_vulnerability_type_recommendations(
                vuln_type, vulns, priority
            )
            
            recommendations.extend(vuln_recommendations)
        
        return recommendations
    
    async def _generate_anomaly_recommendations(self, anomalies: List[Dict[str, Any]], 
                                              context: Dict[str, Any]) -> List[SecurityRecommendation]:
        """Generate recommendations based on detected anomalies."""
        
        recommendations = []
        
        for anomaly in anomalies:
            anomaly_type = anomaly.get('anomaly_type', 'unknown')
            severity = anomaly.get('severity', 'medium')
            
            # Convert severity to priority
            priority_map = {
                'critical': RecommendationPriority.CRITICAL,
                'high': RecommendationPriority.HIGH,
                'medium': RecommendationPriority.MEDIUM,
                'low': RecommendationPriority.LOW
            }
            priority = priority_map.get(severity, RecommendationPriority.MEDIUM)
            
            # Generate anomaly-specific recommendation
            recommendation = self._create_anomaly_recommendation(anomaly, priority)
            if recommendation:
                recommendations.append(recommendation)
        
        return recommendations
    
    async def _generate_threat_recommendations(self, threat_assessment: Dict[str, Any], 
                                             context: Dict[str, Any]) -> List[SecurityRecommendation]:
        """Generate recommendations based on threat assessment."""
        
        recommendations = []
        
        if not threat_assessment:
            return recommendations
        
        threat_level = threat_assessment.get('threat_level', 'medium')
        active_threats = threat_assessment.get('active_threats', [])
        attack_vectors = threat_assessment.get('attack_vectors', [])
        
        # Generate threat-level recommendations
        if threat_level in ['critical', 'high']:
            recommendation = SecurityRecommendation(
                recommendation_id=f"threat_response_{int(time.time())}",
                title="Immediate Threat Response",
                description="Implement immediate threat response measures",
                recommendation_type=RecommendationType.IMMEDIATE_ACTION,
                priority=RecommendationPriority.CRITICAL,
                complexity=ImplementationComplexity.MODERATE,
                affected_components=["All systems"],
                related_vulnerabilities=[],
                security_domains=["Incident Response", "Threat Management"],
                implementation_steps=[
                    "Activate incident response team",
                    "Implement threat containment measures",
                    "Enhance monitoring and logging",
                    "Review and update security controls",
                    "Conduct threat hunting activities"
                ],
                estimated_effort="1-2 days",
                required_skills=["Incident Response", "Threat Analysis"],
                dependencies=[],
                risk_reduction=60.0,
                business_impact="Reduces immediate threat exposure",
                technical_impact="Improves threat detection and response capabilities",
                references=[
                    "NIST Incident Response Guide",
                    "SANS Incident Response Process"
                ],
                tools_suggested=["SIEM", "Threat Intelligence Platform"],
                code_examples=[],
                confidence=0.9,
                created_time=time.time(),
                advisor_version="1.0.0"
            )
            recommendations.append(recommendation)
        
        # Generate attack vector specific recommendations
        for attack_vector in attack_vectors:
            vector_recommendation = self._create_attack_vector_recommendation(attack_vector)
            if vector_recommendation:
                recommendations.append(vector_recommendation)
        
        return recommendations
    
    async def _generate_code_recommendations(self, code_analysis: Dict[str, Any], 
                                           context: Dict[str, Any]) -> List[SecurityRecommendation]:
        """Generate recommendations based on code analysis."""
        
        recommendations = []
        
        if not code_analysis:
            return recommendations
        
        # Check for code quality issues
        features = code_analysis.get('features', {})
        
        # High complexity recommendation
        if features.get('cyclomatic_complexity', 0) > 20:
            recommendation = SecurityRecommendation(
                recommendation_id=f"code_complexity_{int(time.time())}",
                title="Reduce Code Complexity",
                description="High code complexity increases security risk and maintenance burden",
                recommendation_type=RecommendationType.REMEDIATION,
                priority=RecommendationPriority.MEDIUM,
                complexity=ImplementationComplexity.MODERATE,
                affected_components=["Source code"],
                related_vulnerabilities=[],
                security_domains=["Code Quality", "Maintainability"],
                implementation_steps=[
                    "Identify complex functions and methods",
                    "Refactor complex code into smaller functions",
                    "Implement unit tests for refactored code",
                    "Review and simplify business logic",
                    "Establish complexity metrics monitoring"
                ],
                estimated_effort="2-4 weeks",
                required_skills=["Software Development", "Code Review"],
                dependencies=["Development team availability"],
                risk_reduction=30.0,
                business_impact="Improves code maintainability and reduces bug risk",
                technical_impact="Easier code review and testing",
                references=[
                    "Clean Code principles",
                    "Refactoring best practices"
                ],
                tools_suggested=["SonarQube", "Code Climate"],
                code_examples=[],
                confidence=0.8,
                created_time=time.time(),
                advisor_version="1.0.0"
            )
            recommendations.append(recommendation)
        
        # Obfuscation detection recommendation
        if features.get('obfuscation_score', 0) > 0.7:
            recommendation = SecurityRecommendation(
                recommendation_id=f"code_obfuscation_{int(time.time())}",
                title="Investigate Code Obfuscation",
                description="High obfuscation score detected - potential security concern",
                recommendation_type=RecommendationType.IMMEDIATE_ACTION,
                priority=RecommendationPriority.HIGH,
                complexity=ImplementationComplexity.SIMPLE,
                affected_components=["Source code"],
                related_vulnerabilities=[],
                security_domains=["Malware Detection", "Code Analysis"],
                implementation_steps=[
                    "Review obfuscated code sections",
                    "Verify code integrity and origin",
                    "Deobfuscate if necessary for analysis",
                    "Implement code signing verification",
                    "Enhance code review processes"
                ],
                estimated_effort="1-3 days",
                required_skills=["Security Analysis", "Code Review"],
                dependencies=[],
                risk_reduction=70.0,
                business_impact="Prevents potential malware execution",
                technical_impact="Improves code transparency and security",
                references=[
                    "Code obfuscation analysis techniques",
                    "Malware detection best practices"
                ],
                tools_suggested=["Static analysis tools", "Deobfuscation tools"],
                code_examples=[],
                confidence=0.9,
                created_time=time.time(),
                advisor_version="1.0.0"
            )
            recommendations.append(recommendation)
        
        return recommendations
    
    async def _generate_strategic_recommendations(self, analysis_results: Dict[str, Any], 
                                                context: Dict[str, Any]) -> List[SecurityRecommendation]:
        """Generate strategic security recommendations."""
        
        recommendations = []
        
        # Security governance recommendation
        governance_recommendation = SecurityRecommendation(
            recommendation_id=f"governance_{int(time.time())}",
            title="Establish Security Governance Framework",
            description="Implement comprehensive security governance and risk management",
            recommendation_type=RecommendationType.ARCHITECTURE,
            priority=RecommendationPriority.MEDIUM,
            complexity=ImplementationComplexity.ARCHITECTURAL,
            affected_components=["Organization"],
            related_vulnerabilities=[],
            security_domains=["Governance", "Risk Management", "Compliance"],
            implementation_steps=[
                "Establish security steering committee",
                "Define security policies and procedures",
                "Implement risk management framework",
                "Create security awareness program",
                "Establish compliance monitoring"
            ],
            estimated_effort="3-6 months",
            required_skills=["Security Management", "Risk Assessment", "Policy Development"],
            dependencies=["Executive support", "Budget allocation"],
            risk_reduction=40.0,
            business_impact="Improves overall security posture and compliance",
            technical_impact="Provides structure for security implementations",
            references=[
                "NIST Cybersecurity Framework",
                "ISO 27001 standard",
                "COBIT framework"
            ],
            tools_suggested=["GRC platforms", "Risk assessment tools"],
            code_examples=[],
            confidence=0.8,
            created_time=time.time(),
            advisor_version="1.0.0"
        )
        recommendations.append(governance_recommendation)
        
        # Security training recommendation
        training_recommendation = SecurityRecommendation(
            recommendation_id=f"training_{int(time.time())}",
            title="Implement Security Training Program",
            description="Establish comprehensive security training for development teams",
            recommendation_type=RecommendationType.TRAINING,
            priority=RecommendationPriority.MEDIUM,
            complexity=ImplementationComplexity.MODERATE,
            affected_components=["Development teams"],
            related_vulnerabilities=[],
            security_domains=["Security Awareness", "Secure Development"],
            implementation_steps=[
                "Assess current security knowledge gaps",
                "Develop security training curriculum",
                "Implement secure coding training",
                "Create security awareness campaigns",
                "Establish ongoing training programs"
            ],
            estimated_effort="2-4 months",
            required_skills=["Training Development", "Security Education"],
            dependencies=["Training budget", "Team availability"],
            risk_reduction=50.0,
            business_impact="Reduces human error and improves security culture",
            technical_impact="Better security practices in development",
            references=[
                "OWASP Secure Coding Practices",
                "SANS Security Training",
                "Security awareness best practices"
            ],
            tools_suggested=["Learning management systems", "Security training platforms"],
            code_examples=[],
            confidence=0.7,
            created_time=time.time(),
            advisor_version="1.0.0"
        )
        recommendations.append(training_recommendation)
        
        return recommendations
    
    def _get_vulnerability_type_recommendations(self, vuln_type: str, vulnerabilities: List[Dict[str, Any]], 
                                              priority: RecommendationPriority) -> List[SecurityRecommendation]:
        """Get recommendations for specific vulnerability types."""
        
        recommendations = []
        
        # Map vulnerability types to recommendation templates
        template_mapping = {
            'xss': 'input_validation',
            'injection': 'input_validation',
            'authentication': 'authentication_hardening',
            'authorization': 'authentication_hardening',
            'encryption': 'encryption_implementation',
            'data_exposure': 'encryption_implementation'
        }
        
        template_key = template_mapping.get(vuln_type.lower())
        if template_key and template_key in self.recommendation_templates:
            template = self.recommendation_templates[template_key]
            
            recommendation = SecurityRecommendation(
                recommendation_id=f"vuln_{vuln_type}_{int(time.time())}",
                title=template['title'],
                description=f"Address {len(vulnerabilities)} {vuln_type} vulnerabilities",
                recommendation_type=template['type'],
                priority=priority,
                complexity=template['complexity'],
                affected_components=[v.get('file_path', 'Unknown') for v in vulnerabilities[:5]],
                related_vulnerabilities=[v.get('id', '') for v in vulnerabilities],
                security_domains=[vuln_type.title(), "Vulnerability Management"],
                implementation_steps=template['implementation_steps'],
                estimated_effort=template['estimated_effort'],
                required_skills=template['required_skills'],
                dependencies=[],
                risk_reduction=template['risk_reduction'],
                business_impact=f"Reduces {vuln_type} vulnerability exposure",
                technical_impact=f"Improves {vuln_type} security controls",
                references=self._get_vulnerability_references(vuln_type),
                tools_suggested=self._get_vulnerability_tools(vuln_type),
                code_examples=self._get_vulnerability_code_examples(vuln_type),
                confidence=0.8,
                created_time=time.time(),
                advisor_version="1.0.0"
            )
            recommendations.append(recommendation)
        
        return recommendations
    
    def _create_anomaly_recommendation(self, anomaly: Dict[str, Any], 
                                     priority: RecommendationPriority) -> Optional[SecurityRecommendation]:
        """Create recommendation for an anomaly."""
        
        anomaly_type = anomaly.get('anomaly_type', 'unknown')
        
        # Map anomaly types to recommendations
        anomaly_recommendations = {
            'statistical': {
                'title': 'Investigate Statistical Anomaly',
                'description': 'Unusual statistical patterns detected',
                'type': RecommendationType.MONITORING,
                'complexity': ImplementationComplexity.SIMPLE,
                'steps': [
                    'Review anomaly details and affected metrics',
                    'Compare with historical baselines',
                    'Investigate potential root causes',
                    'Implement additional monitoring if needed',
                    'Update baselines if changes are legitimate'
                ]
            },
            'behavioral': {
                'title': 'Investigate Behavioral Anomaly',
                'description': 'Unusual behavior patterns detected',
                'type': RecommendationType.MONITORING,
                'complexity': ImplementationComplexity.MODERATE,
                'steps': [
                    'Analyze behavior pattern details',
                    'Check for unauthorized access or activities',
                    'Review user and system interactions',
                    'Implement behavioral monitoring',
                    'Update security policies if needed'
                ]
            },
            'temporal': {
                'title': 'Investigate Temporal Anomaly',
                'description': 'Unusual timing patterns detected',
                'type': RecommendationType.MONITORING,
                'complexity': ImplementationComplexity.SIMPLE,
                'steps': [
                    'Review timing pattern analysis',
                    'Check for system performance issues',
                    'Investigate external factors',
                    'Monitor for recurring patterns',
                    'Adjust monitoring thresholds if needed'
                ]
            }
        }
        
        if anomaly_type not in anomaly_recommendations:
            return None
        
        template = anomaly_recommendations[anomaly_type]
        
        return SecurityRecommendation(
            recommendation_id=f"anomaly_{anomaly_type}_{int(time.time())}",
            title=template['title'],
            description=template['description'],
            recommendation_type=template['type'],
            priority=priority,
            complexity=template['complexity'],
            affected_components=[anomaly.get('affected_component', 'Unknown')],
            related_vulnerabilities=[],
            security_domains=["Anomaly Detection", "Monitoring"],
            implementation_steps=template['steps'],
            estimated_effort="1-3 days",
            required_skills=["Security Analysis", "Monitoring"],
            dependencies=[],
            risk_reduction=30.0,
            business_impact="Identifies potential security issues early",
            technical_impact="Improves security monitoring capabilities",
            references=["Anomaly detection best practices"],
            tools_suggested=["SIEM", "Monitoring tools"],
            code_examples=[],
            confidence=0.7,
            created_time=time.time(),
            advisor_version="1.0.0"
        )
    
    def _create_attack_vector_recommendation(self, attack_vector: str) -> Optional[SecurityRecommendation]:
        """Create recommendation for an attack vector."""
        
        vector_recommendations = {
            'vulnerability_exploitation': {
                'title': 'Strengthen Vulnerability Management',
                'description': 'Improve vulnerability identification and remediation',
                'steps': [
                    'Implement regular vulnerability scanning',
                    'Establish patch management process',
                    'Prioritize critical vulnerabilities',
                    'Implement vulnerability disclosure program',
                    'Monitor threat intelligence for new vulnerabilities'
                ]
            },
            'supply_chain_compromise': {
                'title': 'Enhance Supply Chain Security',
                'description': 'Secure software supply chain and dependencies',
                'steps': [
                    'Implement software bill of materials (SBOM)',
                    'Use dependency scanning tools',
                    'Verify software integrity and signatures',
                    'Implement secure development practices',
                    'Monitor third-party components'
                ]
            },
            'malware_infection': {
                'title': 'Implement Anti-Malware Controls',
                'description': 'Deploy comprehensive malware protection',
                'steps': [
                    'Deploy endpoint detection and response (EDR)',
                    'Implement email security controls',
                    'Use application sandboxing',
                    'Deploy network-based malware detection',
                    'Implement user security awareness training'
                ]
            }
        }
        
        if attack_vector not in vector_recommendations:
            return None
        
        template = vector_recommendations[attack_vector]
        
        return SecurityRecommendation(
            recommendation_id=f"attack_vector_{attack_vector}_{int(time.time())}",
            title=template['title'],
            description=template['description'],
            recommendation_type=RecommendationType.PREVENTION,
            priority=RecommendationPriority.HIGH,
            complexity=ImplementationComplexity.COMPLEX,
            affected_components=["All systems"],
            related_vulnerabilities=[],
            security_domains=["Attack Vector Mitigation", "Prevention"],
            implementation_steps=template['steps'],
            estimated_effort="2-6 weeks",
            required_skills=["Security Architecture", "Risk Management"],
            dependencies=["Security tools", "Budget allocation"],
            risk_reduction=65.0,
            business_impact=f"Reduces {attack_vector.replace('_', ' ')} risks",
            technical_impact="Improves overall security posture",
            references=[f"{attack_vector.replace('_', ' ').title()} mitigation guides"],
            tools_suggested=["Security tools", "Monitoring systems"],
            code_examples=[],
            confidence=0.8,
            created_time=time.time(),
            advisor_version="1.0.0"
        )
    
    async def _post_process_recommendations(self, recommendations: List[SecurityRecommendation], 
                                          context: Dict[str, Any]) -> List[SecurityRecommendation]:
        """Post-process recommendations to improve quality and relevance."""
        
        # Remove duplicates
        unique_recommendations = self._remove_duplicate_recommendations(recommendations)
        
        # Adjust priorities based on context
        contextualized_recommendations = self._contextualize_recommendations(unique_recommendations, context)
        
        # Sort by priority and impact
        sorted_recommendations = sorted(
            contextualized_recommendations,
            key=lambda r: (r.priority.value, r.risk_reduction),
            reverse=True
        )
        
        return sorted_recommendations
    
    def _remove_duplicate_recommendations(self, recommendations: List[SecurityRecommendation]) -> List[SecurityRecommendation]:
        """Remove duplicate recommendations."""
        
        seen_titles = set()
        unique_recommendations = []
        
        for recommendation in recommendations:
            if recommendation.title not in seen_titles:
                seen_titles.add(recommendation.title)
                unique_recommendations.append(recommendation)
        
        return unique_recommendations
    
    def _contextualize_recommendations(self, recommendations: List[SecurityRecommendation], 
                                     context: Dict[str, Any]) -> List[SecurityRecommendation]:
        """Adjust recommendations based on context."""
        
        # Industry-specific adjustments
        industry = context.get('industry')
        if industry in self.industry_considerations:
            considerations = self.industry_considerations[industry]
            
            for recommendation in recommendations:
                # Add industry-specific considerations
                if any(consideration.lower() in recommendation.description.lower() 
                      for consideration in considerations):
                    if recommendation.priority == RecommendationPriority.MEDIUM:
                        recommendation.priority = RecommendationPriority.HIGH
        
        # Environment-specific adjustments
        environment = context.get('environment', 'production')
        if environment == 'production':
            for recommendation in recommendations:
                if recommendation.recommendation_type == RecommendationType.IMMEDIATE_ACTION:
                    # Increase priority for production systems
                    if recommendation.priority == RecommendationPriority.MEDIUM:
                        recommendation.priority = RecommendationPriority.HIGH
        
        return recommendations
    
    # Helper methods for generating specific content
    def _get_vulnerability_references(self, vuln_type: str) -> List[str]:
        """Get references for vulnerability type."""
        
        references_map = {
            'xss': ['OWASP XSS Prevention Cheat Sheet', 'CWE-79: Cross-site Scripting'],
            'injection': ['OWASP Injection Prevention', 'CWE-89: SQL Injection'],
            'authentication': ['OWASP Authentication Cheat Sheet', 'NIST Authentication Guidelines'],
            'encryption': ['OWASP Cryptographic Storage Cheat Sheet', 'NIST Cryptographic Standards']
        }
        
        return references_map.get(vuln_type.lower(), ['Security best practices'])
    
    def _get_vulnerability_tools(self, vuln_type: str) -> List[str]:
        """Get tool suggestions for vulnerability type."""
        
        tools_map = {
            'xss': ['OWASP ZAP', 'Burp Suite', 'Content Security Policy'],
            'injection': ['SQLMap', 'Static analysis tools', 'WAF'],
            'authentication': ['OAuth providers', 'MFA solutions', 'Identity providers'],
            'encryption': ['OpenSSL', 'Key management systems', 'Hardware security modules']
        }
        
        return tools_map.get(vuln_type.lower(), ['Security tools'])
    
    def _get_vulnerability_code_examples(self, vuln_type: str) -> List[Dict[str, str]]:
        """Get code examples for vulnerability type."""
        
        # This would contain actual code examples in a real implementation
        examples = {
            'xss': [{
                'language': 'javascript',
                'title': 'XSS Prevention',
                'code': '// Use proper encoding\nconst safeOutput = escapeHtml(userInput);'
            }],
            'injection': [{
                'language': 'sql',
                'title': 'Parameterized Query',
                'code': '-- Use parameterized queries\nSELECT * FROM users WHERE id = ?'
            }]
        }
        
        return examples.get(vuln_type.lower(), [])
    
    # Strategy creation helper methods
    def _assess_current_risk_level(self, analysis_results: Dict[str, Any]) -> str:
        """Assess current risk level based on analysis results."""
        
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        threat_assessment = analysis_results.get('threat_assessment', {})
        
        critical_vulns = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'high'])
        threat_score = threat_assessment.get('overall_threat_score', 0)
        
        if critical_vulns > 0 or threat_score > 80:
            return 'critical'
        elif high_vulns > 5 or threat_score > 60:
            return 'high'
        elif high_vulns > 0 or threat_score > 40:
            return 'medium'
        else:
            return 'low'
    
    def _define_short_term_goals(self, analysis_results: Dict[str, Any], 
                               quick_wins: List[SecurityRecommendation]) -> List[str]:
        """Define short-term security goals."""
        
        goals = []
        
        # Critical vulnerability remediation
        critical_vulns = len([v for v in analysis_results.get('vulnerabilities', []) 
                            if v.get('severity') == 'critical'])
        if critical_vulns > 0:
            goals.append(f"Remediate all {critical_vulns} critical vulnerabilities within 30 days")
        
        # Quick wins implementation
        if quick_wins:
            goals.append(f"Implement top {min(5, len(quick_wins))} quick win security improvements")
        
        # Basic security controls
        goals.extend([
            "Establish security monitoring and alerting",
            "Implement basic access controls",
            "Deploy security scanning tools"
        ])
        
        return goals
    
    def _define_long_term_goals(self, analysis_results: Dict[str, Any], 
                              strategic_initiatives: List[SecurityRecommendation],
                              context: Dict[str, Any]) -> List[str]:
        """Define long-term security goals."""
        
        goals = [
            "Achieve comprehensive security posture",
            "Implement security by design principles",
            "Establish mature security operations",
            "Achieve relevant compliance certifications",
            "Build security-aware culture"
        ]
        
        # Industry-specific goals
        industry = context.get('industry')
        if industry == 'healthcare':
            goals.append("Achieve HIPAA compliance")
        elif industry == 'finance':
            goals.append("Achieve PCI DSS compliance")
        elif industry == 'government':
            goals.append("Achieve FedRAMP compliance")
        
        return goals
    
    def _create_timeline_milestones(self, recommendations: List[SecurityRecommendation]) -> List[Dict[str, Any]]:
        """Create timeline milestones for recommendations."""
        
        milestones = []
        
        # 30-day milestone
        immediate_actions = [r for r in recommendations 
                           if r.recommendation_type == RecommendationType.IMMEDIATE_ACTION]
        if immediate_actions:
            milestones.append({
                'timeframe': '30 days',
                'title': 'Immediate Security Actions',
                'deliverables': [r.title for r in immediate_actions[:3]],
                'success_criteria': 'Critical security gaps addressed'
            })
        
        # 90-day milestone
        quick_wins = [r for r in recommendations 
                     if r.complexity in [ImplementationComplexity.SIMPLE, ImplementationComplexity.MODERATE]]
        if quick_wins:
            milestones.append({
                'timeframe': '90 days',
                'title': 'Quick Security Wins',
                'deliverables': [r.title for r in quick_wins[:5]],
                'success_criteria': 'Basic security controls implemented'
            })
        
        # 6-month milestone
        milestones.append({
            'timeframe': '6 months',
            'title': 'Security Infrastructure',
            'deliverables': ['Security monitoring deployed', 'Incident response established', 'Security training completed'],
            'success_criteria': 'Mature security operations established'
        })
        
        # 12-month milestone
        milestones.append({
            'timeframe': '12 months',
            'title': 'Strategic Security Goals',
            'deliverables': ['Comprehensive security program', 'Compliance achievements', 'Security culture established'],
            'success_criteria': 'World-class security posture achieved'
        })
        
        return milestones
    
    def _define_success_metrics(self, analysis_results: Dict[str, Any], 
                              recommendations: List[SecurityRecommendation]) -> List[str]:
        """Define success metrics for security improvements."""
        
        return [
            "Vulnerability count reduced by 80%",
            "Mean time to remediation < 30 days",
            "Security incident response time < 4 hours",
            "Security training completion rate > 95%",
            "Zero critical vulnerabilities in production",
            "Compliance audit success rate > 98%",
            "Security tool coverage > 90%"
        ]
    
    def _create_risk_reduction_timeline(self, recommendations: List[SecurityRecommendation]) -> Dict[str, str]:
        """Create risk reduction timeline."""
        
        return {
            '30 days': '30% risk reduction through immediate actions',
            '90 days': '60% risk reduction through quick wins',
            '6 months': '80% risk reduction through infrastructure improvements',
            '12 months': '95% risk reduction through comprehensive program'
        }
    
    def _assess_budget_considerations(self, recommendations: List[SecurityRecommendation]) -> List[str]:
        """Assess budget considerations for recommendations."""
        
        return [
            "Security tool licensing and subscriptions",
            "Professional services for implementation",
            "Staff training and certification costs",
            "Infrastructure and hardware investments",
            "Ongoing operational costs",
            "Compliance and audit expenses"
        ]
    
    def _assess_team_requirements(self, recommendations: List[SecurityRecommendation]) -> List[str]:
        """Assess team requirements for recommendations."""
        
        skills_needed = set()
        for recommendation in recommendations:
            skills_needed.update(recommendation.required_skills)
        
        return [
            f"Security professionals with {', '.join(list(skills_needed)[:5])} skills",
            "Dedicated security team lead",
            "Part-time security architect",
            "Security awareness training coordinator",
            "Incident response team members"
        ]
    
    def _define_monitoring_requirements(self, recommendations: List[SecurityRecommendation]) -> List[str]:
        """Define monitoring requirements."""
        
        return [
            "Vulnerability scan results tracking",
            "Security control effectiveness monitoring",
            "Incident response metrics",
            "Compliance status monitoring",
            "Security training completion tracking",
            "Risk posture dashboard",
            "Threat intelligence integration"
        ]
    
    def get_advisor_statistics(self) -> Dict[str, Any]:
        """Get advisor statistics."""
        
        return dict(self.stats)
