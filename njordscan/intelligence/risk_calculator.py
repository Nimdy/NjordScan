"""
Advanced Risk Calculator for Vulnerability Assessment

Calculates comprehensive risk scores considering multiple factors and business context.
"""

import math
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class BusinessImpact(Enum):
    """Business impact levels."""
    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

class ExploitMaturity(Enum):
    """Exploit maturity levels."""
    NOT_DEFINED = "not_defined"
    UNPROVEN = "unproven"
    PROOF_OF_CONCEPT = "proof_of_concept"
    FUNCTIONAL = "functional"
    HIGH = "high"

class RemediationLevel(Enum):
    """Remediation difficulty levels."""
    OFFICIAL_FIX = "official_fix"
    TEMPORARY_FIX = "temporary_fix"
    WORKAROUND = "workaround"
    UNAVAILABLE = "unavailable"

@dataclass
class EnvironmentContext:
    """Environmental context for risk assessment."""
    deployment_type: str = "production"  # development, staging, production
    exposure_level: str = "internal"  # internal, external, public
    data_sensitivity: str = "medium"  # low, medium, high, critical
    compliance_requirements: List[str] = field(default_factory=list)
    business_criticality: str = "medium"  # low, medium, high, critical
    
    # Network context
    network_segmentation: bool = True
    firewall_protection: bool = True
    intrusion_detection: bool = False
    
    # Application context
    authentication_required: bool = True
    user_privilege_level: str = "user"  # anonymous, user, admin, system
    data_access_scope: str = "limited"  # none, limited, extensive, full

@dataclass
class RiskAssessment:
    """Comprehensive risk assessment result."""
    vulnerability_id: str
    
    # Core risk scores (0.0 to 10.0)
    base_score: float
    temporal_score: float
    environmental_score: float
    overall_risk_score: float
    
    # Risk categorization
    risk_level: str  # very_low, low, medium, high, very_high, critical
    business_impact: BusinessImpact
    likelihood_score: float  # 0.0 to 1.0
    impact_score: float  # 0.0 to 1.0
    
    # Contextual factors
    exploit_maturity: ExploitMaturity
    remediation_level: RemediationLevel
    confidence: float  # 0.0 to 1.0
    
    # Risk factors breakdown
    technical_factors: Dict[str, float] = field(default_factory=dict)
    environmental_factors: Dict[str, float] = field(default_factory=dict)
    business_factors: Dict[str, float] = field(default_factory=dict)
    
    # Recommendations
    priority_score: int = 0  # 1-10, higher = more urgent
    recommended_timeline: str = "medium_term"  # immediate, short_term, medium_term, long_term
    mitigation_strategies: List[str] = field(default_factory=list)
    
    # Metadata
    assessment_reasoning: List[str] = field(default_factory=list)
    risk_factors_identified: List[str] = field(default_factory=list)
    mitigating_factors: List[str] = field(default_factory=list)

class RiskCalculator:
    """Advanced risk calculator with comprehensive threat modeling."""
    
    def __init__(self):
        # Risk calculation weights
        self.risk_weights = {
            'severity': 0.3,
            'exploitability': 0.25,
            'exposure': 0.2,
            'business_impact': 0.15,
            'remediation_difficulty': 0.1
        }
        
        # Environmental multipliers
        self.environment_multipliers = {
            'production': 1.5,
            'staging': 1.0,
            'development': 0.5
        }
        
        # Exposure multipliers
        self.exposure_multipliers = {
            'public': 2.0,
            'external': 1.5,
            'internal': 1.0
        }
        
        # Data sensitivity multipliers
        self.data_sensitivity_multipliers = {
            'critical': 2.0,
            'high': 1.5,
            'medium': 1.0,
            'low': 0.7
        }
        
        # Industry-specific risk factors
        self.industry_risk_factors = {
            'financial': {'data_breach': 2.0, 'regulatory': 1.8, 'reputation': 1.5},
            'healthcare': {'data_breach': 2.2, 'regulatory': 2.0, 'availability': 1.8},
            'ecommerce': {'data_breach': 1.8, 'availability': 2.0, 'reputation': 1.6},
            'government': {'data_breach': 2.5, 'regulatory': 2.2, 'security': 2.0},
            'default': {'data_breach': 1.5, 'regulatory': 1.2, 'reputation': 1.3}
        }
        
        # Statistics tracking
        self.assessment_stats = {
            'total_assessments': 0,
            'high_risk_count': 0,
            'critical_risk_count': 0,
            'risk_level_distribution': {},
            'average_risk_score': 0.0
        }
    
    def calculate_risk(self, vulnerability: Dict[str, Any], 
                      environment_context: Optional[EnvironmentContext] = None,
                      correlations: Optional[List[Any]] = None) -> RiskAssessment:
        """Calculate comprehensive risk assessment for a vulnerability."""
        
        # Use default context if none provided
        if environment_context is None:
            environment_context = EnvironmentContext()
        
        # Extract base vulnerability information
        vuln_id = vulnerability.get('id', str(hash(str(vulnerability))))
        severity = vulnerability.get('severity', 'medium').lower()
        vuln_type = vulnerability.get('vuln_type', vulnerability.get('type', 'unknown'))
        confidence = float(vulnerability.get('confidence', 0.5))
        
        # Calculate base score using CVSS-like methodology
        base_score = self._calculate_base_score(vulnerability)
        
        # Calculate temporal score (exploit maturity, remediation level)
        temporal_score = self._calculate_temporal_score(vulnerability, vuln_type)
        
        # Calculate environmental score (deployment context, exposure)
        environmental_score = self._calculate_environmental_score(
            base_score, environment_context, vulnerability
        )
        
        # Apply correlation amplification if available
        if correlations:
            correlation_multiplier = self._calculate_correlation_multiplier(correlations)
            environmental_score *= correlation_multiplier
        
        # Calculate overall risk score
        overall_risk_score = self._calculate_overall_risk_score(
            base_score, temporal_score, environmental_score
        )
        
        # Determine risk level and business impact
        risk_level = self._determine_risk_level(overall_risk_score)
        business_impact = self._assess_business_impact(
            overall_risk_score, environment_context, vuln_type
        )
        
        # Calculate likelihood and impact components
        likelihood_score = self._calculate_likelihood_score(
            vulnerability, environment_context
        )
        impact_score = self._calculate_impact_score(
            vulnerability, environment_context
        )
        
        # Determine exploit maturity and remediation level
        exploit_maturity = self._assess_exploit_maturity(vuln_type)
        remediation_level = self._assess_remediation_level(vuln_type, vulnerability)
        
        # Calculate priority and timeline
        priority_score = self._calculate_priority_score(
            overall_risk_score, business_impact, likelihood_score
        )
        recommended_timeline = self._determine_timeline(priority_score, risk_level)
        
        # Generate mitigation strategies
        mitigation_strategies = self._generate_mitigation_strategies(
            vulnerability, environment_context, risk_level
        )
        
        # Collect risk factors and reasoning
        technical_factors = self._analyze_technical_factors(vulnerability)
        environmental_factors = self._analyze_environmental_factors(environment_context)
        business_factors = self._analyze_business_factors(environment_context, vuln_type)
        
        reasoning = self._generate_assessment_reasoning(
            vulnerability, environment_context, overall_risk_score
        )
        
        # Create risk assessment
        assessment = RiskAssessment(
            vulnerability_id=vuln_id,
            base_score=base_score,
            temporal_score=temporal_score,
            environmental_score=environmental_score,
            overall_risk_score=overall_risk_score,
            risk_level=risk_level,
            business_impact=business_impact,
            likelihood_score=likelihood_score,
            impact_score=impact_score,
            exploit_maturity=exploit_maturity,
            remediation_level=remediation_level,
            confidence=confidence,
            technical_factors=technical_factors,
            environmental_factors=environmental_factors,
            business_factors=business_factors,
            priority_score=priority_score,
            recommended_timeline=recommended_timeline,
            mitigation_strategies=mitigation_strategies,
            assessment_reasoning=reasoning
        )
        
        # Update statistics
        self._update_assessment_stats(assessment)
        
        return assessment
    
    def _calculate_base_score(self, vulnerability: Dict[str, Any]) -> float:
        """Calculate base CVSS-like score."""
        
        severity = vulnerability.get('severity', 'medium').lower()
        severity_scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        base_score = severity_scores.get(severity, 5.0)
        
        # Adjust based on vulnerability type
        vuln_type = vulnerability.get('vuln_type', '').lower()
        type_adjustments = {
            'sql_injection': +1.5,
            'command_injection': +1.5,
            'xss': +0.5,
            'csrf': +0.5,
            'authentication_bypass': +2.0,
            'privilege_escalation': +1.8,
            'path_traversal': +1.0,
            'information_disclosure': -0.5,
            'configuration_issue': -1.0
        }
        
        for vuln_pattern, adjustment in type_adjustments.items():
            if vuln_pattern in vuln_type:
                base_score += adjustment
                break
        
        # Consider confidence level
        confidence = float(vulnerability.get('confidence', 0.5))
        if confidence < 0.5:
            base_score *= 0.8  # Reduce score for low confidence findings
        
        return max(0.0, min(10.0, base_score))
    
    def _calculate_temporal_score(self, vulnerability: Dict[str, Any], vuln_type: str) -> float:
        """Calculate temporal score based on exploit maturity and remediation."""
        
        # Exploit maturity factor
        exploit_maturity = self._assess_exploit_maturity(vuln_type)
        exploit_multipliers = {
            ExploitMaturity.NOT_DEFINED: 1.0,
            ExploitMaturity.UNPROVEN: 0.9,
            ExploitMaturity.PROOF_OF_CONCEPT: 0.95,
            ExploitMaturity.FUNCTIONAL: 1.0,
            ExploitMaturity.HIGH: 1.1
        }
        
        # Remediation level factor
        remediation_level = self._assess_remediation_level(vuln_type, vulnerability)
        remediation_multipliers = {
            RemediationLevel.OFFICIAL_FIX: 0.95,
            RemediationLevel.TEMPORARY_FIX: 1.0,
            RemediationLevel.WORKAROUND: 1.05,
            RemediationLevel.UNAVAILABLE: 1.1
        }
        
        base_score = self._calculate_base_score(vulnerability)
        temporal_multiplier = (
            exploit_multipliers[exploit_maturity] * 
            remediation_multipliers[remediation_level]
        )
        
        return base_score * temporal_multiplier
    
    def _calculate_environmental_score(self, base_score: float, 
                                     context: EnvironmentContext,
                                     vulnerability: Dict[str, Any]) -> float:
        """Calculate environmental score based on deployment context."""
        
        environmental_multiplier = 1.0
        
        # Deployment type impact
        environmental_multiplier *= self.environment_multipliers.get(
            context.deployment_type, 1.0
        )
        
        # Exposure level impact
        environmental_multiplier *= self.exposure_multipliers.get(
            context.exposure_level, 1.0
        )
        
        # Data sensitivity impact
        environmental_multiplier *= self.data_sensitivity_multipliers.get(
            context.data_sensitivity, 1.0
        )
        
        # Business criticality impact
        criticality_multipliers = {
            'critical': 1.8,
            'high': 1.4,
            'medium': 1.0,
            'low': 0.8
        }
        environmental_multiplier *= criticality_multipliers.get(
            context.business_criticality, 1.0
        )
        
        # Security controls impact (mitigating factors)
        if context.network_segmentation:
            environmental_multiplier *= 0.9
        if context.firewall_protection:
            environmental_multiplier *= 0.95
        if context.intrusion_detection:
            environmental_multiplier *= 0.9
        if context.authentication_required:
            environmental_multiplier *= 0.9
        
        # User privilege level impact
        privilege_multipliers = {
            'system': 1.5,
            'admin': 1.3,
            'user': 1.0,
            'anonymous': 1.2
        }
        environmental_multiplier *= privilege_multipliers.get(
            context.user_privilege_level, 1.0
        )
        
        return base_score * environmental_multiplier
    
    def _calculate_correlation_multiplier(self, correlations: List[Any]) -> float:
        """Calculate risk amplification from vulnerability correlations."""
        
        if not correlations:
            return 1.0
        
        # Base amplification
        amplification = 1.0
        
        for correlation in correlations:
            # Get correlation impact multiplier
            impact_amp = getattr(correlation, 'impact_amplification', 1.0)
            exploit_amp = getattr(correlation, 'exploitability_increase', 1.0)
            
            # Apply correlation-specific amplification
            correlation_type = getattr(correlation, 'correlation_type', None)
            if correlation_type:
                type_name = correlation_type.value if hasattr(correlation_type, 'value') else str(correlation_type)
                
                if 'attack_chain' in type_name:
                    amplification *= 1.2
                elif 'compound' in type_name:
                    amplification *= 1.4
                elif 'defense_bypass' in type_name:
                    amplification *= 1.6
                else:
                    amplification *= 1.1
        
        # Cap the maximum amplification
        return min(amplification, 2.5)
    
    def _calculate_overall_risk_score(self, base_score: float, temporal_score: float, 
                                    environmental_score: float) -> float:
        """Calculate overall risk score combining all factors."""
        
        # Weighted combination of scores
        overall_score = (
            base_score * 0.4 +
            temporal_score * 0.3 +
            environmental_score * 0.3
        )
        
        return max(0.0, min(10.0, overall_score))
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level category from score."""
        
        if risk_score >= 9.0:
            return "critical"
        elif risk_score >= 7.0:
            return "very_high"
        elif risk_score >= 5.0:
            return "high"
        elif risk_score >= 3.0:
            return "medium"
        elif risk_score >= 1.0:
            return "low"
        else:
            return "very_low"
    
    def _assess_business_impact(self, risk_score: float, context: EnvironmentContext, 
                              vuln_type: str) -> BusinessImpact:
        """Assess business impact level."""
        
        # Base business impact from risk score
        if risk_score >= 8.0:
            base_impact = BusinessImpact.CRITICAL
        elif risk_score >= 6.0:
            base_impact = BusinessImpact.HIGH
        elif risk_score >= 4.0:
            base_impact = BusinessImpact.MODERATE
        elif risk_score >= 2.0:
            base_impact = BusinessImpact.LOW
        else:
            base_impact = BusinessImpact.MINIMAL
        
        # Adjust based on business context
        if context.business_criticality == 'critical':
            if base_impact.value in ['moderate', 'high']:
                return BusinessImpact.CRITICAL
            elif base_impact == BusinessImpact.LOW:
                return BusinessImpact.MODERATE
        
        # Adjust based on compliance requirements
        if context.compliance_requirements:
            high_compliance = {'pci', 'hipaa', 'sox', 'gdpr', 'ccpa'}
            if any(req.lower() in high_compliance for req in context.compliance_requirements):
                if base_impact.value in ['low', 'moderate']:
                    return BusinessImpact.HIGH
                elif base_impact == BusinessImpact.HIGH:
                    return BusinessImpact.CRITICAL
        
        return base_impact
    
    def _calculate_likelihood_score(self, vulnerability: Dict[str, Any], 
                                  context: EnvironmentContext) -> float:
        """Calculate likelihood of exploitation."""
        
        likelihood = 0.5  # Base likelihood
        
        # Vulnerability type impact on likelihood
        vuln_type = vulnerability.get('vuln_type', '').lower()
        type_likelihoods = {
            'sql_injection': 0.8,
            'xss': 0.7,
            'authentication_bypass': 0.9,
            'command_injection': 0.8,
            'csrf': 0.6,
            'path_traversal': 0.7,
            'information_disclosure': 0.5,
            'configuration_issue': 0.4
        }
        
        for vuln_pattern, type_likelihood in type_likelihoods.items():
            if vuln_pattern in vuln_type:
                likelihood = type_likelihood
                break
        
        # Environmental factors
        if context.exposure_level == 'public':
            likelihood *= 1.5
        elif context.exposure_level == 'external':
            likelihood *= 1.2
        
        if not context.authentication_required:
            likelihood *= 1.3
        
        if context.user_privilege_level == 'anonymous':
            likelihood *= 1.4
        
        # Security controls reduce likelihood
        if context.firewall_protection:
            likelihood *= 0.9
        if context.intrusion_detection:
            likelihood *= 0.8
        if context.network_segmentation:
            likelihood *= 0.9
        
        return max(0.0, min(1.0, likelihood))
    
    def _calculate_impact_score(self, vulnerability: Dict[str, Any], 
                              context: EnvironmentContext) -> float:
        """Calculate impact score if vulnerability is exploited."""
        
        # Base impact from severity
        severity = vulnerability.get('severity', 'medium').lower()
        severity_impacts = {
            'critical': 0.9,
            'high': 0.7,
            'medium': 0.5,
            'low': 0.3,
            'info': 0.1
        }
        
        impact = severity_impacts.get(severity, 0.5)
        
        # Data sensitivity amplification
        if context.data_sensitivity == 'critical':
            impact *= 1.5
        elif context.data_sensitivity == 'high':
            impact *= 1.3
        
        # Business criticality amplification
        if context.business_criticality == 'critical':
            impact *= 1.4
        elif context.business_criticality == 'high':
            impact *= 1.2
        
        # Data access scope impact
        scope_multipliers = {
            'full': 1.5,
            'extensive': 1.3,
            'limited': 1.0,
            'none': 0.5
        }
        impact *= scope_multipliers.get(context.data_access_scope, 1.0)
        
        return max(0.0, min(1.0, impact))
    
    def _assess_exploit_maturity(self, vuln_type: str) -> ExploitMaturity:
        """Assess exploit maturity for vulnerability type."""
        
        # Well-known vulnerability types with mature exploits
        mature_exploits = {
            'sql_injection': ExploitMaturity.HIGH,
            'xss': ExploitMaturity.FUNCTIONAL,
            'command_injection': ExploitMaturity.HIGH,
            'path_traversal': ExploitMaturity.FUNCTIONAL,
            'authentication_bypass': ExploitMaturity.FUNCTIONAL
        }
        
        vuln_type_lower = vuln_type.lower()
        for pattern, maturity in mature_exploits.items():
            if pattern in vuln_type_lower:
                return maturity
        
        return ExploitMaturity.PROOF_OF_CONCEPT
    
    def _assess_remediation_level(self, vuln_type: str, vulnerability: Dict[str, Any]) -> RemediationLevel:
        """Assess remediation difficulty level."""
        
        # Check if fix is provided
        if vulnerability.get('fix') or vulnerability.get('recommendation'):
            return RemediationLevel.OFFICIAL_FIX
        
        # Common vulnerability types with known fixes
        easy_fixes = ['xss', 'csrf', 'information_disclosure']
        moderate_fixes = ['sql_injection', 'path_traversal', 'authentication']
        hard_fixes = ['design_flaw', 'architecture', 'logic_error']
        
        vuln_type_lower = vuln_type.lower()
        
        if any(pattern in vuln_type_lower for pattern in easy_fixes):
            return RemediationLevel.OFFICIAL_FIX
        elif any(pattern in vuln_type_lower for pattern in moderate_fixes):
            return RemediationLevel.TEMPORARY_FIX
        elif any(pattern in vuln_type_lower for pattern in hard_fixes):
            return RemediationLevel.WORKAROUND
        
        return RemediationLevel.TEMPORARY_FIX
    
    def _calculate_priority_score(self, risk_score: float, business_impact: BusinessImpact, 
                                likelihood: float) -> int:
        """Calculate priority score (1-10, higher = more urgent)."""
        
        # Base priority from risk score
        base_priority = int(risk_score)
        
        # Business impact adjustment
        impact_adjustments = {
            BusinessImpact.CRITICAL: +3,
            BusinessImpact.HIGH: +2,
            BusinessImpact.MODERATE: +1,
            BusinessImpact.LOW: 0,
            BusinessImpact.MINIMAL: -1
        }
        
        priority = base_priority + impact_adjustments.get(business_impact, 0)
        
        # Likelihood adjustment
        if likelihood > 0.8:
            priority += 2
        elif likelihood > 0.6:
            priority += 1
        elif likelihood < 0.3:
            priority -= 1
        
        return max(1, min(10, priority))
    
    def _determine_timeline(self, priority_score: int, risk_level: str) -> str:
        """Determine recommended remediation timeline."""
        
        if priority_score >= 9 or risk_level == "critical":
            return "immediate"
        elif priority_score >= 7 or risk_level == "very_high":
            return "short_term"
        elif priority_score >= 5 or risk_level == "high":
            return "medium_term"
        else:
            return "long_term"
    
    def _generate_mitigation_strategies(self, vulnerability: Dict[str, Any], 
                                      context: EnvironmentContext, risk_level: str) -> List[str]:
        """Generate contextual mitigation strategies."""
        
        strategies = []
        vuln_type = vulnerability.get('vuln_type', '').lower()
        
        # Vulnerability-specific mitigations
        if 'xss' in vuln_type:
            strategies.extend([
                "Implement proper output encoding/escaping",
                "Use Content Security Policy (CSP) headers",
                "Validate and sanitize all user inputs",
                "Use framework-provided XSS protection"
            ])
        
        elif 'sql_injection' in vuln_type:
            strategies.extend([
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege to database accounts",
                "Enable database query logging and monitoring"
            ])
        
        elif 'command_injection' in vuln_type:
            strategies.extend([
                "Avoid dynamic command execution",
                "Use safe APIs instead of shell commands",
                "Implement strict input validation",
                "Apply sandboxing and containerization"
            ])
        
        # Environmental mitigations
        if context.exposure_level == 'public':
            strategies.append("Implement Web Application Firewall (WAF)")
            
        if not context.intrusion_detection:
            strategies.append("Deploy intrusion detection/prevention system")
        
        if risk_level in ['critical', 'very_high']:
            strategies.extend([
                "Implement emergency response procedures",
                "Consider temporary service isolation",
                "Enhance monitoring and alerting"
            ])
        
        # Business context mitigations
        if context.compliance_requirements:
            strategies.append("Ensure compliance with regulatory requirements")
        
        if context.business_criticality in ['high', 'critical']:
            strategies.extend([
                "Implement business continuity measures",
                "Prepare incident response plan",
                "Consider redundancy and failover mechanisms"
            ])
        
        return strategies
    
    def _analyze_technical_factors(self, vulnerability: Dict[str, Any]) -> Dict[str, float]:
        """Analyze technical risk factors."""
        
        factors = {}
        
        # Severity factor
        severity = vulnerability.get('severity', 'medium').lower()
        severity_scores = {
            'critical': 1.0, 'high': 0.8, 'medium': 0.6, 'low': 0.4, 'info': 0.2
        }
        factors['severity'] = severity_scores.get(severity, 0.6)
        
        # Complexity factor
        description = vulnerability.get('description', '').lower()
        if any(word in description for word in ['complex', 'difficult', 'advanced']):
            factors['complexity'] = 0.8
        elif any(word in description for word in ['simple', 'easy', 'basic']):
            factors['complexity'] = 0.3
        else:
            factors['complexity'] = 0.5
        
        # Confidence factor
        confidence = float(vulnerability.get('confidence', 0.5))
        factors['confidence'] = confidence
        
        return factors
    
    def _analyze_environmental_factors(self, context: EnvironmentContext) -> Dict[str, float]:
        """Analyze environmental risk factors."""
        
        factors = {}
        
        # Deployment environment
        deployment_scores = {'production': 1.0, 'staging': 0.6, 'development': 0.3}
        factors['deployment'] = deployment_scores.get(context.deployment_type, 0.6)
        
        # Exposure level
        exposure_scores = {'public': 1.0, 'external': 0.7, 'internal': 0.4}
        factors['exposure'] = exposure_scores.get(context.exposure_level, 0.4)
        
        # Security controls
        security_score = 1.0
        if context.firewall_protection:
            security_score *= 0.8
        if context.intrusion_detection:
            security_score *= 0.7
        if context.network_segmentation:
            security_score *= 0.9
        factors['security_controls'] = 1.0 - security_score
        
        return factors
    
    def _analyze_business_factors(self, context: EnvironmentContext, vuln_type: str) -> Dict[str, float]:
        """Analyze business risk factors."""
        
        factors = {}
        
        # Business criticality
        criticality_scores = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.3}
        factors['business_criticality'] = criticality_scores.get(context.business_criticality, 0.5)
        
        # Data sensitivity
        sensitivity_scores = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.3}
        factors['data_sensitivity'] = sensitivity_scores.get(context.data_sensitivity, 0.5)
        
        # Compliance impact
        factors['compliance_impact'] = 0.8 if context.compliance_requirements else 0.2
        
        return factors
    
    def _generate_assessment_reasoning(self, vulnerability: Dict[str, Any], 
                                     context: EnvironmentContext, risk_score: float) -> List[str]:
        """Generate human-readable reasoning for the risk assessment."""
        
        reasoning = []
        
        # Risk score explanation
        if risk_score >= 8.0:
            reasoning.append("High risk score due to severe potential impact and high exploitability")
        elif risk_score >= 6.0:
            reasoning.append("Elevated risk score due to significant security implications")
        elif risk_score >= 4.0:
            reasoning.append("Moderate risk score requiring attention and remediation")
        else:
            reasoning.append("Lower risk score but still requires monitoring")
        
        # Environmental factors
        if context.deployment_type == 'production':
            reasoning.append("Production environment increases risk impact")
        
        if context.exposure_level == 'public':
            reasoning.append("Public exposure significantly increases attack likelihood")
        
        if context.data_sensitivity in ['high', 'critical']:
            reasoning.append("High data sensitivity amplifies potential business impact")
        
        # Vulnerability characteristics
        vuln_type = vulnerability.get('vuln_type', '').lower()
        if 'injection' in vuln_type:
            reasoning.append("Injection vulnerabilities pose severe security risks")
        
        if 'authentication' in vuln_type or 'authorization' in vuln_type:
            reasoning.append("Access control issues can lead to privilege escalation")
        
        # Mitigating factors
        if context.firewall_protection and context.intrusion_detection:
            reasoning.append("Security controls in place provide some risk mitigation")
        
        return reasoning
    
    def _update_assessment_stats(self, assessment: RiskAssessment):
        """Update risk assessment statistics."""
        
        self.assessment_stats['total_assessments'] += 1
        
        # Count risk levels
        risk_level = assessment.risk_level
        self.assessment_stats['risk_level_distribution'][risk_level] = (
            self.assessment_stats['risk_level_distribution'].get(risk_level, 0) + 1
        )
        
        # Count high/critical risks
        if risk_level in ['very_high', 'critical']:
            if risk_level == 'critical':
                self.assessment_stats['critical_risk_count'] += 1
            self.assessment_stats['high_risk_count'] += 1
        
        # Update average risk score
        total = self.assessment_stats['total_assessments']
        current_avg = self.assessment_stats['average_risk_score']
        new_score = assessment.overall_risk_score
        
        self.assessment_stats['average_risk_score'] = (
            (current_avg * (total - 1) + new_score) / total
        )
    
    def get_risk_statistics(self) -> Dict[str, Any]:
        """Get risk assessment statistics."""
        
        stats = dict(self.assessment_stats)
        
        if stats['total_assessments'] > 0:
            stats['high_risk_percentage'] = (
                stats['high_risk_count'] / stats['total_assessments'] * 100
            )
            stats['critical_risk_percentage'] = (
                stats['critical_risk_count'] / stats['total_assessments'] * 100
            )
        
        return stats
    
    def calculate_portfolio_risk(self, assessments: List[RiskAssessment]) -> Dict[str, Any]:
        """Calculate overall portfolio risk from multiple assessments."""
        
        if not assessments:
            return {'portfolio_risk_score': 0.0, 'risk_distribution': {}}
        
        # Calculate weighted portfolio risk
        total_risk = sum(assessment.overall_risk_score for assessment in assessments)
        portfolio_risk_score = total_risk / len(assessments)
        
        # Risk distribution
        risk_distribution = {}
        for assessment in assessments:
            level = assessment.risk_level
            risk_distribution[level] = risk_distribution.get(level, 0) + 1
        
        # Critical path analysis (highest risk vulnerabilities)
        critical_path = sorted(assessments, key=lambda a: a.overall_risk_score, reverse=True)[:5]
        
        # Business impact summary
        business_impacts = [a.business_impact.value for a in assessments]
        most_common_impact = max(set(business_impacts), key=business_impacts.count)
        
        return {
            'portfolio_risk_score': round(portfolio_risk_score, 2),
            'total_vulnerabilities': len(assessments),
            'risk_distribution': risk_distribution,
            'critical_path': [
                {
                    'vulnerability_id': a.vulnerability_id,
                    'risk_score': a.overall_risk_score,
                    'priority': a.priority_score
                }
                for a in critical_path
            ],
            'predominant_business_impact': most_common_impact,
            'immediate_action_required': len([a for a in assessments if a.recommended_timeline == 'immediate']),
            'average_priority': sum(a.priority_score for a in assessments) / len(assessments)
        }
