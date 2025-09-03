"""
Integrated Intelligence Engine for NjordScan

Orchestrates all intelligence components for comprehensive vulnerability analysis.
"""

import asyncio
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import logging

from .vulnerability_classifier import VulnerabilityClassifier, ClassificationResult
from .correlation_engine import CorrelationEngine, VulnerabilityCorrelation
from .risk_calculator import RiskCalculator, RiskAssessment, EnvironmentContext
from .false_positive_filter import FalsePositiveFilter, FilterResult
from .vulnerability_prioritizer import VulnerabilityPrioritizer, PriorityScore, PrioritizationContext
from ..vulnerability_types import normalize_vulnerability_type, get_vulnerability_type_info

logger = logging.getLogger(__name__)

@dataclass
class IntelligenceReport:
    """Comprehensive intelligence analysis report."""
    
    # Input data
    total_vulnerabilities: int
    analysis_duration: float
    
    # Classification results
    classifications: List[ClassificationResult]
    classification_summary: Dict[str, Any]
    
    # Correlation analysis
    correlations: List[VulnerabilityCorrelation]
    attack_paths: List[Any]
    correlation_summary: Dict[str, Any]
    
    # Risk assessments
    risk_assessments: List[RiskAssessment]
    portfolio_risk: Dict[str, Any]
    risk_summary: Dict[str, Any]
    
    # False positive filtering
    filter_results: List[FilterResult]
    filtered_vulnerabilities: List[Dict[str, Any]]
    filter_summary: Dict[str, Any]
    
    # Prioritization
    priority_scores: List[PriorityScore]
    top_priorities: List[PriorityScore]
    immediate_actions: List[PriorityScore]
    prioritization_summary: Dict[str, Any]
    
    # Overall insights
    key_insights: List[str]
    recommended_actions: List[str]
    risk_trends: Dict[str, Any]

class IntelligenceEngine:
    """Integrated intelligence engine orchestrating all analysis components."""
    
    def __init__(self):
        # Initialize all intelligence components
        self.classifier = VulnerabilityClassifier()
        self.correlation_engine = CorrelationEngine()
        self.risk_calculator = RiskCalculator()
        self.fp_filter = FalsePositiveFilter()
        self.prioritizer = VulnerabilityPrioritizer()
        
        # Configuration
        self.config = {
            'enable_classification': True,
            'enable_correlation': True,
            'enable_risk_assessment': True,
            'enable_fp_filtering': True,
            'enable_prioritization': True,
            'parallel_processing': True,
            'max_concurrent': 10
        }
        
        # Analysis statistics
        self.stats = {
            'total_analyses': 0,
            'average_analysis_time': 0.0,
            'component_performance': {},
            'accuracy_metrics': {}
        }
    
    async def analyze_vulnerabilities(self, 
                                    vulnerabilities: List[Dict[str, Any]],
                                    environment_context: Optional[EnvironmentContext] = None,
                                    prioritization_context: Optional[PrioritizationContext] = None,
                                    code_context: Optional[Dict[str, Dict[str, Any]]] = None) -> IntelligenceReport:
        """Perform comprehensive intelligence analysis on vulnerabilities."""
        
        import time
        start_time = time.time()
        
        logger.info(f"Starting intelligence analysis on {len(vulnerabilities)} vulnerabilities")
        
        # Initialize contexts if not provided
        if environment_context is None:
            environment_context = EnvironmentContext()
        
        if prioritization_context is None:
            prioritization_context = PrioritizationContext()
        
        if code_context is None:
            code_context = {}
        
        # Phase 1: Classification and False Positive Filtering
        logger.info("Phase 1: Classification and false positive filtering")
        classifications, filter_results, filtered_vulnerabilities = await self._phase1_classify_and_filter(
            vulnerabilities, code_context
        )
        
        # Phase 2: Correlation Analysis
        logger.info("Phase 2: Correlation analysis")
        correlations, attack_paths = await self._phase2_correlation_analysis(filtered_vulnerabilities)
        
        # Phase 3: Risk Assessment
        logger.info("Phase 3: Risk assessment")
        risk_assessments, portfolio_risk = await self._phase3_risk_assessment(
            filtered_vulnerabilities, environment_context, correlations
        )
        
        # Phase 4: Prioritization
        logger.info("Phase 4: Vulnerability prioritization")
        priority_scores, top_priorities, immediate_actions = await self._phase4_prioritization(
            filtered_vulnerabilities, risk_assessments, correlations, prioritization_context
        )
        
        # Phase 5: Insights Generation
        logger.info("Phase 5: Generating insights and recommendations")
        key_insights, recommended_actions, risk_trends = await self._phase5_generate_insights(
            classifications, correlations, risk_assessments, priority_scores
        )
        
        # Calculate analysis duration
        analysis_duration = time.time() - start_time
        
        # Create comprehensive report
        report = IntelligenceReport(
            total_vulnerabilities=len(vulnerabilities),
            analysis_duration=analysis_duration,
            
            classifications=classifications,
            classification_summary=self._generate_classification_summary(classifications),
            
            correlations=correlations,
            attack_paths=attack_paths,
            correlation_summary=self._generate_correlation_summary(correlations, attack_paths),
            
            risk_assessments=risk_assessments,
            portfolio_risk=portfolio_risk,
            risk_summary=self._generate_risk_summary(risk_assessments, portfolio_risk),
            
            filter_results=filter_results,
            filtered_vulnerabilities=filtered_vulnerabilities,
            filter_summary=self._generate_filter_summary(filter_results, len(vulnerabilities)),
            
            priority_scores=priority_scores,
            top_priorities=top_priorities,
            immediate_actions=immediate_actions,
            prioritization_summary=self._generate_prioritization_summary(priority_scores),
            
            key_insights=key_insights,
            recommended_actions=recommended_actions,
            risk_trends=risk_trends
        )
        
        # Update statistics
        self._update_analysis_stats(report)
        
        logger.info(f"Intelligence analysis completed in {analysis_duration:.2f} seconds")
        
        return report
    
    async def _phase1_classify_and_filter(self, vulnerabilities: List[Dict[str, Any]], 
                                        code_context: Dict[str, Dict[str, Any]]) -> tuple:
        """Phase 1: Classify vulnerabilities and filter false positives."""
        
        classifications = []
        filter_results = []
        filtered_vulnerabilities = []
        
        if self.config['parallel_processing']:
            # Process in parallel
            semaphore = asyncio.Semaphore(self.config['max_concurrent'])
            
            async def process_vulnerability(vuln):
                async with semaphore:
                    return await self._process_single_vulnerability_phase1(vuln, code_context)
            
            tasks = [process_vulnerability(vuln) for vuln in vulnerabilities]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Phase 1 processing failed: {result}")
                    continue
                
                classification, filter_result, should_include = result
                classifications.append(classification)
                filter_results.append(filter_result)
                
                if should_include:
                    filtered_vulnerabilities.append(vulnerabilities[len(filtered_vulnerabilities)])
        
        else:
            # Process sequentially
            for vuln in vulnerabilities:
                try:
                    classification, filter_result, should_include = await self._process_single_vulnerability_phase1(
                        vuln, code_context
                    )
                    
                    classifications.append(classification)
                    filter_results.append(filter_result)
                    
                    if should_include:
                        filtered_vulnerabilities.append(vuln)
                
                except Exception as e:
                    logger.error(f"Phase 1 processing failed for vulnerability: {e}")
        
        return classifications, filter_results, filtered_vulnerabilities
    
    async def _process_single_vulnerability_phase1(self, vulnerability: Dict[str, Any], 
                                                 code_context: Dict[str, Dict[str, Any]]) -> tuple:
        """Process a single vulnerability in phase 1."""
        
        vuln_id = vulnerability.get('id', str(hash(str(vulnerability))))
        vuln_code_context = code_context.get(vuln_id)
        
        # Classification
        classification = None
        if self.config['enable_classification']:
            classification = self.classifier.classify_vulnerability(
                vulnerability, 
                vuln_code_context.get('code_content') if vuln_code_context else None,
                vuln_code_context.get('file_context') if vuln_code_context else None
            )
        
        # False positive filtering
        filter_result = None
        should_include = True
        
        if self.config['enable_fp_filtering']:
            filter_result = self.fp_filter.filter_vulnerability(vulnerability, vuln_code_context)
            
            # Decide whether to include based on filter result
            if filter_result.is_likely_false_positive and filter_result.confidence > 0.7:
                should_include = False
            elif filter_result.adjusted_severity:
                # Update severity if suggested
                vulnerability['severity'] = filter_result.adjusted_severity
        
        return classification, filter_result, should_include
    
    async def _phase2_correlation_analysis(self, vulnerabilities: List[Dict[str, Any]]) -> tuple:
        """Phase 2: Analyze vulnerability correlations."""
        
        correlations = []
        attack_paths = []
        
        if self.config['enable_correlation'] and len(vulnerabilities) > 1:
            # Perform correlation analysis
            correlations = self.correlation_engine.analyze_vulnerabilities(vulnerabilities)
            attack_paths = self.correlation_engine.get_attack_paths()
        
        return correlations, attack_paths
    
    async def _phase3_risk_assessment(self, vulnerabilities: List[Dict[str, Any]], 
                                    environment_context: EnvironmentContext,
                                    correlations: List[VulnerabilityCorrelation]) -> tuple:
        """Phase 3: Perform risk assessment."""
        
        risk_assessments = []
        portfolio_risk = {}
        
        if self.config['enable_risk_assessment']:
            # Create correlation lookup for each vulnerability
            correlation_lookup = {}
            for correlation in correlations:
                primary_id = correlation.primary_vulnerability
                if primary_id not in correlation_lookup:
                    correlation_lookup[primary_id] = []
                correlation_lookup[primary_id].append(correlation)
                
                for related_id in correlation.related_vulnerabilities:
                    if related_id not in correlation_lookup:
                        correlation_lookup[related_id] = []
                    correlation_lookup[related_id].append(correlation)
            
            # Assess risk for each vulnerability
            for vulnerability in vulnerabilities:
                vuln_id = vulnerability.get('id', str(hash(str(vulnerability))))
                vuln_correlations = correlation_lookup.get(vuln_id, [])
                
                risk_assessment = self.risk_calculator.calculate_risk(
                    vulnerability, environment_context, vuln_correlations
                )
                risk_assessments.append(risk_assessment)
            
            # Calculate portfolio risk
            if risk_assessments:
                portfolio_risk = self.risk_calculator.calculate_portfolio_risk(risk_assessments)
        
        return risk_assessments, portfolio_risk
    
    async def _phase4_prioritization(self, vulnerabilities: List[Dict[str, Any]],
                                   risk_assessments: List[RiskAssessment],
                                   correlations: List[VulnerabilityCorrelation],
                                   prioritization_context: PrioritizationContext) -> tuple:
        """Phase 4: Prioritize vulnerabilities."""
        
        priority_scores = []
        top_priorities = []
        immediate_actions = []
        
        if self.config['enable_prioritization']:
            # Perform prioritization
            priority_scores = self.prioritizer.prioritize_vulnerabilities(
                vulnerabilities, risk_assessments, correlations, prioritization_context
            )
            
            # Get top priorities and immediate actions
            top_priorities = self.prioritizer.get_top_priorities(priority_scores, count=10)
            immediate_actions = self.prioritizer.get_immediate_action_items(priority_scores)
        
        return priority_scores, top_priorities, immediate_actions
    
    async def _phase5_generate_insights(self, classifications: List[ClassificationResult],
                                      correlations: List[VulnerabilityCorrelation],
                                      risk_assessments: List[RiskAssessment],
                                      priority_scores: List[PriorityScore]) -> tuple:
        """Phase 5: Generate insights and recommendations."""
        
        key_insights = []
        recommended_actions = []
        risk_trends = {}
        
        # Analyze classification patterns
        if classifications:
            class_distribution = {}
            for classification in classifications:
                class_name = classification.primary_class.value
                class_distribution[class_name] = class_distribution.get(class_name, 0) + 1
            
            # Find dominant vulnerability classes
            dominant_classes = sorted(class_distribution.items(), key=lambda x: x[1], reverse=True)[:3]
            
            if dominant_classes:
                key_insights.append(
                    f"Top vulnerability categories: {', '.join([f'{cls} ({count})' for cls, count in dominant_classes])}"
                )
                
                # Recommend actions based on dominant classes
                for class_name, count in dominant_classes:
                    if class_name == 'injection':
                        recommended_actions.append("Implement comprehensive input validation and parameterized queries")
                    elif class_name == 'broken_access_control':
                        recommended_actions.append("Review and strengthen access control mechanisms")
                    elif class_name == 'cryptographic_failure':
                        recommended_actions.append("Audit and upgrade cryptographic implementations")
        
        # Analyze correlation patterns
        if correlations:
            attack_chains = [c for c in correlations if 'attack_chain' in str(c.correlation_type)]
            compound_vulns = [c for c in correlations if 'compound' in str(c.correlation_type)]
            
            if attack_chains:
                key_insights.append(f"Identified {len(attack_chains)} potential attack chains")
                recommended_actions.append("Prioritize fixing vulnerabilities that enable attack chains")
            
            if compound_vulns:
                key_insights.append(f"Found {len(compound_vulns)} compound vulnerabilities with amplified impact")
                recommended_actions.append("Address compound vulnerabilities as unified remediation efforts")
        
        # Analyze risk patterns
        if risk_assessments:
            high_risk_count = sum(1 for ra in risk_assessments if ra.overall_risk_score >= 7.0)
            critical_risk_count = sum(1 for ra in risk_assessments if ra.overall_risk_score >= 9.0)
            
            if critical_risk_count > 0:
                key_insights.append(f"{critical_risk_count} vulnerabilities pose critical risk")
                recommended_actions.append("Immediate action required for critical risk vulnerabilities")
            
            if high_risk_count > len(risk_assessments) * 0.3:  # More than 30% high risk
                key_insights.append("High concentration of high-risk vulnerabilities detected")
                recommended_actions.append("Consider comprehensive security review and remediation program")
            
            # Risk trends
            risk_trends = {
                'total_vulnerabilities': len(risk_assessments),
                'critical_risk': critical_risk_count,
                'high_risk': high_risk_count,
                'average_risk_score': sum(ra.overall_risk_score for ra in risk_assessments) / len(risk_assessments),
                'risk_distribution': self._calculate_risk_distribution(risk_assessments)
            }
        
        # Analyze prioritization patterns
        if priority_scores:
            immediate_count = len([ps for ps in priority_scores if ps.recommended_fix_timeline == 'immediate'])
            
            if immediate_count > 0:
                key_insights.append(f"{immediate_count} vulnerabilities require immediate attention")
                recommended_actions.append("Establish incident response for immediate priority vulnerabilities")
        
        # General recommendations
        if not recommended_actions:
            recommended_actions.append("Continue regular security scanning and monitoring")
        
        recommended_actions.append("Implement continuous security testing in CI/CD pipeline")
        recommended_actions.append("Provide security training for development team")
        
        return key_insights, recommended_actions, risk_trends
    
    def _generate_classification_summary(self, classifications: List[ClassificationResult]) -> Dict[str, Any]:
        """Generate classification analysis summary."""
        
        if not classifications:
            return {'total_classifications': 0}
        
        # Count by class
        class_counts = {}
        confidence_scores = []
        
        for classification in classifications:
            class_name = classification.primary_class.value
            class_counts[class_name] = class_counts.get(class_name, 0) + 1
            confidence_scores.append(classification.confidence)
        
        return {
            'total_classifications': len(classifications),
            'class_distribution': class_counts,
            'average_confidence': sum(confidence_scores) / len(confidence_scores),
            'high_confidence_rate': sum(1 for c in confidence_scores if c > 0.8) / len(confidence_scores)
        }
    
    def _generate_correlation_summary(self, correlations: List[VulnerabilityCorrelation], 
                                    attack_paths: List[Any]) -> Dict[str, Any]:
        """Generate correlation analysis summary."""
        
        if not correlations:
            return {'total_correlations': 0, 'attack_paths': 0}
        
        # Count by correlation type
        type_counts = {}
        for correlation in correlations:
            correlation_type = correlation.correlation_type.value
            type_counts[correlation_type] = type_counts.get(correlation_type, 0) + 1
        
        # High impact correlations
        high_impact = sum(1 for c in correlations if c.impact_amplification > 1.5)
        
        return {
            'total_correlations': len(correlations),
            'correlation_types': type_counts,
            'attack_paths': len(attack_paths),
            'high_impact_correlations': high_impact,
            'average_impact_amplification': sum(c.impact_amplification for c in correlations) / len(correlations)
        }
    
    def _generate_risk_summary(self, risk_assessments: List[RiskAssessment], 
                             portfolio_risk: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk assessment summary."""
        
        if not risk_assessments:
            return {'total_assessments': 0}
        
        risk_levels = {}
        for assessment in risk_assessments:
            level = assessment.risk_level
            risk_levels[level] = risk_levels.get(level, 0) + 1
        
        return {
            'total_assessments': len(risk_assessments),
            'risk_level_distribution': risk_levels,
            'portfolio_risk_score': portfolio_risk.get('portfolio_risk_score', 0.0),
            'average_risk_score': sum(ra.overall_risk_score for ra in risk_assessments) / len(risk_assessments),
            'immediate_action_required': portfolio_risk.get('immediate_action_required', 0)
        }
    
    def _generate_filter_summary(self, filter_results: List[FilterResult], 
                               original_count: int) -> Dict[str, Any]:
        """Generate false positive filtering summary."""
        
        if not filter_results:
            return {'total_filtered': 0, 'false_positives_detected': 0}
        
        fp_detected = sum(1 for fr in filter_results if fr.is_likely_false_positive)
        severity_adjusted = sum(1 for fr in filter_results if fr.adjusted_severity)
        
        return {
            'total_filtered': len(filter_results),
            'original_vulnerability_count': original_count,
            'false_positives_detected': fp_detected,
            'false_positive_rate': fp_detected / len(filter_results) if filter_results else 0,
            'severity_adjustments': severity_adjusted,
            'average_filter_confidence': sum(fr.confidence for fr in filter_results) / len(filter_results)
        }
    
    def _generate_prioritization_summary(self, priority_scores: List[PriorityScore]) -> Dict[str, Any]:
        """Generate prioritization summary."""
        
        if not priority_scores:
            return {'total_prioritized': 0}
        
        # Count by priority level
        priority_counts = {}
        timeline_counts = {}
        
        for score in priority_scores:
            level = score.priority_level.value
            timeline = score.recommended_fix_timeline
            
            priority_counts[level] = priority_counts.get(level, 0) + 1
            timeline_counts[timeline] = timeline_counts.get(timeline, 0) + 1
        
        return {
            'total_prioritized': len(priority_scores),
            'priority_distribution': priority_counts,
            'timeline_distribution': timeline_counts,
            'average_priority_score': sum(ps.overall_priority_score for ps in priority_scores) / len(priority_scores),
            'immediate_action_items': sum(1 for ps in priority_scores if ps.recommended_fix_timeline == 'immediate')
        }
    
    def _calculate_risk_distribution(self, risk_assessments: List[RiskAssessment]) -> Dict[str, int]:
        """Calculate risk score distribution."""
        
        distribution = {
            '0-2': 0, '2-4': 0, '4-6': 0, '6-8': 0, '8-10': 0
        }
        
        for assessment in risk_assessments:
            score = assessment.overall_risk_score
            
            if score < 2:
                distribution['0-2'] += 1
            elif score < 4:
                distribution['2-4'] += 1
            elif score < 6:
                distribution['4-6'] += 1
            elif score < 8:
                distribution['6-8'] += 1
            else:
                distribution['8-10'] += 1
        
        return distribution
    
    def _update_analysis_stats(self, report: IntelligenceReport):
        """Update analysis statistics."""
        
        self.stats['total_analyses'] += 1
        
        # Update average analysis time
        current_avg = self.stats['average_analysis_time']
        new_time = report.analysis_duration
        total_analyses = self.stats['total_analyses']
        
        self.stats['average_analysis_time'] = (
            (current_avg * (total_analyses - 1) + new_time) / total_analyses
        )
        
        # Component performance tracking
        components = ['classification', 'correlation', 'risk_assessment', 'filtering', 'prioritization']
        for component in components:
            if component not in self.stats['component_performance']:
                self.stats['component_performance'][component] = {
                    'total_processed': 0,
                    'average_time': 0.0,
                    'success_rate': 1.0
                }
        
        # Update component stats (simplified - in production would track individual component times)
        for component in components:
            comp_stats = self.stats['component_performance'][component]
            comp_stats['total_processed'] += report.total_vulnerabilities
    
    def get_intelligence_statistics(self) -> Dict[str, Any]:
        """Get comprehensive intelligence engine statistics."""
        
        return {
            'engine_stats': dict(self.stats),
            'component_stats': {
                'classifier': self.classifier.get_classification_statistics(),
                'correlation_engine': self.correlation_engine.get_correlation_statistics(),
                'risk_calculator': self.risk_calculator.get_risk_statistics(),
                'fp_filter': self.fp_filter.get_filter_statistics(),
                'prioritizer': self.prioritizer.get_prioritization_statistics()
            }
        }
    
    def configure_engine(self, config_updates: Dict[str, Any]):
        """Update engine configuration."""
        
        self.config.update(config_updates)
        logger.info(f"Intelligence engine configuration updated: {config_updates}")
    
    def enhance_vulnerabilities_with_intelligence(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance vulnerabilities with intelligence analysis and standardized types."""
        enhanced_vulnerabilities = []
        
        for vuln_dict in vulnerabilities:
            # Normalize vulnerability type
            vuln_type = vuln_dict.get('vuln_type', '')
            normalized_type = normalize_vulnerability_type(vuln_type)
            
            if normalized_type:
                # Get type information from registry
                type_info = get_vulnerability_type_info(normalized_type)
                if type_info:
                    # Enhance vulnerability with intelligence context
                    enhanced_vuln = vuln_dict.copy()
                    
                    # Add standardized type information
                    enhanced_vuln['vuln_type'] = normalized_type.value
                    enhanced_vuln['normalized_type'] = normalized_type.value
                    
                    # Add CWE codes and OWASP category
                    if 'metadata' not in enhanced_vuln:
                        enhanced_vuln['metadata'] = {}
                    
                    enhanced_vuln['metadata']['cwe_codes'] = [cwe.value for cwe in type_info.cwe_codes]
                    enhanced_vuln['metadata']['owasp_category'] = type_info.category.value
                    
                    # Add intelligence analysis context
                    enhanced_vuln['metadata']['intelligence_analysis'] = {
                        'analyzed': True,
                        'type_normalized': True,
                        'cwe_mapped': True,
                        'owasp_categorized': True,
                        'enhancement_timestamp': time.time()
                    }
                    
                    # Use registry information for missing fields
                    if not enhanced_vuln.get('fix') and type_info.remediation:
                        enhanced_vuln['fix'] = type_info.remediation
                    if not enhanced_vuln.get('reference') and type_info.references:
                        enhanced_vuln['reference'] = type_info.references[0]
                    if not enhanced_vuln.get('description') and type_info.description:
                        enhanced_vuln['description'] = type_info.description
                    
                    enhanced_vulnerabilities.append(enhanced_vuln)
                else:
                    enhanced_vulnerabilities.append(vuln_dict)
            else:
                enhanced_vulnerabilities.append(vuln_dict)
        
        return enhanced_vulnerabilities
    
    def learn_from_feedback(self, vulnerability_data: Dict[str, Any], 
                          feedback: Dict[str, Any]):
        """Learn from user feedback to improve analysis accuracy."""
        
        # Distribute feedback to relevant components
        if 'classification_feedback' in feedback:
            class_feedback = feedback['classification_feedback']
            self.classifier.train_from_feedback(
                vulnerability_data,
                class_feedback.get('correct_classification'),
                class_feedback.get('confidence', 1.0)
            )
        
        if 'false_positive_feedback' in feedback:
            fp_feedback = feedback['false_positive_feedback']
            self.fp_filter.learn_from_feedback(
                vulnerability_data,
                fp_feedback.get('is_false_positive', False),
                fp_feedback.get('confidence', 1.0)
            )
        
        logger.info("Intelligence engine learned from user feedback")
