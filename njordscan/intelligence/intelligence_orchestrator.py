"""
Security Intelligence Orchestrator

Master orchestrator for all security intelligence systems:
- Coordinates rules engine, threat intelligence, and behavioral analysis
- Provides unified security intelligence interface
- Manages cross-system correlation and analysis
- Orchestrates intelligent threat detection workflows
- Handles security intelligence data fusion
- Manages adaptive learning and optimization
"""

import asyncio
import time
import logging
from typing import Dict, List, Any, Optional, Union, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json
from collections import defaultdict

from .rules_engine import RulesEngine, RuleEngineConfig, SecurityRule, RuleMatch
from .threat_intelligence import ThreatIntelligenceEngine, ThreatIntelligenceConfig, ThreatIndicator
from .behavioral_analyzer import BehavioralAnalyzer, BehavioralAnalysisConfig, BehaviorEvent, AnomalyDetection

logger = logging.getLogger(__name__)

class IntelligenceMode(Enum):
    """Intelligence analysis modes."""
    PASSIVE = "passive"        # Basic rule matching
    ACTIVE = "active"          # Enhanced analysis with threat intel
    ADAPTIVE = "adaptive"      # ML-enhanced with behavioral analysis
    COMPREHENSIVE = "comprehensive"  # Full intelligence fusion

class ThreatLevel(Enum):
    """Unified threat levels."""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

class AnalysisScope(Enum):
    """Scope of intelligence analysis."""
    FILE = "file"
    MODULE = "module"
    APPLICATION = "application"
    ECOSYSTEM = "ecosystem"

@dataclass
class IntelligenceFinding:
    """Unified intelligence finding."""
    finding_id: str
    finding_type: str  # rule_match, threat_indicator, behavioral_anomaly, correlation
    
    # Core information
    title: str
    description: str
    severity: ThreatLevel
    confidence: float
    
    # Location and context
    file_path: str = ""
    line_number: int = 0
    code_context: str = ""
    
    # Classification
    categories: Set[str] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)
    
    # Evidence and attribution
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    correlations: List[str] = field(default_factory=list)
    threat_actors: Set[str] = field(default_factory=set)
    
    # Risk assessment
    risk_score: float = 0.0
    impact_assessment: str = ""
    exploitability: str = "unknown"
    
    # Recommendations
    remediation_advice: List[str] = field(default_factory=list)
    prevention_measures: List[str] = field(default_factory=list)
    
    # Metadata
    detection_time: float = field(default_factory=time.time)
    source_systems: Set[str] = field(default_factory=set)
    false_positive_likelihood: float = 0.0
    
    # References
    references: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)

@dataclass
class IntelligenceReport:
    """Comprehensive intelligence analysis report."""
    report_id: str
    analysis_scope: AnalysisScope
    target_path: str
    
    # Summary
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    overall_risk_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.LOW
    
    # Findings
    findings: List[IntelligenceFinding] = field(default_factory=list)
    
    # Analysis breakdown
    rules_analysis: Dict[str, Any] = field(default_factory=dict)
    threat_analysis: Dict[str, Any] = field(default_factory=dict)
    behavioral_analysis: Dict[str, Any] = field(default_factory=dict)
    correlation_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Intelligence insights
    threat_landscape: Dict[str, Any] = field(default_factory=dict)
    attack_patterns: List[str] = field(default_factory=list)
    threat_actors: Set[str] = field(default_factory=set)
    
    # Recommendations
    priority_actions: List[str] = field(default_factory=list)
    strategic_recommendations: List[str] = field(default_factory=list)
    compliance_notes: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_time: float = field(default_factory=time.time)
    analysis_duration: float = 0.0
    intelligence_sources: Set[str] = field(default_factory=set)
    
    def add_finding(self, finding: IntelligenceFinding):
        """Add finding to report."""
        self.findings.append(finding)
        self.total_findings += 1
        
        # Update severity counts
        severity_key = finding.severity.value
        self.findings_by_severity[severity_key] = self.findings_by_severity.get(severity_key, 0) + 1
        
        # Update overall risk
        self._update_overall_risk()
        
        # Update threat actors
        self.threat_actors.update(finding.threat_actors)
    
    def _update_overall_risk(self):
        """Update overall risk assessment."""
        if not self.findings:
            self.overall_risk_score = 0.0
            self.threat_level = ThreatLevel.MINIMAL
            return
        
        # Calculate weighted risk score
        severity_weights = {
            ThreatLevel.MINIMAL: 0.1,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.MEDIUM: 0.6,
            ThreatLevel.HIGH: 0.8,
            ThreatLevel.CRITICAL: 1.0,
            ThreatLevel.EMERGENCY: 1.2
        }
        
        total_weighted_score = 0.0
        for finding in self.findings:
            weight = severity_weights.get(finding.severity, 0.5)
            total_weighted_score += weight * finding.confidence
        
        self.overall_risk_score = min(1.0, total_weighted_score / len(self.findings))
        
        # Determine threat level
        if self.overall_risk_score >= 0.9:
            self.threat_level = ThreatLevel.EMERGENCY
        elif self.overall_risk_score >= 0.8:
            self.threat_level = ThreatLevel.CRITICAL
        elif self.overall_risk_score >= 0.6:
            self.threat_level = ThreatLevel.HIGH
        elif self.overall_risk_score >= 0.4:
            self.threat_level = ThreatLevel.MEDIUM
        elif self.overall_risk_score >= 0.2:
            self.threat_level = ThreatLevel.LOW
        else:
            self.threat_level = ThreatLevel.MINIMAL

@dataclass
class IntelligenceOrchestratorConfig:
    """Configuration for intelligence orchestrator."""
    
    # Core settings
    intelligence_mode: IntelligenceMode = IntelligenceMode.COMPREHENSIVE
    enable_cross_system_correlation: bool = True
    enable_adaptive_learning: bool = True
    
    # Analysis settings
    enable_deep_analysis: bool = True
    analysis_timeout_seconds: float = 300.0
    max_concurrent_analyses: int = 5
    
    # Correlation settings
    correlation_threshold: float = 0.7
    enable_temporal_correlation: bool = True
    correlation_window_minutes: int = 60
    
    # Risk assessment
    enable_dynamic_risk_scoring: bool = True
    risk_aggregation_method: str = "weighted_average"  # max, average, weighted_average
    false_positive_penalty: float = 0.2
    
    # Intelligence fusion
    enable_threat_actor_attribution: bool = True
    enable_attack_pattern_recognition: bool = True
    enable_campaign_tracking: bool = True
    
    # Performance optimization
    enable_intelligent_caching: bool = True
    cache_analysis_results: bool = True
    cache_ttl_seconds: int = 3600
    
    # Component configurations
    rules_config: RuleEngineConfig = field(default_factory=RuleEngineConfig)
    threat_intel_config: ThreatIntelligenceConfig = field(default_factory=ThreatIntelligenceConfig)
    behavioral_config: BehavioralAnalysisConfig = field(default_factory=BehavioralAnalysisConfig)
    
    # Reporting and output
    enable_detailed_reporting: bool = True
    include_remediation_guidance: bool = True
    include_threat_context: bool = True
    
    # Learning and adaptation
    learning_rate: float = 0.1
    adaptation_threshold: float = 0.8
    feedback_integration: bool = True

class IntelligenceOrchestrator:
    """Master security intelligence orchestrator."""
    
    def __init__(self, config: IntelligenceOrchestratorConfig = None):
        self.config = config or IntelligenceOrchestratorConfig()
        
        # Initialize intelligence engines
        self.rules_engine = RulesEngine(self.config.rules_config)
        self.threat_intel_engine = ThreatIntelligenceEngine(self.config.threat_intel_config)
        self.behavioral_analyzer = BehavioralAnalyzer(self.config.behavioral_config)
        
        # Correlation and fusion
        self.correlation_engine = CorrelationEngine(self.config)
        self.intelligence_fusion = IntelligenceFusion(self.config)
        self.risk_assessor = RiskAssessor(self.config)
        
        # Learning and adaptation
        if self.config.enable_adaptive_learning:
            self.adaptive_learner = AdaptiveLearner(self.config)
        else:
            self.adaptive_learner = None
        
        # Analysis cache
        self.analysis_cache: Dict[str, IntelligenceReport] = {}
        
        # State management
        self.active_analyses: Dict[str, Dict[str, Any]] = {}
        self.analysis_history: List[IntelligenceReport] = []
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Statistics
        self.stats = {
            'analyses_performed': 0,
            'findings_generated': 0,
            'correlations_found': 0,
            'threat_actors_identified': 0,
            'false_positives_filtered': 0,
            'total_analysis_time': 0.0,
            'average_analysis_time': 0.0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        self.start_time = time.time()
    
    async def initialize(self):
        """Initialize intelligence orchestrator."""
        
        logger.info("Initializing Security Intelligence Orchestrator")
        
        self.running = True
        
        # Initialize core engines
        await self.rules_engine.initialize()
        await self.threat_intel_engine.initialize()
        await self.behavioral_analyzer.initialize()
        
        # Initialize analysis components
        await self.correlation_engine.initialize()
        await self.intelligence_fusion.initialize()
        await self.risk_assessor.initialize()
        
        if self.adaptive_learner:
            await self.adaptive_learner.initialize()
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._correlation_worker()),
            asyncio.create_task(self._cache_cleanup_worker()),
            asyncio.create_task(self._intelligence_update_worker())
        ]
        
        if self.config.enable_adaptive_learning:
            self.background_tasks.append(
                asyncio.create_task(self._adaptive_learning_worker())
            )
        
        logger.info("Security Intelligence Orchestrator initialized")
    
    async def analyze_security_intelligence(self, file_path: str, content: str,
                                          context: Dict[str, Any] = None) -> IntelligenceReport:
        """Perform comprehensive security intelligence analysis."""
        
        analysis_start = time.time()
        analysis_id = f"analysis_{int(analysis_start)}_{hash(file_path)}"
        
        logger.info(f"Starting security intelligence analysis: {file_path}")
        
        try:
            context = context or {}
            
            # Check cache first
            cache_key = self._generate_cache_key(file_path, content, context)
            if self.config.enable_intelligent_caching and cache_key in self.analysis_cache:
                self.stats['cache_hits'] += 1
                logger.debug(f"Cache hit for analysis: {file_path}")
                return self.analysis_cache[cache_key]
            
            self.stats['cache_misses'] += 1
            
            # Create analysis report
            report = IntelligenceReport(
                report_id=analysis_id,
                analysis_scope=AnalysisScope.FILE,
                target_path=file_path
            )
            
            # Track active analysis
            self.active_analyses[analysis_id] = {
                'start_time': analysis_start,
                'file_path': file_path,
                'status': 'running'
            }
            
            # Phase 1: Rules-based analysis
            rules_results = await self._analyze_with_rules(file_path, content, context)
            report.rules_analysis = rules_results
            report.intelligence_sources.add('rules_engine')
            
            # Phase 2: Threat intelligence analysis
            if self.config.intelligence_mode in [IntelligenceMode.ACTIVE, IntelligenceMode.ADAPTIVE, 
                                               IntelligenceMode.COMPREHENSIVE]:
                threat_results = await self._analyze_with_threat_intel(file_path, content, context)
                report.threat_analysis = threat_results
                report.intelligence_sources.add('threat_intelligence')
            
            # Phase 3: Behavioral analysis
            if self.config.intelligence_mode in [IntelligenceMode.ADAPTIVE, IntelligenceMode.COMPREHENSIVE]:
                behavioral_results = await self._analyze_with_behavioral_analysis(file_path, content, context)
                report.behavioral_analysis = behavioral_results
                report.intelligence_sources.add('behavioral_analysis')
            
            # Phase 4: Cross-system correlation
            if self.config.enable_cross_system_correlation:
                correlation_results = await self._perform_correlation_analysis(
                    rules_results, threat_results if 'threat_results' in locals() else {},
                    behavioral_results if 'behavioral_results' in locals() else {}
                )
                report.correlation_analysis = correlation_results
            
            # Phase 5: Intelligence fusion and risk assessment
            await self._fuse_intelligence(report, context)
            
            # Phase 6: Generate recommendations
            await self._generate_recommendations(report, context)
            
            # Finalize report
            report.analysis_duration = time.time() - analysis_start
            
            # Cache results
            if self.config.cache_analysis_results:
                self.analysis_cache[cache_key] = report
            
            # Update statistics
            self.stats['analyses_performed'] += 1
            self.stats['findings_generated'] += len(report.findings)
            self.stats['total_analysis_time'] += report.analysis_duration
            self.stats['average_analysis_time'] = (
                self.stats['total_analysis_time'] / self.stats['analyses_performed']
            )
            
            # Store in history
            self.analysis_history.append(report)
            if len(self.analysis_history) > 1000:  # Keep last 1000 analyses
                self.analysis_history.pop(0)
            
            # Clean up active analysis
            if analysis_id in self.active_analyses:
                del self.active_analyses[analysis_id]
            
            logger.info(f"Security intelligence analysis completed: {file_path} "
                       f"({len(report.findings)} findings, {report.analysis_duration:.2f}s)")
            
            return report
            
        except Exception as e:
            logger.error(f"Security intelligence analysis failed for {file_path}: {str(e)}")
            
            # Clean up on error
            if analysis_id in self.active_analyses:
                del self.active_analyses[analysis_id]
            
            # Return error report
            error_report = IntelligenceReport(
                report_id=analysis_id,
                analysis_scope=AnalysisScope.FILE,
                target_path=file_path
            )
            error_report.analysis_duration = time.time() - analysis_start
            
            return error_report
    
    async def get_threat_landscape_analysis(self, scope: AnalysisScope = AnalysisScope.APPLICATION,
                                          timeframe_days: int = 30) -> Dict[str, Any]:
        """Get comprehensive threat landscape analysis."""
        
        try:
            logger.info(f"Generating threat landscape analysis (scope: {scope.value})")
            
            # Get threat intelligence landscape
            threat_landscape = await self.threat_intel_engine.get_threat_landscape(timeframe_days)
            
            # Analyze recent findings
            recent_analyses = [
                analysis for analysis in self.analysis_history
                if time.time() - analysis.analysis_time < (timeframe_days * 86400)
            ]
            
            # Aggregate findings
            total_findings = sum(len(analysis.findings) for analysis in recent_analyses)
            findings_by_type = defaultdict(int)
            threat_actors = set()
            attack_patterns = set()
            
            for analysis in recent_analyses:
                for finding in analysis.findings:
                    findings_by_type[finding.finding_type] += 1
                    threat_actors.update(finding.threat_actors)
                    if finding.mitre_techniques:
                        attack_patterns.update(finding.mitre_techniques)
            
            # Risk trend analysis
            risk_trend = await self._calculate_risk_trend(recent_analyses)
            
            # Top threats
            top_threats = await self._identify_top_threats(recent_analyses)
            
            landscape_analysis = {
                'analysis_scope': scope.value,
                'timeframe_days': timeframe_days,
                'generated_at': time.time(),
                'summary': {
                    'total_analyses': len(recent_analyses),
                    'total_findings': total_findings,
                    'unique_threat_actors': len(threat_actors),
                    'attack_techniques_observed': len(attack_patterns)
                },
                'threat_intelligence': threat_landscape,
                'findings_analysis': {
                    'by_type': dict(findings_by_type),
                    'top_threats': top_threats,
                    'risk_trend': risk_trend
                },
                'threat_actors': list(threat_actors)[:20],  # Top 20
                'attack_patterns': list(attack_patterns)[:30],  # Top 30
                'recommendations': await self._generate_landscape_recommendations(recent_analyses)
            }
            
            return landscape_analysis
            
        except Exception as e:
            logger.error(f"Threat landscape analysis failed: {str(e)}")
            return {'error': str(e)}
    
    async def correlate_findings(self, findings: List[IntelligenceFinding],
                               context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Correlate intelligence findings across different sources."""
        
        try:
            return await self.correlation_engine.correlate_findings(findings, context or {})
        except Exception as e:
            logger.error(f"Finding correlation failed: {str(e)}")
            return {}
    
    async def add_feedback(self, finding_id: str, feedback_type: str, 
                         feedback_data: Dict[str, Any]):
        """Add feedback for adaptive learning."""
        
        if not self.adaptive_learner:
            return
        
        try:
            await self.adaptive_learner.add_feedback(finding_id, feedback_type, feedback_data)
            logger.debug(f"Feedback added for finding: {finding_id}")
        except Exception as e:
            logger.error(f"Failed to add feedback: {str(e)}")
    
    async def get_intelligence_metrics(self) -> Dict[str, Any]:
        """Get comprehensive intelligence metrics."""
        
        try:
            # Base statistics
            metrics = dict(self.stats)
            metrics['uptime'] = time.time() - self.start_time
            
            # Component statistics
            metrics['components'] = {
                'rules_engine': self.rules_engine.get_statistics(),
                'threat_intelligence': self.threat_intel_engine.get_statistics(),
                'behavioral_analyzer': self.behavioral_analyzer.get_statistics()
            }
            
            # Analysis metrics
            if self.analysis_history:
                recent_analyses = [
                    analysis for analysis in self.analysis_history
                    if time.time() - analysis.analysis_time < 86400  # Last 24 hours
                ]
                
                if recent_analyses:
                    metrics['recent_analysis'] = {
                        'count': len(recent_analyses),
                        'average_findings': sum(len(a.findings) for a in recent_analyses) / len(recent_analyses),
                        'average_risk_score': sum(a.overall_risk_score for a in recent_analyses) / len(recent_analyses),
                        'threat_levels': {
                            level.value: sum(1 for a in recent_analyses if a.threat_level == level)
                            for level in ThreatLevel
                        }
                    }
            
            # Cache metrics
            metrics['cache'] = {
                'size': len(self.analysis_cache),
                'hit_rate': self.stats['cache_hits'] / max(1, self.stats['cache_hits'] + self.stats['cache_misses']),
                'active_analyses': len(self.active_analyses)
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get intelligence metrics: {str(e)}")
            return {}
    
    # Private analysis methods
    
    async def _analyze_with_rules(self, file_path: str, content: str, 
                                context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze with rules engine."""
        
        try:
            rule_matches = await self.rules_engine.analyze_code(file_path, content, context)
            
            # Convert to intelligence findings
            findings = []
            for match in rule_matches:
                finding = await self._create_finding_from_rule_match(match, file_path)
                findings.append(finding)
            
            return {
                'matches_found': len(rule_matches),
                'findings': findings,
                'analysis_time': time.time()
            }
            
        except Exception as e:
            logger.error(f"Rules analysis failed: {str(e)}")
            return {'error': str(e)}
    
    async def _analyze_with_threat_intel(self, file_path: str, content: str,
                                       context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze with threat intelligence."""
        
        try:
            threat_matches = await self.threat_intel_engine.check_indicators(content, file_path, context)
            
            # Convert to intelligence findings
            findings = []
            for match in threat_matches:
                finding = await self._create_finding_from_threat_match(match, file_path)
                findings.append(finding)
            
            return {
                'indicators_matched': len(threat_matches),
                'findings': findings,
                'analysis_time': time.time()
            }
            
        except Exception as e:
            logger.error(f"Threat intelligence analysis failed: {str(e)}")
            return {'error': str(e)}
    
    async def _analyze_with_behavioral_analysis(self, file_path: str, content: str,
                                              context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze with behavioral analyzer."""
        
        try:
            behavioral_results = await self.behavioral_analyzer.analyze_code_behavior(
                file_path, content, context
            )
            
            # Convert anomalies to intelligence findings
            findings = []
            for anomaly_data in behavioral_results.get('anomalies', []):
                finding = await self._create_finding_from_behavioral_anomaly(anomaly_data, file_path)
                findings.append(finding)
            
            return {
                'events_detected': len(behavioral_results.get('events', [])),
                'sequences_created': len(behavioral_results.get('sequences', [])),
                'anomalies_found': len(behavioral_results.get('anomalies', [])),
                'findings': findings,
                'risk_assessment': behavioral_results.get('risk_assessment', {}),
                'analysis_time': time.time()
            }
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {str(e)}")
            return {'error': str(e)}
    
    async def _perform_correlation_analysis(self, rules_results: Dict[str, Any],
                                          threat_results: Dict[str, Any],
                                          behavioral_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform cross-system correlation analysis."""
        
        try:
            # Collect all findings
            all_findings = []
            all_findings.extend(rules_results.get('findings', []))
            all_findings.extend(threat_results.get('findings', []))
            all_findings.extend(behavioral_results.get('findings', []))
            
            if not all_findings:
                return {'correlations_found': 0}
            
            # Perform correlation
            correlations = await self.correlation_engine.correlate_findings(all_findings)
            
            self.stats['correlations_found'] += len(correlations.get('correlations', []))
            
            return correlations
            
        except Exception as e:
            logger.error(f"Correlation analysis failed: {str(e)}")
            return {'error': str(e)}
    
    async def _fuse_intelligence(self, report: IntelligenceReport, context: Dict[str, Any]):
        """Fuse intelligence from multiple sources."""
        
        try:
            # Collect all findings
            all_findings = []
            
            # Add findings from different analysis phases
            for analysis_result in [report.rules_analysis, report.threat_analysis, report.behavioral_analysis]:
                all_findings.extend(analysis_result.get('findings', []))
            
            # Perform intelligence fusion
            fused_findings = await self.intelligence_fusion.fuse_findings(all_findings, context)
            
            # Add fused findings to report
            for finding in fused_findings:
                report.add_finding(finding)
            
            # Perform risk assessment
            risk_assessment = await self.risk_assessor.assess_risk(report.findings, context)
            report.overall_risk_score = risk_assessment.get('overall_risk_score', 0.0)
            
            # Update threat level based on fused intelligence
            report._update_overall_risk()
            
        except Exception as e:
            logger.error(f"Intelligence fusion failed: {str(e)}")
    
    async def _generate_recommendations(self, report: IntelligenceReport, context: Dict[str, Any]):
        """Generate actionable recommendations."""
        
        try:
            # Priority actions based on critical findings
            critical_findings = [f for f in report.findings if f.severity == ThreatLevel.CRITICAL]
            high_findings = [f for f in report.findings if f.severity == ThreatLevel.HIGH]
            
            if critical_findings:
                report.priority_actions.append("Address critical security vulnerabilities immediately")
                report.priority_actions.extend([f.remediation_advice[0] for f in critical_findings if f.remediation_advice])
            
            if high_findings:
                report.priority_actions.append("Review and remediate high-severity issues")
            
            # Strategic recommendations
            if len(report.findings) > 10:
                report.strategic_recommendations.append("Consider implementing automated security scanning in CI/CD pipeline")
            
            if report.threat_actors:
                report.strategic_recommendations.append("Implement threat actor-specific monitoring and detection")
            
            # Compliance recommendations
            mitre_techniques = set()
            for finding in report.findings:
                mitre_techniques.update(finding.mitre_techniques)
            
            if mitre_techniques:
                report.compliance_notes.append(f"Detected techniques: {', '.join(list(mitre_techniques)[:5])}")
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {str(e)}")
    
    # Finding creation methods
    
    async def _create_finding_from_rule_match(self, match: RuleMatch, file_path: str) -> IntelligenceFinding:
        """Create intelligence finding from rule match."""
        
        # Get rule details (would need to be implemented in rules engine)
        rule_id = match.rule_id
        
        finding = IntelligenceFinding(
            finding_id=f"rule_{match.match_id}",
            finding_type="rule_match",
            title=f"Security Rule Violation: {rule_id}",
            description=f"Rule {rule_id} matched at line {match.line_number}",
            severity=ThreatLevel.MEDIUM,  # Would map from rule severity
            confidence=match.confidence_score,
            file_path=file_path,
            line_number=match.line_number,
            code_context=match.matched_text,
            source_systems={"rules_engine"}
        )
        
        return finding
    
    async def _create_finding_from_threat_match(self, match: Dict[str, Any], file_path: str) -> IntelligenceFinding:
        """Create intelligence finding from threat intelligence match."""
        
        finding = IntelligenceFinding(
            finding_id=f"threat_{match['indicator_id']}",
            finding_type="threat_indicator",
            title=f"Threat Indicator Detected: {match['indicator_type']}",
            description=match.get('description', ''),
            severity=ThreatLevel(match.get('severity', 'medium')),
            confidence=match.get('confidence', 0.5),
            file_path=file_path,
            mitre_techniques=set(match.get('mitre_techniques', [])),
            threat_actors=set(match.get('threat_actors', [])),
            source_systems={"threat_intelligence"}
        )
        
        return finding
    
    async def _create_finding_from_behavioral_anomaly(self, anomaly: Dict[str, Any], 
                                                    file_path: str) -> IntelligenceFinding:
        """Create intelligence finding from behavioral anomaly."""
        
        finding = IntelligenceFinding(
            finding_id=f"behavioral_{anomaly['anomaly_id']}",
            finding_type="behavioral_anomaly",
            title=f"Behavioral Anomaly: {anomaly['anomaly_type']}",
            description=anomaly['description'],
            severity=ThreatLevel(anomaly.get('severity', 'medium')),
            confidence=anomaly.get('confidence', 0.5),
            file_path=file_path,
            source_systems={"behavioral_analysis"},
            false_positive_likelihood=anomaly.get('false_positive_likelihood', 0.0)
        )
        
        return finding
    
    # Utility methods
    
    def _generate_cache_key(self, file_path: str, content: str, context: Dict[str, Any]) -> str:
        """Generate cache key for analysis results."""
        
        import hashlib
        
        # Create hash from file path, content hash, and context
        content_hash = hashlib.md5(content.encode()).hexdigest()
        context_hash = hashlib.md5(json.dumps(context, sort_keys=True).encode()).hexdigest()
        
        return f"{file_path}_{content_hash}_{context_hash}"
    
    async def _calculate_risk_trend(self, analyses: List[IntelligenceReport]) -> Dict[str, Any]:
        """Calculate risk trend from historical analyses."""
        
        if len(analyses) < 2:
            return {'trend': 'insufficient_data'}
        
        # Sort by analysis time
        sorted_analyses = sorted(analyses, key=lambda a: a.analysis_time)
        
        # Calculate trend
        recent_risk = sum(a.overall_risk_score for a in sorted_analyses[-10:]) / min(10, len(sorted_analyses))
        older_risk = sum(a.overall_risk_score for a in sorted_analyses[:-10]) / max(1, len(sorted_analyses) - 10)
        
        if recent_risk > older_risk * 1.1:
            trend = 'increasing'
        elif recent_risk < older_risk * 0.9:
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'recent_average': recent_risk,
            'historical_average': older_risk,
            'change_percentage': ((recent_risk - older_risk) / max(0.01, older_risk)) * 100
        }
    
    async def _identify_top_threats(self, analyses: List[IntelligenceReport]) -> List[Dict[str, Any]]:
        """Identify top threats from analyses."""
        
        threat_counts = defaultdict(int)
        threat_severity = defaultdict(list)
        
        for analysis in analyses:
            for finding in analysis.findings:
                threat_key = f"{finding.finding_type}_{finding.title}"
                threat_counts[threat_key] += 1
                threat_severity[threat_key].append(finding.severity.value)
        
        # Sort by frequency and severity
        top_threats = []
        for threat, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            avg_severity = max(threat_severity[threat])  # Use highest severity seen
            top_threats.append({
                'threat': threat,
                'occurrences': count,
                'severity': avg_severity
            })
        
        return top_threats
    
    async def _generate_landscape_recommendations(self, analyses: List[IntelligenceReport]) -> List[str]:
        """Generate recommendations based on threat landscape."""
        
        recommendations = []
        
        total_findings = sum(len(a.findings) for a in analyses)
        if total_findings > 100:
            recommendations.append("High volume of security findings detected - prioritize automated remediation")
        
        critical_count = sum(
            len([f for f in a.findings if f.severity == ThreatLevel.CRITICAL])
            for a in analyses
        )
        if critical_count > 0:
            recommendations.append(f"{critical_count} critical vulnerabilities require immediate attention")
        
        return recommendations
    
    # Background workers
    
    async def _correlation_worker(self):
        """Background correlation analysis worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.correlation_window_minutes * 60)
                
                # Perform background correlation on recent analyses
                recent_analyses = [
                    analysis for analysis in self.analysis_history
                    if time.time() - analysis.analysis_time < self.config.correlation_window_minutes * 60
                ]
                
                if len(recent_analyses) >= 2:
                    logger.debug("Running background correlation analysis")
                    # Implementation would perform cross-analysis correlation
                
            except Exception as e:
                logger.error(f"Correlation worker error: {str(e)}")
    
    async def _cache_cleanup_worker(self):
        """Background cache cleanup worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Clean up expired cache entries
                current_time = time.time()
                expired_keys = []
                
                for cache_key, report in self.analysis_cache.items():
                    if current_time - report.analysis_time > self.config.cache_ttl_seconds:
                        expired_keys.append(cache_key)
                
                for key in expired_keys:
                    del self.analysis_cache[key]
                
                logger.debug(f"Cache cleanup: removed {len(expired_keys)} expired entries")
                
            except Exception as e:
                logger.error(f"Cache cleanup worker error: {str(e)}")
    
    async def _intelligence_update_worker(self):
        """Background intelligence update worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(86400)  # Run daily
                
                # Update threat intelligence
                logger.info("Updating threat intelligence data")
                # Implementation would trigger threat intelligence updates
                
            except Exception as e:
                logger.error(f"Intelligence update worker error: {str(e)}")
    
    async def _adaptive_learning_worker(self):
        """Background adaptive learning worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                if self.adaptive_learner:
                    await self.adaptive_learner.update_models()
                
            except Exception as e:
                logger.error(f"Adaptive learning worker error: {str(e)}")
    
    async def shutdown(self):
        """Shutdown intelligence orchestrator."""
        
        logger.info("Shutting down Security Intelligence Orchestrator")
        
        self.running = False
        self.shutdown_event.set()
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for background tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Shutdown components
        await self.rules_engine.shutdown()
        await self.threat_intel_engine.shutdown()
        await self.behavioral_analyzer.shutdown()
        await self.correlation_engine.shutdown()
        await self.intelligence_fusion.shutdown()
        await self.risk_assessor.shutdown()
        
        if self.adaptive_learner:
            await self.adaptive_learner.shutdown()
        
        logger.info("Security Intelligence Orchestrator shutdown completed")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        
        stats = dict(self.stats)
        stats['uptime'] = time.time() - self.start_time
        stats['analysis_history_size'] = len(self.analysis_history)
        stats['cache_size'] = len(self.analysis_cache)
        stats['active_analyses'] = len(self.active_analyses)
        
        return stats


# Helper classes (stubs - would be implemented based on specific requirements)

class CorrelationEngine:
    """Cross-system correlation engine."""
    
    def __init__(self, config: IntelligenceOrchestratorConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def correlate_findings(self, findings: List[IntelligenceFinding], 
                               context: Dict[str, Any] = None) -> Dict[str, Any]:
        return {'correlations': []}
    
    async def shutdown(self):
        pass


class IntelligenceFusion:
    """Intelligence fusion engine."""
    
    def __init__(self, config: IntelligenceOrchestratorConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def fuse_findings(self, findings: List[IntelligenceFinding], 
                          context: Dict[str, Any]) -> List[IntelligenceFinding]:
        return findings  # Placeholder
    
    async def shutdown(self):
        pass


class RiskAssessor:
    """Risk assessment engine."""
    
    def __init__(self, config: IntelligenceOrchestratorConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def assess_risk(self, findings: List[IntelligenceFinding], 
                        context: Dict[str, Any]) -> Dict[str, Any]:
        if not findings:
            return {'overall_risk_score': 0.0}
        
        # Simple risk calculation
        total_risk = sum(f.risk_score * f.confidence for f in findings)
        avg_risk = total_risk / len(findings)
        
        return {'overall_risk_score': min(1.0, avg_risk)}
    
    async def shutdown(self):
        pass


class AdaptiveLearner:
    """Adaptive learning engine."""
    
    def __init__(self, config: IntelligenceOrchestratorConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def add_feedback(self, finding_id: str, feedback_type: str, 
                         feedback_data: Dict[str, Any]):
        pass
    
    async def update_models(self):
        pass
    
    async def shutdown(self):
        pass
