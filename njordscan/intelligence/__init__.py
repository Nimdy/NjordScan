"""
Security Intelligence System for NjordScan.

This module provides comprehensive security intelligence capabilities including:
- Rules engine for security pattern matching
- Threat intelligence and indicator analysis
- Behavioral analysis and anomaly detection
- False positive filtering and validation
- Vulnerability classification and scoring
- Intelligence correlation and fusion
"""

from .intelligence_orchestrator import (
    IntelligenceOrchestrator, 
    IntelligenceMode, 
    ThreatLevel, 
    AnalysisScope,
    IntelligenceFinding,
    IntelligenceReport
)
from .rules_engine import RulesEngine, RuleEngineConfig, SecurityRule, RuleMatch
from .threat_intelligence import ThreatIntelligenceEngine, ThreatIntelligenceConfig, ThreatIndicator
from .behavioral_analyzer import BehavioralAnalyzer, BehavioralAnalysisConfig, BehaviorEvent, AnomalyDetection
from .false_positive_filter import FalsePositiveFilter, FalsePositiveConfig
from .vulnerability_classifier import VulnerabilityClassifier, ClassificationResult

__all__ = [
    'IntelligenceOrchestrator',
    'IntelligenceMode',
    'ThreatLevel',
    'AnalysisScope',
    'IntelligenceFinding',
    'IntelligenceReport',
    'RulesEngine',
    'RuleEngineConfig',
    'SecurityRule',
    'RuleMatch',
    'ThreatIntelligenceEngine',
    'ThreatIntelligenceConfig',
    'ThreatIndicator',
    'BehavioralAnalyzer',
    'BehavioralAnalysisConfig',
    'BehaviorEvent',
    'AnomalyDetection',
    'FalsePositiveFilter',
    'FalsePositiveConfig',
    'VulnerabilityClassifier',
    'ClassificationResult'
]