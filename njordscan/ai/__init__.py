"""
AI-Powered Security Analysis Module for NjordScan.
Consolidated AI and Intelligence capabilities.
"""

from .code_understanding import CodeUnderstandingEngine
from .security_advisor import SecurityAdvisor
from .ai_orchestrator import AISecurityOrchestrator

# New AI-powered npm attack detection modules
from .ai_package_analyzer import AIPackageAnalyzer, AIPackageThreatType, PackageRiskLevel
from .ai_code_fingerprinting import AICodeFingerprinter, CodePatternType, FingerprintConfidence
from .package_similarity_analyzer import PackageSimilarityAnalyzer, SimilarityType, ThreatLevel
from .maintainer_profile_analyzer import MaintainerProfileAnalyzer, MaintainerRiskLevel, SuspiciousPattern

# Import from consolidated intelligence module
from ..intelligence.threat_intelligence import ThreatIntelligenceEngine
from ..intelligence.behavioral_analyzer import BehavioralAnalyzer

__all__ = [
    'ThreatIntelligenceEngine',
    'CodeUnderstandingEngine',
    'BehavioralAnalyzer',
    'SecurityAdvisor',
    'AISecurityOrchestrator',
    # New AI-powered npm attack detection modules
    'AIPackageAnalyzer',
    'AIPackageThreatType',
    'PackageRiskLevel',
    'AICodeFingerprinter',
    'CodePatternType',
    'FingerprintConfidence',
    'PackageSimilarityAnalyzer',
    'SimilarityType',
    'ThreatLevel',
    'MaintainerProfileAnalyzer',
    'MaintainerRiskLevel',
    'SuspiciousPattern'
]
