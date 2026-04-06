"""
Heuristic Security Analysis for NjordScan

NOTE: Despite the "ai" package name (kept for backward compatibility), this
module does NOT use machine learning, LLMs, or neural networks.  All detection
is rule-based: regex pattern matching, string-similarity scoring (e.g.
Levenshtein / SequenceMatcher), entropy calculations, and weighted heuristics.

Modules:
  - ai_package_analyzer:       Regex + similarity heuristics for npm package risk
  - ai_code_fingerprinting:    Regex-based obfuscation / minification detection
  - code_understanding:        Lexical feature extraction (LOC, entropy, comments)
  - package_similarity_analyzer: String-distance typosquatting detection
  - maintainer_profile_analyzer: Metadata heuristics for maintainer anomalies
  - security_advisor:          Lookup-table remediation recommendations
  - ai_orchestrator:           Orchestrates the above modules
"""

from .code_understanding import CodeUnderstandingEngine
from .security_advisor import SecurityAdvisor
from .ai_orchestrator import AISecurityOrchestrator

# Heuristic npm attack detection modules
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
