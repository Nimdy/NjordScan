"""
Advanced Dependency Security Analysis Module for NjordScan.

This module provides comprehensive dependency security analysis including:
- Software Bill of Materials (SBOM) generation
- Vulnerability database integration and analysis
- Supply chain risk assessment
- License compliance checking
- Dependency graph analysis and attack surface mapping
"""

from .dependency_analyzer import DependencyAnalyzer
from .sbom_generator import SBOMGenerator
from .vulnerability_scanner import VulnerabilityScanner
from .supply_chain_analyzer import SupplyChainAnalyzer
from .license_analyzer import LicenseAnalyzer
from .dependency_orchestrator import DependencySecurityOrchestrator

__all__ = [
    'DependencyAnalyzer',
    'SBOMGenerator',
    'VulnerabilityScanner', 
    'SupplyChainAnalyzer',
    'LicenseAnalyzer',
    'DependencySecurityOrchestrator'
]
