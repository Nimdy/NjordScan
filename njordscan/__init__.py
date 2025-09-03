"""
🛡️ NjordScan v1.0.0 - The Ultimate Security Scanner

The most advanced, comprehensive, and developer-friendly security scanner for modern 
JavaScript applications. Built specifically for Next.js, React, and Vite applications,
combining cutting-edge AI, community-driven intelligence, and enterprise-grade performance.

Features:
- 🧠 AI-Powered Intelligence with ML-enhanced vulnerability detection
- ⚡ Enterprise-Grade Performance with multi-threaded scanning
- 🎨 Amazing Developer Experience with interactive CLI and IDE integration
- 🌟 Community Ecosystem with shared security rules and threat intelligence
- 🔄 Complete CI/CD Integration for all major platforms
- 🛡️ Comprehensive Security Coverage with 25+ standardized vulnerability types aligned with OWASP Top 10 2021

Author: NjordScan Contributors
License: MIT
Homepage: https://njordscan.dev
Repository: https://github.com/nimdy/njordscan
"""

__version__ = "1.0.0"
__title__ = "njordscan"
__description__ = "The Ultimate Security Scanner for Next.js, React, and Vite Applications"
__author__ = "NjordScan Contributors"
__author_email__ = "info@njordscan.dev"
__maintainer__ = "Nimdy"
__maintainer_email__ = "info@hackme.ai"
__license__ = "MIT"
__url__ = "https://njordscan.dev"
__repository__ = "https://github.com/nimdy/njordscan"
__documentation__ = "https://njordscan.dev/docs"
__status__ = "Production/Stable"

# Core imports
from .scanner import ScanOrchestrator
from .config import Config
from .vulnerability import Vulnerability, Severity, Confidence
from .vulnerability_types import VulnerabilityType, normalize_vulnerability_type

# Version info tuple for programmatic access
__version_info__ = tuple(int(x) for x in __version__.split('.'))

# All public API exports
__all__ = [
    # Core classes
    "ScanOrchestrator", 
    "Config",
    "Vulnerability",
    "Severity", 
    "Confidence",
    "VulnerabilityType",
    "normalize_vulnerability_type",
    
    # Metadata
    "__version__",
    "__version_info__",
    "__title__",
    "__description__",
    "__author__",
    "__license__",
    "__url__",
]

# Banner for CLI display
BANNER = f"""
🛡️  NjordScan v{__version__} - The Ultimate Security Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🧠 AI-Powered  ⚡ Enterprise-Grade  🎨 Developer-Friendly  🌟 Community-Driven
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# Feature flags for conditional imports and functionality
FEATURES = {
    "ai_enhanced": True,
    "behavioral_analysis": True, 
    "threat_intelligence": True,
    "community_features": True,
    "enterprise_features": True,
    "plugin_system": True,
    "ide_integration": True,
    "cicd_integration": True,
    "advanced_reporting": True,
    "performance_optimization": True,
}

def get_version():
    """Get the current version string."""
    return __version__

def get_version_info():
    """Get version information as a dictionary."""
    return {
        "version": __version__,
        "version_info": __version_info__,
        "title": __title__,
        "description": __description__,
        "author": __author__,
        "license": __license__,
        "url": __url__,
        "repository": __repository__,
        "documentation": __documentation__,
        "status": __status__,
    }

def print_banner():
    """Print the NjordScan banner."""
    print(BANNER)