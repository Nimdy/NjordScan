"""
Static Analysis Components for NjordScan.
"""

from .ast_analyzer import JavaScriptASTAnalyzer, TypeScriptASTAnalyzer
from .pattern_engine import PatternEngine, SecurityPattern

try:
    from .taint_tracker import TaintTracker, TREE_SITTER_AVAILABLE
except ImportError:
    TaintTracker = None
    TREE_SITTER_AVAILABLE = False

__all__ = [
    'JavaScriptASTAnalyzer',
    'TypeScriptASTAnalyzer',
    'PatternEngine',
    'SecurityPattern',
    'TaintTracker',
    'TREE_SITTER_AVAILABLE',
]
