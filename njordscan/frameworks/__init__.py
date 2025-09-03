"""
Framework-Specific Deep Analysis Modules for NjordScan.
"""

from .nextjs_analyzer import NextJSAnalyzer
from .react_analyzer import ReactAnalyzer
from .vite_analyzer import ViteAnalyzer
from .framework_detector import FrameworkDetector
from .base_framework_analyzer import BaseFrameworkAnalyzer

__all__ = [
    'NextJSAnalyzer',
    'ReactAnalyzer',
    'ViteAnalyzer',
    'FrameworkDetector',
    'BaseFrameworkAnalyzer'
]
