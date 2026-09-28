"""Unified analyzer contracts and compatibility adapters."""

from m_hunter.analyzers.adapters import LegacyAnalyzerAdapter
from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.capabilities import AnalyzerCapabilities
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.analyzers.result import AnalysisResult

__all__ = [
    "AnalysisContext",
    "AnalysisResult",
    "AnalyzerCapabilities",
    "AnalyzerRegistry",
    "BaseAnalyzer",
    "LegacyAnalyzerAdapter",
]
