from abc import ABC, abstractmethod
from typing import Any

from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.capabilities import AnalyzerCapabilities
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.response import HttpResponse


class BaseAnalyzer(ABC):
    name: str = "base"
    description: str = "Base response analyzer"

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        """Default to passive response analysis; subclasses may refine this."""
        return AnalyzerCapabilities(
            mode="passive", requires_response=True,
            description=self.description,
        )

    @abstractmethod
    def analyze(self, response: HttpResponse) -> dict[str, Any]:
        """Analyze an HTTP response and return structured results."""
        raise NotImplementedError

    def run(self, context: AnalysisContext) -> AnalysisResult:
        """Run this analyzer through the context-based interface.

        The legacy ``analyze(response)`` method remains the implementation
        point for existing analyzers. Specialized analyzers can override this
        method or be wrapped with ``LegacyAnalyzerAdapter``.
        """
        if context.response is None:
            raise ValueError(
                f"Analyzer {self.name!r} requires an HTTP response"
            )

        # Use the same argument-to-context mapping as legacy adapters so
        # BaseAnalyzer subclasses with optional context parameters (for
        # example request-aware cache analysis) can consume them too.
        from m_hunter.analyzers.adapters import LegacyAnalyzerAdapter

        data = LegacyAnalyzerAdapter._invoke_from_context(self, context)
        return AnalysisResult(
            analyzer_name=self.name,
            data=data,
        )
