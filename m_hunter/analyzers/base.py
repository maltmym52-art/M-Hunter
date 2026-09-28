from abc import ABC, abstractmethod
from typing import Any

from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.response import HttpResponse


class BaseAnalyzer(ABC):
    name: str = "base"
    description: str = "Base response analyzer"

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

        return AnalysisResult(
            analyzer_name=self.name,
            data=self.analyze(context.response),
        )
