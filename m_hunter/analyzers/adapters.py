"""Adapters for running legacy analyzers through the unified API."""

from collections.abc import Callable
from typing import Any

from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.response import HttpResponse


LegacyInvocation = Callable[[Any, AnalysisContext], Any]


class LegacyAnalyzerAdapter(BaseAnalyzer):
    """Expose an existing analyzer through ``BaseAnalyzer.run``.

    ``invoke`` maps a context to the legacy analyzer's existing call shape.
    If omitted, the wrapped analyzer is called with ``context.response``.
    The wrapped object's ``analyze`` method and public API are not modified.
    """

    def __init__(
        self,
        analyzer: Any,
        invoke: LegacyInvocation | None = None,
        *,
        name: str | None = None,
    ) -> None:
        legacy_analyze = getattr(analyzer, "analyze", None)
        if not callable(legacy_analyze):
            raise TypeError("analyzer must provide a callable analyze method")

        analyzer_name = name or getattr(analyzer, "name", None)
        if analyzer_name is None:
            analyzer_name = analyzer.__class__.__module__.rsplit(".", 1)[-1]
        if not isinstance(analyzer_name, str) or not analyzer_name.strip():
            raise ValueError("analyzer must provide a non-empty name")

        self.analyzer = analyzer
        self.name = analyzer_name
        self.description = getattr(analyzer, "description", "Legacy analyzer")
        self._invoke = invoke or self._invoke_response

    @staticmethod
    def _legacy_name(analyzer: Any) -> str:
        return getattr(
            analyzer,
            "name",
            analyzer.__class__.__module__.rsplit(".", 1)[-1],
        )

    @staticmethod
    def _invoke_response(
        analyzer: Any,
        context: AnalysisContext,
    ) -> Any:
        if context.response is None:
            raise ValueError(
                "Analyzer "
                f"{LegacyAnalyzerAdapter._legacy_name(analyzer)!r} "
                "requires an HTTP response"
            )
        return analyzer.analyze(context.response)

    @classmethod
    def for_content(
        cls,
        analyzer: Any,
        *,
        content_getter: Callable[[AnalysisContext], str | bytes | None] | None = None,
    ) -> "LegacyAnalyzerAdapter":
        """Adapt analyzers whose legacy method accepts text or bytes content."""

        def invoke(legacy: Any, context: AnalysisContext) -> Any:
            content = (
                content_getter(context)
                if content_getter is not None
                else context.content
            )
            if content is None:
                raise ValueError(
                    f"Analyzer {LegacyAnalyzerAdapter._legacy_name(legacy)!r} requires content"
                )
            return legacy.analyze(content)

        return cls(analyzer, invoke)

    def analyze(self, response: HttpResponse) -> Any:
        """Preserve response-based use for callers of the legacy API."""
        return self.run(AnalysisContext(response=response)).data

    def run(self, context: AnalysisContext) -> AnalysisResult:
        if not isinstance(context, AnalysisContext):
            raise TypeError("context must be an AnalysisContext")

        data = self._invoke(self.analyzer, context)
        if isinstance(data, AnalysisResult):
            return AnalysisResult(
                analyzer_name=self.name,
                data=data.data,
                status=data.status,
                errors=list(data.errors),
                metadata=data.metadata,
            )

        return AnalysisResult(
            analyzer_name=self.name,
            data=data,
        )
