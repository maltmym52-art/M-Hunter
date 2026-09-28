import pytest

from m_hunter.analyzers.adapters import LegacyAnalyzerAdapter
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.corp import CORPAnalyzer
from m_hunter.analyzers.coop import COOPAnalyzer
from m_hunter.analyzers.sqli import SQLiAnalyzer
from m_hunter.analyzers.ssrf import SSRFAnalyzer
from m_hunter.analyzers.xxe import XXEAnalyzer
from m_hunter.core.response import HttpResponse


def make_response(content: bytes = b"safe") -> HttpResponse:
    return HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers={"Content-Type": "text/html"},
        content=content,
        cookies={},
        response_time=0.0,
        content_length=len(content),
    )


@pytest.mark.parametrize(
    "legacy_analyzer",
    [COOPAnalyzer, CORPAnalyzer, SQLiAnalyzer, SSRFAnalyzer],
)
def test_response_adapter_preserves_legacy_analysis_type(legacy_analyzer):
    analyzer = legacy_analyzer()
    adapter = LegacyAnalyzerAdapter(analyzer)

    result = adapter.run(AnalysisContext(response=make_response()))

    assert result.analyzer_name == adapter.name
    assert type(result.data).__name__.endswith("Analysis")


def test_content_adapter_runs_xxe_without_changing_legacy_call_shape():
    analyzer = XXEAnalyzer()
    adapter = LegacyAnalyzerAdapter.for_content(analyzer)

    result = adapter.run(
        AnalysisContext(content=b"<!DOCTYPE root><root/>")
    )

    assert result.analyzer_name == "xxe"
    assert result.data.detected is True
    assert analyzer.analyze("<root/>").detected is False


def test_legacy_adapter_requires_context_for_default_response_call():
    adapter = LegacyAnalyzerAdapter(COOPAnalyzer())

    with pytest.raises(ValueError, match="requires an HTTP response"):
        adapter.run(AnalysisContext())


def test_content_adapter_requires_content():
    adapter = LegacyAnalyzerAdapter.for_content(XXEAnalyzer())

    with pytest.raises(ValueError, match="requires content"):
        adapter.run(AnalysisContext())


def test_adapter_can_map_context_options_to_legacy_arguments():
    from m_hunter.analyzers.web_cache_key_security import (
        WebCacheKeySecurityAnalyzer,
        WebCacheKeyIndicatorType,
    )

    analyzer = WebCacheKeySecurityAnalyzer()
    adapter = LegacyAnalyzerAdapter(
        analyzer,
        invoke=lambda legacy, context: legacy.analyze(
            context.response,
            request_url=context.request_url,
            **context.options,
        ),
    )

    result = adapter.run(
        AnalysisContext(
            response=make_response(),
            request_url="https://example.com/?token=value",
        )
    )

    assert result.data.has_type(
        WebCacheKeyIndicatorType.SENSITIVE_QUERY_PARAMETER
    )
