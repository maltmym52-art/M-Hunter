from m_hunter.analyzers.cache_control_security import (
    CacheControlSecurityAnalyzer,
)
from m_hunter.pipelines.cache_control_security import (
    CacheControlSecurityPipeline,
)


def test_pipeline_generates_security_findings():
    analyzer = CacheControlSecurityAnalyzer()

    analysis = analyzer.analyze(
        cache_control="public, max-age=3600",
        vary=None,
        sensitive_content=True,
    )

    pipeline = CacheControlSecurityPipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
        endpoint="/account",
    )

    assert len(findings) == 2
    assert findings[0].title == "Sensitive Content Is Publicly Cacheable"
    assert findings[1].title == "Missing Vary Header on Sensitive Cacheable Response"


def test_pipeline_ignores_informational_indicators():
    analyzer = CacheControlSecurityAnalyzer()

    analysis = analyzer.analyze(
        cache_control="private, max-age=300",
        pragma="no-cache",
    )

    pipeline = CacheControlSecurityPipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
    )

    assert findings == []


def test_pipeline_handles_multiple_security_indicators():
    analyzer = CacheControlSecurityAnalyzer()

    analysis = analyzer.analyze(
        cache_control="public, private, max-age=3600",
        sensitive_content=True,
        multiple_cache_control=True,
    )

    pipeline = CacheControlSecurityPipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
        endpoint="/profile",
    )

    assert len(findings) == 4

    titles = {finding.title for finding in findings}

    assert "Sensitive Content Is Publicly Cacheable" in titles
    assert "Conflicting Cache-Control Directives" in titles
    assert "Multiple Cache-Control Headers" in titles
    assert "Missing Vary Header on Sensitive Cacheable Response" in titles
