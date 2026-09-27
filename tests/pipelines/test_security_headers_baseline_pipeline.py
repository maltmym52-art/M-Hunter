from m_hunter.analyzers.security_headers_baseline import (
    SecurityHeadersBaselineAnalyzer,
)
from m_hunter.pipelines.security_headers_baseline import (
    SecurityHeadersBaselinePipeline,
)


def test_pipeline_generates_findings():
    analysis = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options=None,
        x_xss_protection="1; mode=block",
        x_permitted_cross_domain_policies="all",
        clear_site_data='"*"',
        multiple_security_header=True,
    )

    pipeline = SecurityHeadersBaselinePipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
        endpoint="/",
    )

    assert len(findings) == 6

    titles = {finding.title for finding in findings}

    assert "X-Content-Type-Options Header Missing" in titles
    assert "MIME Sniffing Protection Missing" in titles
    assert "Legacy X-XSS-Protection Configuration" in titles
    assert "Broad Cross-Domain Policy" in titles
    assert "Clear-Site-Data Wildcard Usage" in titles
    assert "Multiple Security Header Instances" in titles


def test_pipeline_ignores_informational_indicators():
    analysis = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
        x_xss_protection="0",
        expect_ct="max-age=86400",
    )

    pipeline = SecurityHeadersBaselinePipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
    )

    assert findings == []


def test_pipeline_handles_all_security_indicators():
    analysis = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options=None,
        x_xss_protection="1",
        x_permitted_cross_domain_policies="master-only",
        clear_site_data='"*"',
        multiple_security_header=True,
    )

    pipeline = SecurityHeadersBaselinePipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
        endpoint="/security",
    )

    assert len(findings) == 6

    severities = {finding.severity for finding in findings}

    assert "Medium" in severities
    assert "Low" in severities
