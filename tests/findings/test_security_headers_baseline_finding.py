from m_hunter.analyzers.security_headers_baseline import (
    SecurityHeadersBaselineAnalyzer,
)
from m_hunter.findings.security_headers_baseline import (
    SecurityHeadersBaselineFinding,
)


def test_missing_content_type_options():
    finding = SecurityHeadersBaselineFinding.build(
        "X_CONTENT_TYPE_OPTIONS_MISSING",
        "https://example.com",
    )

    assert finding.title == "X-Content-Type-Options Header Missing"
    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-693"


def test_unsafe_xss_protection():
    finding = SecurityHeadersBaselineFinding.build(
        "X_XSS_PROTECTION_UNSAFE",
        "https://example.com",
        endpoint="/",
        evidence="1; mode=block",
    )

    assert finding.title == "Legacy X-XSS-Protection Configuration"
    assert finding.severity == "Low"
    assert finding.evidence == "1; mode=block"


def test_deprecated_expect_ct():
    finding = SecurityHeadersBaselineFinding.build(
        "EXPECT_CT_DEPRECATED",
        "https://example.com",
    )

    assert finding.title == "Deprecated Expect-CT Header"
    assert finding.severity == "Info"


def test_unsafe_cross_domain_policy():
    finding = SecurityHeadersBaselineFinding.build(
        "CROSS_DOMAIN_POLICY_UNSAFE",
        "https://example.com",
        evidence="all",
    )

    assert finding.title == "Broad Cross-Domain Policy"
    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-942"


def test_from_analysis():
    analysis = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options=None,
        x_xss_protection="1; mode=block",
        expect_ct="max-age=86400",
        x_permitted_cross_domain_policies="all",
        clear_site_data='"*"',
        multiple_security_header=True,
    )

    findings = SecurityHeadersBaselineFinding.from_analysis(
        analysis,
        "https://example.com",
        endpoint="/",
    )

    assert len(findings) == 7

    titles = {finding.title for finding in findings}

    assert "X-Content-Type-Options Header Missing" in titles
    assert "MIME Sniffing Protection Missing" in titles
    assert "Legacy X-XSS-Protection Configuration" in titles
    assert "Deprecated Expect-CT Header" in titles
    assert "Broad Cross-Domain Policy" in titles
    assert "Clear-Site-Data Wildcard Usage" in titles
    assert "Multiple Security Header Instances" in titles
