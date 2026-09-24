from m_hunter.analyzers.security_headers_finding import (
    SecurityHeadersFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse


def make_response(
    headers: dict[str, str] | None = None,
) -> HttpResponse:
    content = b"<html>test</html>"

    return HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.25,
        content_length=len(content),
    )


def test_finding_analyzer_name():
    analyzer = SecurityHeadersFindingAnalyzer()

    assert analyzer.name == "security_headers_findings"


def test_finding_analyzer_description():
    analyzer = SecurityHeadersFindingAnalyzer()

    assert analyzer.description


def test_all_missing_headers_create_findings():
    analyzer = SecurityHeadersFindingAnalyzer()

    analysis = {
        "missing": [
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
        ]
    }

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) == 6
    assert all(isinstance(finding, Finding) for finding in findings)


def test_no_missing_headers_creates_no_findings():
    analyzer = SecurityHeadersFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "missing": [],
        },
        target="https://example.com",
    )

    assert findings == []


def test_unknown_missing_header_is_ignored():
    analyzer = SecurityHeadersFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "missing": [
                "unknown-security-header",
            ],
        },
        target="https://example.com",
    )

    assert findings == []


def test_content_security_policy_finding():
    analyzer = SecurityHeadersFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "missing": [
                "content-security-policy",
            ],
        },
        target="https://example.com",
        endpoint="https://example.com/login",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "Missing Content-Security-Policy Header"
    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.target == "https://example.com"
    assert finding.endpoint == "https://example.com/login"
    assert finding.cwe == "CWE-693"
    assert finding.owasp == "A05:2021"
    assert "content-security-policy" in finding.evidence
    assert finding.remediation


def test_x_frame_options_finding():
    analyzer = SecurityHeadersFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "missing": [
                "x-frame-options",
            ],
        },
        target="https://example.com",
    )

    finding = findings[0]

    assert finding.title == "Missing X-Frame-Options Header"
    assert finding.severity == "Low"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-1021"
    assert finding.owasp == "A05:2021"


def test_hsts_finding():
    analyzer = SecurityHeadersFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "missing": [
                "strict-transport-security",
            ],
        },
        target="https://example.com",
    )

    finding = findings[0]

    assert finding.title == (
        "Missing Strict-Transport-Security Header"
    )
    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-319"


def test_multiple_missing_headers_preserve_order():
    analyzer = SecurityHeadersFindingAnalyzer()

    missing = [
        "x-frame-options",
        "content-security-policy",
        "referrer-policy",
    ]

    findings = analyzer.analyze(
        {
            "missing": missing,
        },
        target="https://example.com",
    )

    assert [finding.title for finding in findings] == [
        "Missing X-Frame-Options Header",
        "Missing Content-Security-Policy Header",
        "Missing Referrer-Policy Header",
    ]


def test_analyze_response_creates_findings():
    analyzer = SecurityHeadersFindingAnalyzer()

    response = make_response(
        headers={
            "Strict-Transport-Security": "max-age=31536000",
        }
    )

    findings = analyzer.analyze_response(response)

    assert len(findings) == 5

    titles = [finding.title for finding in findings]

    assert "Missing Strict-Transport-Security Header" not in titles
    assert "Missing Content-Security-Policy Header" in titles
    assert "Missing X-Frame-Options Header" in titles


def test_analyze_response_uses_response_url_by_default():
    analyzer = SecurityHeadersFindingAnalyzer()

    response = make_response()

    findings = analyzer.analyze_response(response)

    assert findings
    assert all(
        finding.target == "https://example.com/"
        for finding in findings
    )
    assert all(
        finding.endpoint == "https://example.com/"
        for finding in findings
    )


def test_analyze_response_accepts_custom_target_and_endpoint():
    analyzer = SecurityHeadersFindingAnalyzer()

    response = make_response()

    findings = analyzer.analyze_response(
        response,
        target="https://target.example",
        endpoint="https://target.example/login",
    )

    assert findings
    assert all(
        finding.target == "https://target.example"
        for finding in findings
    )
    assert all(
        finding.endpoint == "https://target.example/login"
        for finding in findings
    )


def test_present_headers_are_not_reported():
    analyzer = SecurityHeadersFindingAnalyzer()

    response = make_response(
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
    )

    findings = analyzer.analyze_response(response)

    assert findings == []
