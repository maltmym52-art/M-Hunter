import pytest

from m_hunter.analyzers.authentication import (
    AuthenticationAnalyzer,
)
from m_hunter.analyzers.authentication_finding import (
    AuthenticationFindingAnalyzer,
)
from m_hunter.analyzers.http import HTTPAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


def make_http_analysis(
    request_headers=None,
    response_headers=None,
):
    request = HttpRequest(
        method="GET",
        url="https://example.com/api",
        headers=request_headers or {},
    )

    response = HttpResponse(
        status_code=200,
        url="https://example.com/api",
        headers=response_headers or {},
        content=b"{}",
        cookies={},
        response_time=0.1,
        content_length=2,
    )

    return HTTPAnalyzer().analyze(
        request,
        response,
    )


def test_analyzer_name():
    analyzer = AuthenticationFindingAnalyzer()

    assert analyzer.name == "authentication_findings"


def test_analyzer_description():
    analyzer = AuthenticationFindingAnalyzer()

    assert analyzer.description


def test_empty_analysis_creates_no_findings():
    analyzer = AuthenticationFindingAnalyzer()
    authentication = AuthenticationAnalyzer().analyze(
        make_http_analysis()
    )

    findings = analyzer.analyze(
        authentication,
        target="https://example.com",
    )

    assert findings == []


def test_bearer_authentication_creates_no_finding():
    analyzer = AuthenticationFindingAnalyzer()
    authentication = AuthenticationAnalyzer().analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer token",
            }
        )
    )

    findings = analyzer.analyze(
        authentication,
        target="https://example.com",
    )

    assert findings == []


def test_basic_authentication_creates_finding():
    analyzer = AuthenticationFindingAnalyzer()
    authentication = AuthenticationAnalyzer().analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Basic abc123",
            }
        )
    )

    findings = analyzer.analyze(
        authentication,
        target="https://example.com",
        endpoint="https://example.com/login",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.title == (
        "Basic Authentication Detected"
    )
    assert finding.severity == "Low"
    assert finding.confidence == "High"
    assert finding.target == "https://example.com"
    assert finding.endpoint == (
        "https://example.com/login"
    )
    assert finding.cwe == "CWE-319"
    assert finding.owasp == "A07:2021"
    assert finding.evidence
    assert finding.remediation


def test_basic_authentication_without_endpoint():
    analyzer = AuthenticationFindingAnalyzer()
    authentication = AuthenticationAnalyzer().analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Basic abc123",
            }
        )
    )

    findings = analyzer.analyze(
        authentication,
        target="https://example.com",
    )

    assert len(findings) == 1
    assert findings[0].endpoint is None
    assert "https://example.com" in findings[0].evidence


def test_basic_scheme_is_case_sensitive_by_design():
    analyzer = AuthenticationFindingAnalyzer()
    authentication = AuthenticationAnalyzer().analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "basic abc123",
            }
        )
    )

    findings = analyzer.analyze(
        authentication,
        target="https://example.com",
    )

    assert findings == []


def test_unknown_scheme_creates_no_finding():
    analyzer = AuthenticationFindingAnalyzer()
    authentication = AuthenticationAnalyzer().analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Digest abc123",
            }
        )
    )

    findings = analyzer.analyze(
        authentication,
        target="https://example.com",
    )

    assert findings == []


def test_www_authenticate_alone_creates_no_finding():
    analyzer = AuthenticationFindingAnalyzer()
    authentication = AuthenticationAnalyzer().analyze(
        make_http_analysis(
            response_headers={
                "WWW-Authenticate": "Basic realm=\"example\"",
            }
        )
    )

    findings = analyzer.analyze(
        authentication,
        target="https://example.com",
    )

    assert findings == []


def test_analyze_requires_authentication_analysis():
    analyzer = AuthenticationFindingAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze(
            {},
            target="https://example.com",
        )


def test_analyze_http_integrates_with_authentication_analyzer():
    analyzer = AuthenticationFindingAnalyzer()

    http_analysis = make_http_analysis(
        request_headers={
            "Authorization": "Basic abc123",
        }
    )

    findings = analyzer.analyze_http(
        http_analysis,
        target="https://example.com",
    )

    assert len(findings) == 1
    assert findings[0].title == (
        "Basic Authentication Detected"
    )
    assert findings[0].target == "https://example.com"
    assert findings[0].endpoint == (
        "https://example.com/api"
    )


def test_analyze_http_uses_response_url_as_target():
    analyzer = AuthenticationFindingAnalyzer()

    http_analysis = make_http_analysis(
        request_headers={
            "Authorization": "Basic abc123",
        }
    )

    findings = analyzer.analyze_http(
        http_analysis,
    )

    assert len(findings) == 1
    assert findings[0].target == (
        "https://example.com/api"
    )
    assert findings[0].endpoint == (
        "https://example.com/api"
    )


def test_custom_endpoint_is_preserved():
    analyzer = AuthenticationFindingAnalyzer()

    http_analysis = make_http_analysis(
        request_headers={
            "Authorization": "Basic abc123",
        }
    )

    findings = analyzer.analyze_http(
        http_analysis,
        target="https://example.com",
        endpoint="https://example.com/auth",
    )

    assert len(findings) == 1
    assert findings[0].endpoint == (
        "https://example.com/auth"
    )
