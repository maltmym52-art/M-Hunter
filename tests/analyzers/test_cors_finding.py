import pytest

from m_hunter.analyzers.cors_finding import (
    CORSFindingAnalyzer,
)
from m_hunter.analyzers.http import HTTPAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


def make_http_analysis(headers=None):
    request = HttpRequest(
        method="GET",
        url="https://example.com/api",
    )

    response = HttpResponse(
        status_code=200,
        url="https://example.com/api",
        headers=headers or {},
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
    analyzer = CORSFindingAnalyzer()

    assert analyzer.name == "cors_findings"


def test_analyzer_description():
    analyzer = CORSFindingAnalyzer()

    assert analyzer.description


def test_unknown_issue_is_ignored():
    analyzer = CORSFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "issues": [
                {
                    "issue": "unknown_issue",
                }
            ]
        },
        target="https://example.com",
    )

    assert findings == []


def test_empty_issues_create_no_findings():
    analyzer = CORSFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "issues": [],
        },
        target="https://example.com",
    )

    assert findings == []


def test_wildcard_origin_with_credentials_finding():
    analyzer = CORSFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "issues": [
                {
                    "issue":
                        "wildcard_origin_with_credentials",
                    "severity": "high",
                }
            ]
        },
        target="https://example.com",
        endpoint="https://example.com/api",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.title == (
        "CORS Wildcard Origin with Credentials"
    )
    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.target == "https://example.com"
    assert finding.endpoint == "https://example.com/api"
    assert finding.cwe == "CWE-942"
    assert finding.owasp == "A05:2021"
    assert finding.evidence
    assert finding.remediation


def test_origin_with_credentials_finding():
    analyzer = CORSFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "issues": [
                {
                    "issue": "origin_with_credentials",
                    "severity": "medium",
                }
            ]
        },
        target="https://example.com",
    )

    assert len(findings) == 1
    assert findings[0].title == (
        "Credentialed CORS for Explicit Origin"
    )
    assert findings[0].severity == "Medium"
    assert findings[0].confidence == "Medium"


def test_null_origin_finding():
    analyzer = CORSFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "issues": [
                {
                    "issue": "null_origin_allowed",
                    "severity": "medium",
                }
            ]
        },
        target="https://example.com",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "CORS Allows null Origin"
    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-942"


def test_wildcard_methods_finding():
    analyzer = CORSFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "issues": [
                {
                    "issue": "wildcard_methods",
                    "severity": "low",
                }
            ]
        },
        target="https://example.com",
    )

    assert len(findings) == 1
    assert findings[0].title == (
        "CORS Allows Wildcard Methods"
    )
    assert findings[0].severity == "Low"


def test_wildcard_headers_finding():
    analyzer = CORSFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "issues": [
                {
                    "issue": "wildcard_headers",
                    "severity": "low",
                }
            ]
        },
        target="https://example.com",
    )

    assert len(findings) == 1
    assert findings[0].title == (
        "CORS Allows Wildcard Headers"
    )
    assert findings[0].severity == "Low"


def test_multiple_issues_create_multiple_findings():
    analyzer = CORSFindingAnalyzer()

    findings = analyzer.analyze(
        {
            "issues": [
                {
                    "issue": "null_origin_allowed",
                    "severity": "medium",
                },
                {
                    "issue": "wildcard_methods",
                    "severity": "low",
                },
                {
                    "issue": "wildcard_headers",
                    "severity": "low",
                },
            ]
        },
        target="https://example.com",
    )

    assert len(findings) == 3

    assert [
        finding.title
        for finding in findings
    ] == [
        "CORS Allows null Origin",
        "CORS Allows Wildcard Methods",
        "CORS Allows Wildcard Headers",
    ]


def test_analyze_requires_dictionary():
    analyzer = CORSFindingAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze(
            "not-analysis",
            target="https://example.com",
        )


def test_analyze_http_integrates_with_cors_analyzer():
    analyzer = CORSFindingAnalyzer()

    http_analysis = make_http_analysis(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

    findings = analyzer.analyze_http(
        http_analysis,
        target="https://example.com",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == (
        "CORS Wildcard Origin with Credentials"
    )
    assert finding.target == "https://example.com"
    assert finding.endpoint == "https://example.com/api"


def test_safe_cors_configuration_creates_no_findings():
    analyzer = CORSFindingAnalyzer()

    http_analysis = make_http_analysis(
        {
            "Access-Control-Allow-Origin":
                "https://trusted.example",
        }
    )

    findings = analyzer.analyze_http(
        http_analysis,
        target="https://example.com",
    )

    assert findings == []


def test_custom_endpoint_is_preserved():
    analyzer = CORSFindingAnalyzer()

    http_analysis = make_http_analysis(
        {
            "Access-Control-Allow-Origin": "null",
        }
    )

    findings = analyzer.analyze_http(
        http_analysis,
        target="https://example.com",
        endpoint="https://example.com/login",
    )

    assert len(findings) == 1
    assert findings[0].endpoint == (
        "https://example.com/login"
    )
