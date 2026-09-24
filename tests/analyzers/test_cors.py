import pytest

from m_hunter.analyzers.cors import (
    CORSAnalysis,
    CORSAnalyzer,
    CORSHeaders,
    CORSIssue,
)
from m_hunter.analyzers.http import HTTPAnalyzer
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


def make_analysis(headers=None):
    request = HttpRequest(
        method="GET",
        url="https://example.com/api/users",
    )

    response = HttpResponse(
        status_code=200,
        url="https://example.com/api/users",
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


def test_empty_cors_analysis():
    result = CORSAnalyzer().analyze(
        make_analysis()
    )

    assert isinstance(result, CORSAnalysis)
    assert result.enabled is False
    assert result.wildcard_origin is False
    assert result.credentials_enabled is False
    assert result.origin_with_credentials is False
    assert result.allowed_methods == ()
    assert result.allowed_headers == ()
    assert result.issues == []
    assert result.potentially_sensitive is False


def test_requires_http_analysis():
    with pytest.raises(TypeError):
        CORSAnalyzer().analyze(
            "not-http-analysis"
        )


def test_extracts_all_cors_headers():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Origin":
                    "https://client.example",
                "Access-Control-Allow-Credentials":
                    "true",
                "Access-Control-Allow-Methods":
                    "GET, POST, PUT",
                "Access-Control-Allow-Headers":
                    "Authorization, Content-Type",
                "Access-Control-Expose-Headers":
                    "X-Request-ID",
                "Access-Control-Max-Age":
                    "600",
            }
        )
    )

    assert result.headers == CORSHeaders(
        allow_origin="https://client.example",
        allow_credentials="true",
        allow_methods="GET, POST, PUT",
        allow_headers="Authorization, Content-Type",
        expose_headers="X-Request-ID",
        max_age="600",
    )


def test_detects_wildcard_origin():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Origin": "*",
            }
        )
    )

    assert result.enabled is True
    assert result.wildcard_origin is True
    assert result.issues == []
    assert result.potentially_sensitive is False


def test_detects_credentials():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Credentials":
                    "true",
            }
        )
    )

    assert result.credentials_enabled is True


def test_credentials_value_is_case_insensitive():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Credentials":
                    "TRUE",
            }
        )
    )

    assert result.credentials_enabled is True


def test_origin_with_credentials():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Origin":
                    "https://client.example",
                "Access-Control-Allow-Credentials":
                    "true",
            }
        )
    )

    assert result.origin_with_credentials is True
    assert result.potentially_sensitive is True

    assert result.issues == [
        CORSIssue(
            issue="origin_with_credentials",
            severity="medium",
            description=(
                "CORS allows credentials for a specific "
                "origin. The origin should be validated "
                "against an explicit allowlist."
            ),
        )
    ]


def test_wildcard_with_credentials_is_detected():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials":
                    "true",
            }
        )
    )

    assert result.wildcard_origin is True
    assert result.credentials_enabled is True
    assert result.origin_with_credentials is False
    assert result.potentially_sensitive is True

    assert result.issues == [
        CORSIssue(
            issue="wildcard_origin_with_credentials",
            severity="high",
            description=(
                "CORS allows a wildcard origin while "
                "credentials are enabled."
            ),
        )
    ]


def test_null_origin_is_detected():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Origin": "null",
            }
        )
    )

    assert result.issues == [
        CORSIssue(
            issue="null_origin_allowed",
            severity="medium",
            description=(
                "CORS explicitly allows the null origin."
            ),
        )
    ]


def test_allowed_methods_are_parsed():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Methods":
                    "GET, POST, PUT, DELETE",
            }
        )
    )

    assert result.allowed_methods == (
        "GET",
        "POST",
        "PUT",
        "DELETE",
    )


def test_allowed_headers_are_parsed():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Headers":
                    "Authorization, Content-Type, X-Test",
            }
        )
    )

    assert result.allowed_headers == (
        "Authorization",
        "Content-Type",
        "X-Test",
    )


def test_empty_values_are_ignored():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Methods":
                    "GET, , POST, ",
                "Access-Control-Allow-Headers":
                    " Authorization, , Content-Type ",
            }
        )
    )

    assert result.allowed_methods == (
        "GET",
        "POST",
    )

    assert result.allowed_headers == (
        "Authorization",
        "Content-Type",
    )


def test_wildcard_origin_allows_whitespace():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Origin": " * ",
            }
        )
    )

    assert result.wildcard_origin is True


def test_non_true_credentials_are_not_enabled():
    for value in (
        "false",
        "1",
        "yes",
        "enabled",
    ):
        result = CORSAnalyzer().analyze(
            make_analysis(
                {
                    "Access-Control-Allow-Credentials":
                        value,
                }
            )
        )

        assert result.credentials_enabled is False


def test_partial_cors_configuration_is_supported():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Origin":
                    "https://example.com",
            }
        )
    )

    assert result.enabled is True
    assert result.headers.allow_origin == (
        "https://example.com"
    )
    assert result.headers.allow_credentials is None


def test_headers_are_case_insensitive():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "access-control-allow-origin":
                    "https://example.com",
                "ACCESS-CONTROL-ALLOW-CREDENTIALS":
                    "true",
            }
        )
    )

    assert result.enabled is True
    assert result.origin_with_credentials is True


def test_no_origin_means_not_enabled():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Server": "nginx",
                "Content-Type": "application/json",
            }
        )
    )

    assert result.enabled is False
    assert result.issues == []


def test_wildcard_methods_are_detected():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Methods": "*",
            }
        )
    )

    assert result.issues == [
        CORSIssue(
            issue="wildcard_methods",
            severity="low",
            description=(
                "CORS allows all methods through a "
                "wildcard method value."
            ),
        )
    ]


def test_wildcard_headers_are_detected():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Headers": "*",
            }
        )
    )

    assert result.issues == [
        CORSIssue(
            issue="wildcard_headers",
            severity="low",
            description=(
                "CORS allows all request headers through "
                "a wildcard header value."
            ),
        )
    ]


def test_multiple_cors_issues_are_collected():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Origin":
                    "https://client.example",
                "Access-Control-Allow-Credentials":
                    "true",
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Headers": "*",
            }
        )
    )

    assert len(result.issues) == 3

    assert result.issues[0].issue == (
        "origin_with_credentials"
    )
    assert result.issues[1].issue == "wildcard_methods"
    assert result.issues[2].issue == "wildcard_headers"


def test_cors_issue_is_immutable():
    issue = CORSIssue(
        issue="test",
        severity="low",
        description="test",
    )

    with pytest.raises(
        AttributeError
    ):
        issue.severity = "high"
