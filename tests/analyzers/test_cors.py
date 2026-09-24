import pytest

from m_hunter.analyzers.cors import (
    CORSAnalysis,
    CORSAnalyzer,
    CORSHeaders,
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


def test_wildcard_is_not_automatically_sensitive():
    result = CORSAnalyzer().analyze(
        make_analysis(
            {
                "Access-Control-Allow-Origin": "*",
            }
        )
    )

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


def test_wildcard_with_credentials_is_not_origin_with_credentials():
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


def test_origin_matching_is_case_sensitive_for_wildcard():
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
