import pytest

from m_hunter.analyzers.authentication import (
    AuthenticationAnalyzer,
    AuthenticationAnalysis,
    AuthenticationHeaders,
)
from m_hunter.analyzers.http import HTTPAnalyzer
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


def test_analyzer_returns_authentication_analysis():
    analyzer = AuthenticationAnalyzer()

    analysis = make_http_analysis()

    result = analyzer.analyze(analysis)

    assert isinstance(result, AuthenticationAnalysis)


def test_analyzer_requires_http_analysis():
    analyzer = AuthenticationAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze("invalid")


def test_empty_authentication():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis()
    )

    assert isinstance(
        result.headers,
        AuthenticationHeaders,
    )
    assert result.authentication_present is False
    assert result.has_request_authentication is False
    assert result.has_response_authentication is False
    assert result.authentication_scheme is None
    assert result.challenges == ()


def test_authorization_header_is_detected():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer token123",
            }
        )
    )

    assert result.has_request_authentication is True
    assert result.headers.authorization == (
        "Bearer token123"
    )
    assert result.authentication_scheme == "Bearer"
    assert result.authentication_present is True


def test_basic_authorization_scheme():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Basic abc123",
            }
        )
    )

    assert result.authentication_scheme == "Basic"


def test_authorization_scheme_is_case_preserved():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "bearer token",
            }
        )
    )

    assert result.authentication_scheme == "bearer"


def test_empty_authorization_has_no_scheme():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "",
            }
        )
    )

    assert result.has_request_authentication is False
    assert result.authentication_scheme is None


def test_whitespace_authorization_has_no_scheme():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "   ",
            }
        )
    )

    assert result.has_request_authentication is False
    assert result.authentication_scheme is None


def test_proxy_authorization_is_detected():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Proxy-Authorization": "Basic abc",
            }
        )
    )

    assert result.has_request_authentication is True
    assert result.headers.proxy_authorization == (
        "Basic abc"
    )


def test_www_authenticate_is_detected():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            response_headers={
                "WWW-Authenticate": "Bearer",
            }
        )
    )

    assert result.has_response_authentication is True
    assert result.headers.www_authenticate == "Bearer"
    assert result.challenges == ("Bearer",)


def test_basic_www_authenticate_is_detected():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            response_headers={
                "WWW-Authenticate": 'Basic realm="example"',
            }
        )
    )

    assert result.has_response_authentication is True
    assert result.challenges == ("Basic",)


def test_multiple_authentication_challenges():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            response_headers={
                "WWW-Authenticate":
                    'Basic realm="example", Bearer',
            }
        )
    )

    assert result.challenges == (
        "Basic",
        "Bearer",
    )


def test_duplicate_authentication_challenges_are_deduplicated():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            response_headers={
                "WWW-Authenticate":
                    "Basic, Bearer, Basic",
            }
        )
    )

    assert result.challenges == (
        "Basic",
        "Bearer",
    )


def test_empty_challenge_is_ignored():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            response_headers={
                "WWW-Authenticate": ", Bearer, ",
            }
        )
    )

    assert result.challenges == ("Bearer",)


def test_proxy_authenticate_is_detected():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            response_headers={
                "Proxy-Authenticate": "Basic",
            }
        )
    )

    assert result.has_response_authentication is True
    assert result.headers.proxy_authenticate == "Basic"


def test_request_and_response_authentication():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer token",
            },
            response_headers={
                "WWW-Authenticate": "Bearer",
            },
        )
    )

    assert result.has_request_authentication is True
    assert result.has_response_authentication is True
    assert result.authentication_present is True
    assert result.authentication_scheme == "Bearer"
    assert result.challenges == ("Bearer",)


def test_header_name_matching_is_case_insensitive():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "authorization": "Bearer token",
            },
            response_headers={
                "www-authenticate": "Bearer",
            },
        )
    )

    assert result.has_request_authentication is True
    assert result.has_response_authentication is True


def test_authentication_headers_are_preserved():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer abc",
                "Proxy-Authorization": "Basic xyz",
            },
            response_headers={
                "WWW-Authenticate": "Bearer",
                "Proxy-Authenticate": "Basic",
            },
        )
    )

    assert result.headers.authorization == "Bearer abc"
    assert result.headers.proxy_authorization == "Basic xyz"
    assert result.headers.www_authenticate == "Bearer"
    assert result.headers.proxy_authenticate == "Basic"


def test_authentication_present_property():
    analyzer = AuthenticationAnalyzer()

    no_auth = analyzer.analyze(
        make_http_analysis()
    )

    request_auth = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer token",
            }
        )
    )

    response_auth = analyzer.analyze(
        make_http_analysis(
            response_headers={
                "WWW-Authenticate": "Bearer",
            }
        )
    )

    assert no_auth.authentication_present is False
    assert request_auth.authentication_present is True
    assert response_auth.authentication_present is True


def test_authorization_with_extra_spaces():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "  Bearer   token  ",
            }
        )
    )

    assert result.has_request_authentication is True
    assert result.authentication_scheme == "Bearer"


def test_challenge_whitespace_is_handled():
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            response_headers={
                "WWW-Authenticate":
                    "  Basic realm=\"example\"  ",
            }
        )
    )

    assert result.challenges == ("Basic",)
