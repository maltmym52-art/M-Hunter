import pytest

from m_hunter.analyzers.http import (
    CookieInfo,
    HeaderInfo,
    HTTPAnalysis,
    HTTPAnalyzer,
)
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


def make_request():
    return HttpRequest(
        method="GET",
        url="https://example.com/users?id=1&name=test",
        headers={
            "User-Agent": "M-Hunter",
            "Authorization": "Bearer token",
        },
        cookies={
            "session": "abc123",
        },
    )


def make_response():
    return HttpResponse(
        status_code=200,
        url="https://example.com/users?id=1&name=test",
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Server": "nginx",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Access-Control-Allow-Origin": "*",
        },
        content=b"<html><title>Users</title></html>",
        cookies={
            "session": "abc123",
        },
        response_time=0.25,
        content_length=38,
    )


def test_header_info_normalizes_name():
    header = HeaderInfo(
        name=" Content-Type ",
        value="text/html",
    )

    assert header.normalized_name == "content-type"


def test_cookie_info():
    cookie = CookieInfo(
        name="session",
        value="abc",
    )

    assert cookie.name == "session"
    assert cookie.value == "abc"


def test_analyzer_requires_request():
    analyzer = HTTPAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze(
            "not-request",
            make_response(),
        )


def test_analyzer_requires_response():
    analyzer = HTTPAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze(
            make_request(),
            "not-response",
        )


def test_basic_analysis():
    analyzer = HTTPAnalyzer()

    analysis = analyzer.analyze(
        make_request(),
        make_response(),
    )

    assert isinstance(
        analysis,
        HTTPAnalysis,
    )

    assert analysis.status_code == 200
    assert analysis.content_type == "text/html"
    assert analysis.is_html is True
    assert analysis.is_json is False


def test_request_headers_are_extracted():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.request_header(
        "user-agent"
    ) == "M-Hunter"

    assert analysis.request_header(
        "Authorization"
    ) == "Bearer token"


def test_response_headers_are_extracted():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.response_header(
        "content-type"
    ) == "text/html; charset=utf-8"

    assert analysis.response_header(
        "SERVER"
    ) == "nginx"


def test_missing_header_returns_none():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.response_header(
        "x-missing"
    ) is None


def test_header_presence():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.has_response_header(
        "Content-Security-Policy"
    ) is True

    assert analysis.has_response_header(
        "X-Missing"
    ) is False


def test_request_header_presence():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.has_request_header(
        "Authorization"
    ) is True

    assert analysis.has_request_header(
        "X-Missing"
    ) is False


def test_request_cookies_are_extracted():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.request_cookies == [
        CookieInfo(
            name="session",
            value="abc123",
        )
    ]


def test_response_cookies_are_extracted():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.response_cookies == [
        CookieInfo(
            name="session",
            value="abc123",
        )
    ]


def test_has_cookies():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.has_cookies is True


def test_query_parameters_are_extracted():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.query_parameters == (
        "id",
        "name",
    )


def test_security_headers():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    headers = analysis.security_headers()

    assert headers == {
        "content-security-policy":
            "default-src 'self'",
        "x-content-type-options":
            "nosniff",
    }


def test_cors_headers():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.cors_headers() == {
        "access-control-allow-origin": "*",
    }


def test_authentication_headers():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.authentication_headers() == {
        "authorization": "Bearer token",
    }


def test_redirect_url():
    response = make_response()
    response.status_code = 302
    response.headers["Location"] = (
        "https://example.com/login"
    )

    analysis = HTTPAnalyzer().analyze(
        make_request(),
        response,
    )

    assert analysis.redirect_url == (
        "https://example.com/login"
    )


def test_server_header():
    analysis = HTTPAnalyzer().analyze(
        make_request(),
        make_response(),
    )

    assert analysis.server == "nginx"


def test_json_response():
    response = HttpResponse(
        status_code=200,
        url="https://example.com/api/users",
        headers={
            "Content-Type": "application/json",
        },
        content=b'{"id":1}',
        cookies={},
        response_time=0.1,
        content_length=8,
    )

    analysis = HTTPAnalyzer().analyze(
        make_request(),
        response,
    )

    assert analysis.is_json is True
    assert analysis.is_html is False


def test_empty_headers_and_cookies():
    request = HttpRequest(
        method="GET",
        url="https://example.com/",
    )

    response = HttpResponse(
        status_code=204,
        url="https://example.com/",
        headers={},
        content=b"",
        cookies={},
        response_time=0.1,
        content_length=0,
    )

    analysis = HTTPAnalyzer().analyze(
        request,
        response,
    )

    assert analysis.request_headers == []
    assert analysis.response_headers == []
    assert analysis.request_cookies == []
    assert analysis.response_cookies == []
    assert analysis.query_parameters == ()
    assert analysis.has_cookies is False
    assert analysis.security_headers() == {}
    assert analysis.cors_headers() == {}
    assert analysis.authentication_headers() == {}
