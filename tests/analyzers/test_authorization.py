import pytest

from m_hunter.analyzers.authorization import (
    AuthorizationAnalysis,
    AuthorizationAnalyzer,
    AuthorizationContext,
)
from m_hunter.analyzers.http import HTTPAnalyzer
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


def make_http_analysis(
    *,
    method="GET",
    url="https://example.com/api",
    request_headers=None,
    cookies=None,
    params=None,
    body=None,
):
    request = HttpRequest(
        method=method,
        url=url,
        headers=request_headers or {},
        cookies=cookies or {},
        params=params or {},
        body=body,
    )

    response = HttpResponse(
        status_code=200,
        url=url,
        headers={},
        content=b"{}",
        cookies={},
        response_time=0.1,
        content_length=2,
    )

    return HTTPAnalyzer().analyze(
        request,
        response,
    )


def test_analyzer_returns_authorization_analysis():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis()
    )

    assert isinstance(result, AuthorizationAnalysis)


def test_analyzer_requires_http_analysis():
    analyzer = AuthorizationAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze("invalid")


def test_empty_request_is_not_protected():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis()
    )

    assert isinstance(
        result.context,
        AuthorizationContext,
    )
    assert result.protected_request is False
    assert result.authorization_present is False
    assert result.authorization_mechanisms == ()


def test_authorization_header_is_detected():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer token",
            }
        )
    )

    assert result.protected_request is True
    assert result.authorization_present is True
    assert result.authorization_mechanisms == (
        "authorization_header",
    )
    assert result.context.has_authorization_header is True


def test_empty_authorization_header_is_ignored():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "   ",
            }
        )
    )

    assert result.protected_request is False
    assert result.context.has_authorization_header is False


def test_cookie_authentication_is_detected():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            cookies={
                "session": "abc123",
            }
        )
    )

    assert result.protected_request is True
    assert "cookie" in result.authorization_mechanisms
    assert "session_cookie" in (
        result.authorization_mechanisms
    )
    assert result.context.has_session_cookie is True


def test_non_session_cookie_does_not_count_as_session_cookie():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            cookies={
                "theme": "dark",
            }
        )
    )

    assert result.protected_request is True
    assert "cookie" in result.authorization_mechanisms
    assert "session_cookie" not in (
        result.authorization_mechanisms
    )
    assert result.context.has_session_cookie is False


def test_multiple_authorization_mechanisms_are_deduplicated():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer token",
            },
            cookies={
                "sessionid": "abc",
            },
        )
    )

    assert result.authorization_mechanisms == (
        "authorization_header",
        "cookie",
        "session_cookie",
    )


def test_query_parameters_are_extracted():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            url="https://example.com/api?id=123&name=test",
        )
    )

    assert result.context.query_parameters == (
        "id",
        "name",
    )


def test_query_parameters_are_detected_from_request_url():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            url="https://example.com/api?user_id=123",
        )
    )

    assert result.has_resource_identifier is True
    assert result.resource_identifiers == (
        "user_id",
    )


def test_parameter_resource_identifier_is_detected():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            params={
                "document_id": "42",
            }
        )
    )

    assert result.has_resource_identifier is True
    assert result.resource_identifiers == (
        "document_id",
    )


def test_multiple_resource_identifiers_are_deduplicated():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            url="https://example.com/api?id=1&user_id=2",
            params={
                "id": "1",
            },
        )
    )

    assert result.resource_identifiers == (
        "id",
        "user_id",
    )


def test_resource_identifier_matching_is_case_insensitive():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            params={
                "USER_ID": "42",
            }
        )
    )

    assert result.resource_identifiers == (
        "USER_ID",
    )


def test_unrelated_parameter_is_not_resource_identifier():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            params={
                "search": "admin",
            }
        )
    )

    assert result.resource_identifiers == ()
    assert result.has_resource_identifier is False


def test_request_method_is_preserved():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            method="post",
        )
    )

    assert result.context.method == "POST"


def test_full_url_is_preserved():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            url="https://example.com/api",
            params={
                "id": "42",
            },
        )
    )

    assert result.context.url == (
        "https://example.com/api?id=42"
    )


def test_path_is_extracted():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            url="https://example.com/api/users/42",
        )
    )

    assert result.context.path == "/api/users/42"


def test_body_presence_is_detected():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            method="POST",
            body='{"user_id":42}',
        )
    )

    assert result.context.has_body is True


def test_empty_body_is_not_present():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis()
    )

    assert result.context.has_body is False


def test_session_cookie_name_matching_is_case_insensitive():
    analyzer = AuthorizationAnalyzer()

    result = analyzer.analyze(
        make_http_analysis(
            cookies={
                "SessionID": "abc",
            }
        )
    )

    assert result.context.has_session_cookie is True


def test_resource_identifier_property():
    analyzer = AuthorizationAnalyzer()

    with_identifier = analyzer.analyze(
        make_http_analysis(
            params={
                "order_id": "100",
            }
        )
    )

    without_identifier = analyzer.analyze(
        make_http_analysis(
            params={
                "status": "open",
            }
        )
    )

    assert with_identifier.has_resource_identifier is True
    assert without_identifier.has_resource_identifier is False


def test_authorization_present_property():
    analyzer = AuthorizationAnalyzer()

    no_auth = analyzer.analyze(
        make_http_analysis()
    )

    auth = analyzer.analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer token",
            }
        )
    )

    assert no_auth.authorization_present is False
    assert auth.authorization_present is True
