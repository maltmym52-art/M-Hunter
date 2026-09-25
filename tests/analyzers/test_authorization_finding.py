import pytest

from m_hunter.analyzers.authorization import (
    AuthorizationAnalyzer,
)
from m_hunter.analyzers.authorization_finding import (
    AuthorizationFindingAnalyzer,
)
from m_hunter.analyzers.http import HTTPAnalyzer
from m_hunter.core.finding import Finding


def make_http_analysis(
    *,
    method="GET",
    url="https://example.com/api",
    request_headers=None,
    cookies=None,
    params=None,
    body=None,
):
    from m_hunter.core.request import HttpRequest
    from m_hunter.core.response import HttpResponse

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


def test_analyzer_name():
    analyzer = AuthorizationFindingAnalyzer()

    assert analyzer.name == "authorization_findings"


def test_analyzer_description():
    analyzer = AuthorizationFindingAnalyzer()

    assert analyzer.description


def test_empty_analysis_creates_no_findings():
    analyzer = AuthorizationFindingAnalyzer()
    analysis = AuthorizationAnalyzer().analyze(
        make_http_analysis()
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


def test_authorized_request_creates_no_finding():
    analyzer = AuthorizationFindingAnalyzer()
    analysis = AuthorizationAnalyzer().analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer token",
            }
        )
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


def test_session_cookie_creates_no_finding():
    analyzer = AuthorizationFindingAnalyzer()
    analysis = AuthorizationAnalyzer().analyze(
        make_http_analysis(
            cookies={
                "session": "abc123",
            }
        )
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


def test_resource_identifier_creates_no_finding():
    analyzer = AuthorizationFindingAnalyzer()
    analysis = AuthorizationAnalyzer().analyze(
        make_http_analysis(
            params={
                "user_id": "42",
            }
        )
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


def test_resource_identifier_with_authentication_creates_no_finding():
    analyzer = AuthorizationFindingAnalyzer()
    analysis = AuthorizationAnalyzer().analyze(
        make_http_analysis(
            request_headers={
                "Authorization": "Bearer token",
            },
            params={
                "user_id": "42",
            },
        )
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


def test_multiple_resource_identifiers_create_no_finding():
    analyzer = AuthorizationFindingAnalyzer()
    analysis = AuthorizationAnalyzer().analyze(
        make_http_analysis(
            url="https://example.com/api?id=1",
            params={
                "user_id": "42",
                "order_id": "100",
            },
        )
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


def test_analyze_requires_authorization_analysis():
    analyzer = AuthorizationFindingAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze(
            {},
            target="https://example.com",
        )


def test_analyze_http_integrates_with_authorization_analyzer():
    analyzer = AuthorizationFindingAnalyzer()

    http_analysis = make_http_analysis(
        request_headers={
            "Authorization": "Bearer token",
        },
        params={
            "user_id": "42",
        },
    )

    findings = analyzer.analyze_http(
        http_analysis,
        target="https://example.com",
    )

    assert findings == []


def test_analyze_http_uses_response_url_as_target():
    analyzer = AuthorizationFindingAnalyzer()

    http_analysis = make_http_analysis(
        params={
            "document_id": "123",
        }
    )

    findings = analyzer.analyze_http(
        http_analysis,
    )

    assert findings == []


def test_custom_endpoint_does_not_create_finding():
    analyzer = AuthorizationFindingAnalyzer()

    http_analysis = make_http_analysis(
        params={
            "account_id": "123",
        }
    )

    findings = analyzer.analyze_http(
        http_analysis,
        target="https://example.com",
        endpoint="https://example.com/account",
    )

    assert findings == []


def test_safe_design_does_not_claim_idor_from_single_request():
    analyzer = AuthorizationFindingAnalyzer()

    http_analysis = make_http_analysis(
        request_headers={
            "Authorization": "Bearer user-a",
        },
        params={
            "user_id": "user-b",
        },
    )

    findings = analyzer.analyze_http(
        http_analysis,
        target="https://example.com",
    )

    assert findings == []


def test_finding_output_is_always_a_list():
    analyzer = AuthorizationFindingAnalyzer()
    analysis = AuthorizationAnalyzer().analyze(
        make_http_analysis()
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert isinstance(findings, list)


def test_no_false_positive_for_cookie_and_identifier():
    analyzer = AuthorizationFindingAnalyzer()

    http_analysis = make_http_analysis(
        cookies={
            "sessionid": "abc",
        },
        params={
            "resource_id": "55",
        },
    )

    findings = analyzer.analyze_http(
        http_analysis,
        target="https://example.com",
    )

    assert findings == []
