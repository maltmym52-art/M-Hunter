from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.security_headers import SecurityHeadersAnalyzer
from m_hunter.core.response import HttpResponse


def make_response(
    headers: dict[str, str] | None = None,
) -> HttpResponse:
    return HttpResponse(
        status_code=200,
        url="https://example.com",
        headers=headers or {},
        content=b"<html>test</html>",
        cookies={},
        response_time=0.25,
        content_length=17,
    )


def test_security_headers_analyzer_inherits_base_analyzer():
    analyzer = SecurityHeadersAnalyzer()

    assert isinstance(analyzer, BaseAnalyzer)


def test_security_headers_analyzer_name():
    analyzer = SecurityHeadersAnalyzer()

    assert analyzer.name == "security_headers"


def test_security_headers_analyzer_description():
    analyzer = SecurityHeadersAnalyzer()

    assert analyzer.description


def test_security_headers_definitions_are_available():
    analyzer = SecurityHeadersAnalyzer()

    assert "strict-transport-security" in analyzer.SECURITY_HEADERS
    assert "content-security-policy" in analyzer.SECURITY_HEADERS
    assert "x-content-type-options" in analyzer.SECURITY_HEADERS
    assert "x-frame-options" in analyzer.SECURITY_HEADERS
    assert "referrer-policy" in analyzer.SECURITY_HEADERS
    assert "permissions-policy" in analyzer.SECURITY_HEADERS


def test_all_headers_missing():
    analyzer = SecurityHeadersAnalyzer()

    result = analyzer.analyze(
        make_response()
    )

    assert result["present"] == {}

    assert result["missing"] == [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]

    assert result["count_present"] == 0
    assert result["count_missing"] == 6
    assert result["total_headers_checked"] == 6


def test_all_headers_present():
    analyzer = SecurityHeadersAnalyzer()

    result = analyzer.analyze(
        make_response(
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            }
        )
    )

    assert result["count_present"] == 6
    assert result["count_missing"] == 0
    assert result["missing"] == []

    assert result["present"] == {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }


def test_header_names_are_case_insensitive():
    analyzer = SecurityHeadersAnalyzer()

    result = analyzer.analyze(
        make_response(
            headers={
                "STRICT-TRANSPORT-SECURITY": "max-age=100",
                "Content-Security-Policy": "default-src 'self'",
            }
        )
    )

    assert result["count_present"] == 2
    assert result["count_missing"] == 4

    assert result["present"]["strict-transport-security"] == "max-age=100"
    assert result["present"]["content-security-policy"] == "default-src 'self'"


def test_partial_headers_are_detected():
    analyzer = SecurityHeadersAnalyzer()

    result = analyzer.analyze(
        make_response(
            headers={
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin",
            }
        )
    )

    assert result["count_present"] == 2
    assert result["count_missing"] == 4

    assert "x-content-type-options" in result["present"]
    assert "referrer-policy" in result["present"]

    assert "content-security-policy" in result["missing"]
    assert "permissions-policy" in result["missing"]


def test_present_values_are_preserved():
    analyzer = SecurityHeadersAnalyzer()

    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            }
        )
    )

    assert (
        result["present"]["content-security-policy"]
        == "default-src 'none'; frame-ancestors 'none'"
    )


def test_analyzer_does_not_modify_response_headers():
    analyzer = SecurityHeadersAnalyzer()

    response = make_response(
        headers={
            "X-Frame-Options": "DENY",
        }
    )

    original_headers = response.get_headers()

    analyzer.analyze(response)

    assert response.get_headers() == original_headers


def test_result_contains_expected_top_level_keys():
    analyzer = SecurityHeadersAnalyzer()

    result = analyzer.analyze(
        make_response()
    )

    assert set(result.keys()) == {
        "present",
        "missing",
        "count_present",
        "count_missing",
        "total_headers_checked",
    }
