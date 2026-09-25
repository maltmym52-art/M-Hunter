import pytest

from m_hunter.analyzers.api_security import (
    APIAnalysis,
    APIIndicator,
    APIIndicatorType,
    APISecurityAnalyzer,
)


@pytest.fixture
def analyzer():
    return APISecurityAnalyzer()


def test_clean_response_has_no_indicators(analyzer):
    result = analyzer.analyze(
        headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        },
        body='{"status":"ok"}',
        expected_methods=["GET"],
        allowed_methods=["GET"],
        content_type="application/json",
    )

    assert result.detected is False
    assert result.indicator_count == 0
    assert result.types == []
    assert result.indicators == []


def test_missing_security_headers_are_detected(analyzer):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
    )

    assert result.detected is True
    assert (
        APIIndicatorType.MISSING_SECURITY_HEADER
        in result.types
    )


def test_custom_required_headers_are_supported(analyzer):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
        required_security_headers={
            "x-custom-security-header",
        },
    )

    assert result.indicator_count == 1
    assert result.indicators[0].name == (
        "x-custom-security-header"
    )


def test_security_headers_are_case_insensitive(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
        body="{}",
        content_type="application/json",
        expected_methods=["GET"],
        allowed_methods=["GET"],
    )

    assert (
        APIIndicatorType.MISSING_SECURITY_HEADER
        not in result.types
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "password",
        "password_hash",
        "passwordhash",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "private_key",
        "privatekey",
        "credit_card",
        "card_number",
        "ssn",
    ],
)
def test_sensitive_fields_are_detected(
    analyzer,
    field_name,
):
    result = analyzer.analyze(
        headers={},
        body=f'{{"{field_name}":"value"}}',
        content_type="application/json",
    )

    assert (
        APIIndicatorType.EXCESSIVE_DATA_EXPOSURE
        in result.types
    )

    matches = [
        item
        for item in result.indicators
        if item.type
        == APIIndicatorType.EXCESSIVE_DATA_EXPOSURE
    ]

    assert any(
        item.name == field_name
        for item in matches
    )


def test_sensitive_field_detection_is_case_insensitive(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body='{"PASSWORD":"secret"}',
        content_type="application/json",
    )

    assert (
        APIIndicatorType.EXCESSIVE_DATA_EXPOSURE
        in result.types
    )


@pytest.mark.parametrize(
    "marker",
    [
        "debug",
        "traceback",
        "stack trace",
        "stacktrace",
        "exception",
        "internal server error",
        "development mode",
    ],
)
def test_verbose_error_markers_are_detected(
    analyzer,
    marker,
):
    result = analyzer.analyze(
        headers={},
        body=f"Error: {marker}",
        content_type="application/json",
    )

    assert (
        APIIndicatorType.VERBOSE_ERROR
        in result.types
    )


@pytest.mark.parametrize(
    "body",
    [
        "debug mode enabled",
        "debug=true",
        "development environment",
        "dev environment",
    ],
)
def test_debug_information_is_detected(
    analyzer,
    body,
):
    result = analyzer.analyze(
        headers={},
        body=body,
        content_type="application/json",
    )

    assert (
        APIIndicatorType.DEBUG_INFORMATION
        in result.types
    )


def test_server_disclosure_is_detected(analyzer):
    result = analyzer.analyze(
        headers={
            "server": "nginx",
        },
        body="{}",
        content_type="application/json",
    )

    assert (
        APIIndicatorType.SERVER_DISCLOSURE
        in result.types
    )

    finding = next(
        item
        for item in result.indicators
        if item.type
        == APIIndicatorType.SERVER_DISCLOSURE
    )

    assert finding.name == "server"
    assert finding.value == "nginx"


def test_server_version_disclosure_is_detected(
    analyzer,
):
    result = analyzer.analyze(
        headers={
            "server": "nginx/1.25.3",
        },
        body="{}",
        content_type="application/json",
    )

    assert (
        APIIndicatorType.SERVER_DISCLOSURE
        in result.types
    )
    assert (
        APIIndicatorType.VERSION_DISCLOSURE
        in result.types
    )


def test_server_without_version_does_not_create_version_indicator(
    analyzer,
):
    result = analyzer.analyze(
        headers={
            "server": "nginx",
        },
        body="{}",
        content_type="application/json",
    )

    assert (
        APIIndicatorType.SERVER_DISCLOSURE
        in result.types
    )
    assert (
        APIIndicatorType.VERSION_DISCLOSURE
        not in result.types
    )


def test_unexpected_method_is_detected(analyzer):
    result = analyzer.analyze(
        headers={},
        body="{}",
        allowed_methods=["GET", "DELETE"],
        expected_methods=["GET"],
        content_type="application/json",
    )

    assert (
        APIIndicatorType.UNRESTRICTED_METHOD
        in result.types
    )

    finding = next(
        item
        for item in result.indicators
        if item.type
        == APIIndicatorType.UNRESTRICTED_METHOD
    )

    assert finding.name == "DELETE"


def test_method_comparison_is_case_insensitive(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        allowed_methods=["get"],
        expected_methods=["GET"],
        content_type="application/json",
    )

    assert (
        APIIndicatorType.UNRESTRICTED_METHOD
        not in result.types
    )


def test_multiple_unexpected_methods_are_detected(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        allowed_methods=["GET", "POST", "PUT", "DELETE"],
        expected_methods=["GET"],
        content_type="application/json",
    )

    matches = [
        item
        for item in result.indicators
        if item.type
        == APIIndicatorType.UNRESTRICTED_METHOD
    ]

    assert len(matches) == 3
    assert {
        item.name
        for item in matches
    } == {"POST", "PUT", "DELETE"}


def test_missing_content_type_is_detected(analyzer):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type=None,
    )

    assert (
        APIIndicatorType.MISSING_CONTENT_TYPE
        in result.types
    )


def test_empty_content_type_is_detected(analyzer):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="",
    )

    assert (
        APIIndicatorType.MISSING_CONTENT_TYPE
        in result.types
    )


@pytest.mark.parametrize(
    "content_type",
    [
        "text/plain",
        "text/html",
        "application/octet-stream",
    ],
)
def test_weak_content_types_are_detected(
    analyzer,
    content_type,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type=content_type,
    )

    assert (
        APIIndicatorType.WEAK_CONTENT_TYPE
        in result.types
    )


def test_content_type_parameters_are_normalized(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="text/plain; charset=utf-8",
    )

    assert (
        APIIndicatorType.WEAK_CONTENT_TYPE
        in result.types
    )


def test_json_content_type_is_not_weak(analyzer):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
    )

    assert (
        APIIndicatorType.WEAK_CONTENT_TYPE
        not in result.types
    )
    assert (
        APIIndicatorType.MISSING_CONTENT_TYPE
        not in result.types
    )


def test_wildcard_cors_with_credentials_is_detected(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
        cors_origin="*",
        cors_credentials=True,
    )

    assert (
        APIIndicatorType.CORS_MISCONFIGURATION
        in result.types
    )


def test_wildcard_cors_without_credentials_is_not_detected(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
        cors_origin="*",
        cors_credentials=False,
    )

    assert (
        APIIndicatorType.CORS_MISCONFIGURATION
        not in result.types
    )


def test_specific_cors_origin_with_credentials_is_not_flagged_here(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
        cors_origin="https://example.com",
        cors_credentials=True,
    )

    assert (
        APIIndicatorType.CORS_MISCONFIGURATION
        not in result.types
    )


def test_indicator_count_matches_indicators(
    analyzer,
):
    result = analyzer.analyze(
        headers={
            "server": "nginx/1.25",
        },
        body='{"password":"x","debug":true}',
        content_type="text/plain",
        allowed_methods=["GET", "DELETE"],
        expected_methods=["GET"],
        cors_origin="*",
        cors_credentials=True,
    )

    assert result.indicator_count == len(
        result.indicators
    )


def test_types_are_unique(analyzer):
    result = analyzer.analyze(
        headers={},
        body='{"password":"x","token":"y"}',
        content_type="application/json",
    )

    assert len(result.types) == len(
        set(result.types)
    )


def test_names_are_unique(analyzer):
    result = analyzer.analyze(
        headers={
            "server": "nginx/1.25",
        },
        body='{"password":"x","token":"y"}',
        content_type="application/json",
    )

    assert len(result.names) == len(
        set(result.names)
    )


def test_names_only_include_named_indicators(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type=None,
    )

    assert all(
        name is not None
        for name in result.names
    )


def test_analysis_result_type(analyzer):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
    )

    assert isinstance(result, APIAnalysis)


def test_indicator_result_type(analyzer):
    result = analyzer.analyze(
        headers={},
        body='{"password":"x"}',
        content_type="application/json",
    )

    assert all(
        isinstance(item, APIIndicator)
        for item in result.indicators
    )


def test_detected_matches_indicator_presence(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
    )

    assert result.detected == bool(
        result.indicators
    )


def test_empty_inputs_are_supported(analyzer):
    result = analyzer.analyze()

    assert result.detected is True
    assert result.indicator_count > 0


def test_required_security_headers_can_be_empty(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
        required_security_headers=set(),
    )

    assert (
        APIIndicatorType.MISSING_SECURITY_HEADER
        not in result.types
    )


def test_none_allowed_methods_is_supported(analyzer):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
        allowed_methods=None,
    )

    assert (
        APIIndicatorType.UNRESTRICTED_METHOD
        not in result.types
    )


def test_none_expected_methods_is_supported(analyzer):
    result = analyzer.analyze(
        headers={},
        body="{}",
        content_type="application/json",
        expected_methods=None,
    )

    assert (
        APIIndicatorType.UNRESTRICTED_METHOD
        not in result.types
    )


def test_none_body_is_supported(analyzer):
    result = analyzer.analyze(
        headers={},
        body=None,
        content_type="application/json",
    )

    assert isinstance(result, APIAnalysis)


def test_invalid_headers_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(headers=[])


def test_invalid_body_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(body=b"response")


def test_invalid_allowed_methods_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            allowed_methods="GET"
        )


def test_invalid_expected_methods_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            expected_methods="GET"
        )


def test_invalid_cors_credentials_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            cors_credentials="true"
        )


def test_custom_security_header_case_is_normalized(
    analyzer,
):
    result = analyzer.analyze(
        headers={
            "X-Custom-Header": "enabled",
        },
        body="{}",
        content_type="application/json",
        required_security_headers={
            "x-custom-header",
        },
    )

    assert (
        APIIndicatorType.MISSING_SECURITY_HEADER
        not in result.types
    )


def test_server_header_name_is_case_insensitive(
    analyzer,
):
    result = analyzer.analyze(
        headers={
            "Server": "Apache/2.4",
        },
        body="{}",
        content_type="application/json",
    )

    assert (
        APIIndicatorType.SERVER_DISCLOSURE
        in result.types
    )


def test_sensitive_and_debug_indicators_can_coexist(
    analyzer,
):
    result = analyzer.analyze(
        headers={},
        body='{"password":"x","debug mode enabled":true}',
        content_type="application/json",
    )

    assert (
        APIIndicatorType.EXCESSIVE_DATA_EXPOSURE
        in result.types
    )
    assert (
        APIIndicatorType.DEBUG_INFORMATION
        in result.types
    )


def test_all_indicator_types_are_reachable(
    analyzer,
):
    result = analyzer.analyze(
        headers={
            "server": "nginx/1.25",
        },
        body=(
            '{"password":"x",'
            '"debug mode":true,'
            '"traceback":"test"}'
        ),
        allowed_methods=["GET", "DELETE"],
        expected_methods=["GET"],
        content_type="text/plain",
        cors_origin="*",
        cors_credentials=True,
    )

    expected = {
        APIIndicatorType.MISSING_SECURITY_HEADER,
        APIIndicatorType.EXCESSIVE_DATA_EXPOSURE,
        APIIndicatorType.VERBOSE_ERROR,
        APIIndicatorType.DEBUG_INFORMATION,
        APIIndicatorType.SERVER_DISCLOSURE,
        APIIndicatorType.VERSION_DISCLOSURE,
        APIIndicatorType.UNRESTRICTED_METHOD,
        APIIndicatorType.WEAK_CONTENT_TYPE,
        APIIndicatorType.CORS_MISCONFIGURATION,
    }

    assert expected.issubset(set(result.types))
