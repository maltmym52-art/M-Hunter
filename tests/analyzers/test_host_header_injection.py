import pytest

from m_hunter.analyzers.host_header_injection import (
    HostHeaderInjectionAnalyzer,
    HostHeaderInjectionIndicatorType,
)


@pytest.fixture
def analyzer():
    return HostHeaderInjectionAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()
    assert result.detected is False
    assert result.count == 0
    assert result.types == ()


def test_host_header(analyzer):
    result = analyzer.analyze(
        headers={"Host": "example.test"},
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.HOST_HEADER
    )


def test_forwarded_host(analyzer):
    result = analyzer.analyze(
        headers={"X-Forwarded-Host": "example.test"},
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.FORWARDED_HOST
    )


def test_x_host(analyzer):
    result = analyzer.analyze(
        headers={"X-Host": "example.test"},
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.X_HOST
    )


def test_forwarded_header(analyzer):
    result = analyzer.analyze(
        headers={"Forwarded": "host=example.test"},
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.FORWARDED_HEADER
    )


def test_host_override(analyzer):
    result = analyzer.analyze(
        headers={"X-Original-Host": "example.test"},
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.HOST_OVERRIDE
    )


def test_external_host(analyzer):
    result = analyzer.analyze(
        headers={"Host": "attacker.test"},
        expected_host="example.test",
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.EXTERNAL_HOST
    )


def test_expected_host_same_is_not_external(analyzer):
    result = analyzer.analyze(
        headers={"Host": "example.test"},
        expected_host="example.test",
    )
    assert not result.has_type(
        HostHeaderInjectionIndicatorType.EXTERNAL_HOST
    )


def test_absolute_location(analyzer):
    result = analyzer.analyze(
        response_headers={
            "Location": "https://example.test/reset"
        },
        expected_host="example.test",
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.ABSOLUTE_URL
    )


def test_external_location(analyzer):
    result = analyzer.analyze(
        response_headers={
            "Location": "https://attacker.test/reset"
        },
        expected_host="example.test",
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.EXTERNAL_HOST
    )


def test_password_reset_marker(analyzer):
    result = analyzer.analyze(
        response_body="Click here to reset password.",
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.PASSWORD_RESET_LINK
    )


def test_email_link_marker(analyzer):
    result = analyzer.analyze(
        response_body="An email link was generated.",
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.EMAIL_LINK
    )


def test_canonical_marker(analyzer):
    result = analyzer.analyze(
        response_body='<link rel="canonical" href="https://example.test">',
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.CANONICAL_URL
    )


def test_absolute_url_in_body(analyzer):
    result = analyzer.analyze(
        response_body="https://example.test/account",
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.ABSOLUTE_URL
    )


def test_external_url_in_body(analyzer):
    result = analyzer.analyze(
        response_body="https://attacker.test/reset",
        expected_host="example.test",
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.EXTERNAL_HOST
    )


def test_request_host_mismatch(analyzer):
    result = analyzer.analyze(
        headers={"Host": "attacker.test"},
        request_host="example.test",
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.HOST_MISMATCH
    )


def test_request_response_host_mismatch(analyzer):
    result = analyzer.analyze(
        request_host="example.test",
        response_host="attacker.test",
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.HOST_MISMATCH
    )


def test_absolute_link_header(analyzer):
    result = analyzer.analyze(
        response_headers={
            "Link": '<https://example.test/reset>; rel="alternate"'
        },
    )
    assert result.has_type(
        HostHeaderInjectionIndicatorType.ABSOLUTE_URL
    )


def test_value_preserved(analyzer):
    value = "attacker.test"

    result = analyzer.analyze(
        headers={"Host": value},
    )

    assert any(
        indicator.value == value
        for indicator in result.indicators
    )


def test_names_are_unique(analyzer):
    result = analyzer.analyze(
        headers={
            "Host": "example.test",
            "X-Host": "example.test",
        },
    )

    assert len(result.names) == len(set(result.names))


def test_types_are_unique(analyzer):
    result = analyzer.analyze(
        headers={
            "Host": "attacker.test",
            "X-Forwarded-Host": "attacker.test",
        },
        expected_host="example.test",
    )

    assert len(result.types) == len(set(result.types))


def test_non_dict_headers_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(headers=[])


def test_non_dict_response_headers_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(response_headers=[])


def test_non_string_response_body_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(response_body=123)


def test_non_string_expected_host_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(expected_host=123)


def test_non_string_header_value_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            headers={"Host": 123},
        )


def test_bytes_response_body_supported(analyzer):
    result = analyzer.analyze(
        response_body=b"Password reset link",
    )
    assert result.detected
