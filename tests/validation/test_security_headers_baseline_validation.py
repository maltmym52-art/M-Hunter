from m_hunter.validation.security_headers_baseline import (
    SecurityHeadersBaselineValidator,
)


def test_security_indicators():
    validator = SecurityHeadersBaselineValidator()

    for indicator in validator.SECURITY_INDICATORS:
        result = validator.validate(indicator)

        assert result.indicator == indicator
        assert result.requires_response_change is True


def test_content_type_options_missing():
    validator = SecurityHeadersBaselineValidator()

    result = validator.validate("X_CONTENT_TYPE_OPTIONS_MISSING")

    assert result.requires_response_change is True
    assert validator.is_security_relevant(
        "X_CONTENT_TYPE_OPTIONS_MISSING"
    )


def test_nosniff_missing():
    validator = SecurityHeadersBaselineValidator()

    result = validator.validate("NOSNIFF_MISSING")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("NOSNIFF_MISSING")


def test_unsafe_xss_protection():
    validator = SecurityHeadersBaselineValidator()

    result = validator.validate("X_XSS_PROTECTION_UNSAFE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("X_XSS_PROTECTION_UNSAFE")


def test_unsafe_cross_domain_policy():
    validator = SecurityHeadersBaselineValidator()

    result = validator.validate("CROSS_DOMAIN_POLICY_UNSAFE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant(
        "CROSS_DOMAIN_POLICY_UNSAFE"
    )


def test_clear_site_data_wildcard():
    validator = SecurityHeadersBaselineValidator()

    result = validator.validate("CLEAR_SITE_DATA_WILDCARD")

    assert result.requires_response_change is True
    assert validator.is_security_relevant(
        "CLEAR_SITE_DATA_WILDCARD"
    )


def test_multiple_security_header():
    validator = SecurityHeadersBaselineValidator()

    result = validator.validate("MULTIPLE_SECURITY_HEADER")

    assert result.requires_response_change is True
    assert validator.is_security_relevant(
        "MULTIPLE_SECURITY_HEADER"
    )


def test_informational_indicator():
    validator = SecurityHeadersBaselineValidator()

    result = validator.validate("EXPECT_CT_DEPRECATED")

    assert result.requires_response_change is False
    assert validator.is_security_relevant(
        "EXPECT_CT_DEPRECATED"
    ) is False


def test_validate_all():
    validator = SecurityHeadersBaselineValidator()

    results = validator.validate_all(
        [
            "X_CONTENT_TYPE_OPTIONS_MISSING",
            "X_XSS_PROTECTION_UNSAFE",
            "EXPECT_CT_DEPRECATED",
        ]
    )

    assert len(results) == 3
    assert results[0].requires_response_change is True
    assert results[1].requires_response_change is True
    assert results[2].requires_response_change is False
