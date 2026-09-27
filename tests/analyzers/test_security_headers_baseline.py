from m_hunter.analyzers.security_headers_baseline import (
    SecurityHeaderIndicatorType,
    SecurityHeadersBaselineAnalyzer,
)


def test_x_content_type_options():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
    )

    assert result.has_type(SecurityHeaderIndicatorType.X_CONTENT_TYPE_OPTIONS)
    assert result.count >= 2


def test_x_content_type_options_missing():
    result = SecurityHeadersBaselineAnalyzer().analyze()

    assert result.has_type(
        SecurityHeaderIndicatorType.X_CONTENT_TYPE_OPTIONS_MISSING
    )
    assert result.has_type(SecurityHeaderIndicatorType.NOSNIFF_MISSING)


def test_x_xss_protection():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_xss_protection="1; mode=block",
    )

    assert result.has_type(SecurityHeaderIndicatorType.X_XSS_PROTECTION)
    assert result.has_type(SecurityHeaderIndicatorType.X_XSS_PROTECTION_UNSAFE)


def test_x_xss_protection_non_legacy():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_xss_protection="0",
    )

    assert result.has_type(SecurityHeaderIndicatorType.X_XSS_PROTECTION)
    assert not result.has_type(
        SecurityHeaderIndicatorType.X_XSS_PROTECTION_UNSAFE
    )


def test_expect_ct():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        expect_ct="max-age=86400, enforce",
    )

    assert result.has_type(SecurityHeaderIndicatorType.EXPECT_CT)
    assert result.has_type(SecurityHeaderIndicatorType.EXPECT_CT_DEPRECATED)


def test_cross_domain_policy():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_permitted_cross_domain_policies="all",
    )

    assert result.has_type(
        SecurityHeaderIndicatorType.X_PERMITTED_CROSS_DOMAIN_POLICIES
    )
    assert result.has_type(
        SecurityHeaderIndicatorType.CROSS_DOMAIN_POLICY_UNSAFE
    )


def test_cross_domain_policy_restricted():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_permitted_cross_domain_policies="none",
    )

    assert result.has_type(
        SecurityHeaderIndicatorType.X_PERMITTED_CROSS_DOMAIN_POLICIES
    )
    assert not result.has_type(
        SecurityHeaderIndicatorType.CROSS_DOMAIN_POLICY_UNSAFE
    )


def test_clear_site_data():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        clear_site_data='"cache", "cookies"',
    )

    assert result.has_type(SecurityHeaderIndicatorType.CLEAR_SITE_DATA)
    assert not result.has_type(
        SecurityHeaderIndicatorType.CLEAR_SITE_DATA_WILDCARD
    )


def test_clear_site_data_wildcard():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        clear_site_data='"*"',
    )

    assert result.has_type(SecurityHeaderIndicatorType.CLEAR_SITE_DATA)
    assert result.has_type(
        SecurityHeaderIndicatorType.CLEAR_SITE_DATA_WILDCARD
    )


def test_security_headers_present():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
        x_xss_protection="0",
    )

    assert result.has_type(
        SecurityHeaderIndicatorType.SECURITY_HEADERS_PRESENT
    )


def test_security_headers_missing():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
    )

    assert result.has_type(
        SecurityHeaderIndicatorType.SECURITY_HEADERS_MISSING
    )


def test_multiple_security_header():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
        multiple_security_header=True,
    )

    assert result.has_type(
        SecurityHeaderIndicatorType.MULTIPLE_SECURITY_HEADER
    )


def test_count():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
        x_xss_protection="0",
        clear_site_data='"cache"',
    )

    assert result.count == len(result.indicators)


def test_types():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
    )

    assert all(
        isinstance(item, SecurityHeaderIndicatorType)
        for item in result.types
    )


def test_names():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
    )

    assert result.names
    assert all(isinstance(name, str) for name in result.names)


def test_has_type_false():
    result = SecurityHeadersBaselineAnalyzer().analyze()

    assert not result.has_type(SecurityHeaderIndicatorType.EXPECT_CT)


def test_all_headers():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
        x_xss_protection="0",
        expect_ct="max-age=86400",
        x_permitted_cross_domain_policies="none",
        clear_site_data='"cache"',
    )

    assert result.has_type(SecurityHeaderIndicatorType.X_CONTENT_TYPE_OPTIONS)
    assert result.has_type(SecurityHeaderIndicatorType.X_XSS_PROTECTION)
    assert result.has_type(SecurityHeaderIndicatorType.EXPECT_CT)
    assert result.has_type(
        SecurityHeaderIndicatorType.X_PERMITTED_CROSS_DOMAIN_POLICIES
    )
    assert result.has_type(SecurityHeaderIndicatorType.CLEAR_SITE_DATA)


def test_empty_headers():
    result = SecurityHeadersBaselineAnalyzer().analyze()

    assert result.count >= 3
    assert result.has_type(
        SecurityHeaderIndicatorType.SECURITY_HEADERS_MISSING
    )


def test_case_insensitive_nosniff():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="NoSniff",
    )

    assert result.has_type(SecurityHeaderIndicatorType.X_CONTENT_TYPE_OPTIONS)


def test_case_insensitive_cross_domain_policy():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_permitted_cross_domain_policies="ALL",
    )

    assert result.has_type(
        SecurityHeaderIndicatorType.CROSS_DOMAIN_POLICY_UNSAFE
    )


def test_wildcard_detection():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        clear_site_data='"*"',
    )

    assert result.has_type(
        SecurityHeaderIndicatorType.CLEAR_SITE_DATA_WILDCARD
    )


def test_multiple_headers_flag():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        multiple_security_header=True,
    )

    assert result.has_type(
        SecurityHeaderIndicatorType.MULTIPLE_SECURITY_HEADER
    )


def test_missing_count():
    result = SecurityHeadersBaselineAnalyzer().analyze(
        x_content_type_options="nosniff",
        x_xss_protection="0",
    )

    missing = next(
        item
        for item in result.indicators
        if item.type == SecurityHeaderIndicatorType.SECURITY_HEADERS_MISSING
    )

    assert missing.value == "3"
