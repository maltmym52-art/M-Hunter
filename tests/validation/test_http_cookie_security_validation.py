from m_hunter.validation.http_cookie_security import (
    HttpCookieSecurityValidator,
)


def test_security_indicators():
    validator = HttpCookieSecurityValidator()

    for indicator in validator.SECURITY_INDICATORS:
        result = validator.validate(indicator)

        assert result.indicator == indicator
        assert result.requires_response_change is True


def test_secure_missing():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("SECURE_MISSING")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("SECURE_MISSING")


def test_httponly_missing():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("HTTPONLY_MISSING")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("HTTPONLY_MISSING")


def test_samesite_missing():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("SAMESITE_MISSING")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("SAMESITE_MISSING")


def test_samesite_none():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("SAMESITE_NONE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("SAMESITE_NONE")


def test_samesite_invalid():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("SAMESITE_INVALID")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("SAMESITE_INVALID")


def test_domain_broad():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("DOMAIN_BROAD")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("DOMAIN_BROAD")


def test_path_broad():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("PATH_BROAD")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("PATH_BROAD")


def test_long_lived_cookie():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("LONG_LIVED_COOKIE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("LONG_LIVED_COOKIE")


def test_prefix_violation():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("PREFIX_VIOLATION")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("PREFIX_VIOLATION")


def test_duplicate_cookie():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("DUPLICATE_COOKIE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("DUPLICATE_COOKIE")


def test_informational_indicator():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("COOKIE_PRESENT")

    assert result.requires_response_change is False
    assert validator.is_security_relevant("COOKIE_PRESENT") is False


def test_session_cookie_is_informational():
    validator = HttpCookieSecurityValidator()

    result = validator.validate("SESSION_COOKIE")

    assert result.requires_response_change is False
    assert validator.is_security_relevant("SESSION_COOKIE") is False


def test_validate_all():
    validator = HttpCookieSecurityValidator()

    results = validator.validate_all(
        [
            "SECURE_MISSING",
            "HTTPONLY_MISSING",
            "COOKIE_PRESENT",
        ]
    )

    assert len(results) == 3
    assert results[0].requires_response_change is True
    assert results[1].requires_response_change is True
    assert results[2].requires_response_change is False
