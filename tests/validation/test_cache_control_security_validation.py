from m_hunter.validation.cache_control_security import (
    CacheControlSecurityValidator,
)


def test_security_indicators():
    validator = CacheControlSecurityValidator()

    for indicator in validator.SECURITY_INDICATORS:
        result = validator.validate(indicator)

        assert result.indicator == indicator
        assert result.requires_response_change is True


def test_public_sensitive_content():
    validator = CacheControlSecurityValidator()

    result = validator.validate("PUBLIC_SENSITIVE_CONTENT")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("PUBLIC_SENSITIVE_CONTENT") is True


def test_missing_vary():
    validator = CacheControlSecurityValidator()

    result = validator.validate("MISSING_VARY")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("MISSING_VARY") is True


def test_conflicting_directives():
    validator = CacheControlSecurityValidator()

    result = validator.validate("CONFLICTING_CACHE_DIRECTIVES")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("CONFLICTING_CACHE_DIRECTIVES") is True


def test_multiple_cache_control():
    validator = CacheControlSecurityValidator()

    result = validator.validate("MULTIPLE_CACHE_CONTROL")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("MULTIPLE_CACHE_CONTROL") is True


def test_informational_indicator():
    validator = CacheControlSecurityValidator()

    result = validator.validate("CACHE_CONTROL_PRESENT")

    assert result.requires_response_change is False
    assert validator.is_security_relevant("CACHE_CONTROL_PRESENT") is False


def test_validate_all():
    validator = CacheControlSecurityValidator()

    results = validator.validate_all(
        [
            "CACHE_CONTROL_PRESENT",
            "PUBLIC_SENSITIVE_CONTENT",
            "MISSING_VARY",
        ]
    )

    assert len(results) == 3
    assert results[0].requires_response_change is False
    assert results[1].requires_response_change is True
    assert results[2].requires_response_change is True
