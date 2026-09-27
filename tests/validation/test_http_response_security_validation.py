from m_hunter.validation.http_response_security import (
    HttpResponseSecurityValidator,
)


def test_security_indicators():
    validator = HttpResponseSecurityValidator()

    for indicator in validator.SECURITY_INDICATORS:
        result = validator.validate(indicator)

        assert result.indicator == indicator
        assert result.requires_response_change is True


def test_server_version_disclosure():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("SERVER_VERSION_DISCLOSURE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant(
        "SERVER_VERSION_DISCLOSURE"
    )


def test_x_powered_by():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("X_POWERED_BY")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("X_POWERED_BY")


def test_debug_disclosure():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("DEBUG_DISCLOSURE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("DEBUG_DISCLOSURE")


def test_stack_trace_disclosure():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("STACK_TRACE_DISCLOSURE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("STACK_TRACE_DISCLOSURE")


def test_exception_disclosure():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("EXCEPTION_DISCLOSURE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("EXCEPTION_DISCLOSURE")


def test_internal_path_disclosure():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("INTERNAL_PATH_DISCLOSURE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("INTERNAL_PATH_DISCLOSURE")


def test_internal_ip_disclosure():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("INTERNAL_IP_DISCLOSURE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("INTERNAL_IP_DISCLOSURE")


def test_directory_listing():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("DIRECTORY_LISTING")

    assert result.requires_response_change is True
    assert validator.is_security_relevant("DIRECTORY_LISTING")


def test_error_details_disclosure():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("ERROR_DETAILS_DISCLOSURE")

    assert result.requires_response_change is True
    assert validator.is_security_relevant(
        "ERROR_DETAILS_DISCLOSURE"
    )


def test_informational_indicator():
    validator = HttpResponseSecurityValidator()

    result = validator.validate("SERVER_DISCLOSURE")

    assert result.requires_response_change is False
    assert validator.is_security_relevant(
        "SERVER_DISCLOSURE"
    ) is False


def test_validate_all():
    validator = HttpResponseSecurityValidator()

    results = validator.validate_all(
        [
            "SERVER_VERSION_DISCLOSURE",
            "DEBUG_DISCLOSURE",
            "SERVER_DISCLOSURE",
        ]
    )

    assert len(results) == 3
    assert results[0].requires_response_change is True
    assert results[1].requires_response_change is True
    assert results[2].requires_response_change is False
