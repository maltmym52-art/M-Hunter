from m_hunter.analyzers.http_response_security import (
    HttpResponseSecurityAnalyzer,
    HttpResponseSecurityIndicatorType,
)


def test_server_disclosure():
    result = HttpResponseSecurityAnalyzer().analyze(
        server="nginx",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.SERVER_DISCLOSURE
    )


def test_server_version_disclosure():
    result = HttpResponseSecurityAnalyzer().analyze(
        server="nginx/1.24.0",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.SERVER_VERSION_DISCLOSURE
    )


def test_x_powered_by():
    result = HttpResponseSecurityAnalyzer().analyze(
        x_powered_by="PHP/8.3",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.X_POWERED_BY
    )
    assert result.has_type(
        HttpResponseSecurityIndicatorType.TECHNOLOGY_DISCLOSURE
    )


def test_debug_flag():
    result = HttpResponseSecurityAnalyzer().analyze(
        debug=True,
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.DEBUG_DISCLOSURE
    )


def test_debug_body():
    result = HttpResponseSecurityAnalyzer().analyze(
        body="Debug toolbar enabled",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.DEBUG_DISCLOSURE
    )


def test_stack_trace_flag():
    result = HttpResponseSecurityAnalyzer().analyze(
        stack_trace=True,
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.STACK_TRACE_DISCLOSURE
    )


def test_stack_trace_body():
    result = HttpResponseSecurityAnalyzer().analyze(
        body="Traceback (most recent call last)",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.STACK_TRACE_DISCLOSURE
    )


def test_exception_details():
    result = HttpResponseSecurityAnalyzer().analyze(
        exception_details=True,
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.EXCEPTION_DISCLOSURE
    )


def test_exception_body():
    result = HttpResponseSecurityAnalyzer().analyze(
        body="Unhandled exception occurred",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.EXCEPTION_DISCLOSURE
    )


def test_internal_path_flag():
    result = HttpResponseSecurityAnalyzer().analyze(
        internal_path=True,
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.INTERNAL_PATH_DISCLOSURE
    )


def test_internal_path_body():
    result = HttpResponseSecurityAnalyzer().analyze(
        body="File: /var/www/app/config.py",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.INTERNAL_PATH_DISCLOSURE
    )


def test_internal_ip():
    result = HttpResponseSecurityAnalyzer().analyze(
        internal_ip=True,
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.INTERNAL_IP_DISCLOSURE
    )


def test_directory_listing_flag():
    result = HttpResponseSecurityAnalyzer().analyze(
        directory_listing=True,
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.DIRECTORY_LISTING
    )


def test_directory_listing_body():
    result = HttpResponseSecurityAnalyzer().analyze(
        body="<title>Index of /backup</title>",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.DIRECTORY_LISTING
    )


def test_error_details():
    result = HttpResponseSecurityAnalyzer().analyze(
        debug=True,
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.ERROR_DETAILS_DISCLOSURE
    )


def test_information_present():
    result = HttpResponseSecurityAnalyzer().analyze(
        server="Apache/2.4.58",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.RESPONSE_INFORMATION_PRESENT
    )


def test_empty_response():
    result = HttpResponseSecurityAnalyzer().analyze()

    assert result.count == 0


def test_count():
    result = HttpResponseSecurityAnalyzer().analyze(
        server="nginx/1.24.0",
        x_powered_by="PHP/8.3",
    )

    assert result.count == len(result.indicators)


def test_types():
    result = HttpResponseSecurityAnalyzer().analyze(
        server="nginx",
    )

    assert all(
        isinstance(item, HttpResponseSecurityIndicatorType)
        for item in result.types
    )


def test_names():
    result = HttpResponseSecurityAnalyzer().analyze(
        server="nginx",
    )

    assert result.names
    assert all(isinstance(name, str) for name in result.names)


def test_has_type_false():
    result = HttpResponseSecurityAnalyzer().analyze(
        server="nginx",
    )

    assert not result.has_type(
        HttpResponseSecurityIndicatorType.DIRECTORY_LISTING
    )


def test_multiple_indicators():
    result = HttpResponseSecurityAnalyzer().analyze(
        server="Apache/2.4.58",
        x_powered_by="PHP/8.3",
        debug=True,
        internal_ip=True,
        directory_listing=True,
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.SERVER_DISCLOSURE
    )
    assert result.has_type(
        HttpResponseSecurityIndicatorType.X_POWERED_BY
    )
    assert result.has_type(
        HttpResponseSecurityIndicatorType.DEBUG_DISCLOSURE
    )
    assert result.has_type(
        HttpResponseSecurityIndicatorType.INTERNAL_IP_DISCLOSURE
    )
    assert result.has_type(
        HttpResponseSecurityIndicatorType.DIRECTORY_LISTING
    )


def test_case_insensitive_markers():
    result = HttpResponseSecurityAnalyzer().analyze(
        body="DIRECTORY LISTING",
    )

    assert result.has_type(
        HttpResponseSecurityIndicatorType.DIRECTORY_LISTING
    )
