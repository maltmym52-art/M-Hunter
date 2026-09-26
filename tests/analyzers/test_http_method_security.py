import pytest

from m_hunter.analyzers.http_method_security import (
    HTTPMethodSecurityAnalysis,
    HTTPMethodSecurityAnalyzer,
    HTTPMethodSecurityIndicatorType,
)
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


def make_response(
    *,
    status_code=200,
    content=b"OK",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def analyzer():
    return HTTPMethodSecurityAnalyzer()


def make_request(
    method="GET",
    *,
    headers=None,
    params=None,
):
    return HttpRequest(
        method=method,
        url="https://example.com/",
        headers=headers or {},
        params=params or {},
    )


def test_empty_analysis(analyzer):
    result = analyzer.analyze(
        request=make_request(),
        response=make_response(),
    )

    assert isinstance(result, HTTPMethodSecurityAnalysis)
    assert result.detected is False
    assert result.count == 0


@pytest.mark.parametrize(
    "method,indicator",
    [
        ("TRACE", HTTPMethodSecurityIndicatorType.DANGEROUS_METHOD),
        ("TRACK", HTTPMethodSecurityIndicatorType.DANGEROUS_METHOD),
        ("CONNECT", HTTPMethodSecurityIndicatorType.DANGEROUS_METHOD),
    ],
)
def test_dangerous_method_detected(
    analyzer,
    method,
    indicator,
):
    result = analyzer.analyze(
        request=make_request(method),
        response=make_response(),
    )

    assert result.has_type(indicator)


@pytest.mark.parametrize(
    "method,indicator",
    [
        ("TRACE", HTTPMethodSecurityIndicatorType.TRACE_ENABLED),
        ("TRACK", HTTPMethodSecurityIndicatorType.TRACK_ENABLED),
        ("CONNECT", HTTPMethodSecurityIndicatorType.CONNECT_ENABLED),
    ],
)
def test_successful_dangerous_method_detected(
    analyzer,
    method,
    indicator,
):
    result = analyzer.analyze(
        request=make_request(method),
        response=make_response(status_code=200),
    )

    assert result.has_type(indicator)


def test_dangerous_method_error_response_is_not_enabled(
    analyzer,
):
    result = analyzer.analyze(
        request=make_request("TRACE"),
        response=make_response(status_code=405),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.DANGEROUS_METHOD
    )
    assert not result.has_type(
        HTTPMethodSecurityIndicatorType.TRACE_ENABLED
    )
    assert result.has_type(
        HTTPMethodSecurityIndicatorType.METHOD_NOT_ALLOWED
    )


def test_put_detected(analyzer):
    result = analyzer.analyze(
        request=make_request("PUT"),
        response=make_response(),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.UNEXPECTED_PUT
    )


def test_delete_detected(analyzer):
    result = analyzer.analyze(
        request=make_request("DELETE"),
        response=make_response(),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.UNEXPECTED_DELETE
    )


@pytest.mark.parametrize(
    "header",
    [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
    ],
)
def test_method_override_header_detected(
    analyzer,
    header,
):
    result = analyzer.analyze(
        request=make_request(
            headers={header: "DELETE"},
        ),
        response=make_response(),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER
    )


@pytest.mark.parametrize(
    "parameter",
    [
        "_method",
        "method",
        "http_method",
        "http-method",
    ],
)
def test_method_override_parameter_detected(
    analyzer,
    parameter,
):
    result = analyzer.analyze(
        request=make_request(
            params={parameter: "DELETE"},
        ),
        response=make_response(),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_PARAMETER
    )


def test_options_exposure_detected(analyzer):
    result = analyzer.analyze(
        request=make_request("OPTIONS"),
        response=make_response(),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.OPTIONS_EXPOSURE
    )


def test_allow_header_detected(analyzer):
    result = analyzer.analyze(
        request=make_request(),
        response=make_response(
            headers={
                "Allow": "GET, POST, PUT, DELETE",
            },
        ),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.ALLOW_HEADER
    )


def test_method_not_allowed_detected(analyzer):
    result = analyzer.analyze(
        request=make_request("PATCH"),
        response=make_response(status_code=405),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.METHOD_NOT_ALLOWED
    )


def test_case_insensitive_headers(analyzer):
    result = analyzer.analyze(
        request=make_request(
            headers={
                "x-http-method-override": "PUT",
            },
        ),
        response=make_response(),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER
    )


def test_case_insensitive_parameters(analyzer):
    result = analyzer.analyze(
        request=make_request(
            params={
                "_METHOD": "DELETE",
            },
        ),
        response=make_response(),
    )

    assert result.has_type(
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_PARAMETER
    )


def test_names_and_types_are_exposed(analyzer):
    result = analyzer.analyze(
        request=make_request(
            headers={
                "X-HTTP-Method-Override": "DELETE",
            },
        ),
        response=make_response(
            headers={
                "Allow": "GET, POST",
            },
        ),
    )

    assert "X-HTTP-Method-Override" in result.names
    assert "Allow" in result.names
    assert (
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER
        in result.types
    )


def test_all_indicators_have_evidence(analyzer):
    result = analyzer.analyze(
        request=make_request(
            "TRACE",
            headers={
                "X-HTTP-Method-Override": "DELETE",
            },
            params={
                "_method": "PUT",
            },
        ),
        response=make_response(
            headers={
                "Allow": "GET, POST",
            },
        ),
    )

    assert result.indicators
    assert all(
        indicator.evidence
        for indicator in result.indicators
    )


def test_requires_request(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            request="invalid",
            response=make_response(),
        )


def test_requires_response(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            request=make_request(),
            response="invalid",
        )


def test_normal_get_has_no_method_abuse_indicator(analyzer):
    result = analyzer.analyze(
        request=make_request("GET"),
        response=make_response(),
    )

    assert result.types == set()
