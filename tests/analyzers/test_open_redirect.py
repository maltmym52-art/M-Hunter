import pytest

from m_hunter.analyzers.open_redirect import (
    OpenRedirectAnalyzer,
    OpenRedirectIndicatorType,
)


@pytest.fixture
def analyzer():
    return OpenRedirectAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()

    assert not result.detected
    assert result.count == 0
    assert result.types == []
    assert result.names == []


def test_redirect_parameter(analyzer):
    result = analyzer.analyze(
        url="https://example.com/login?redirect=https://other.example"
    )

    assert result.detected
    assert result.has_type(
        OpenRedirectIndicatorType.REDIRECT_PARAMETER
    )


def test_absolute_url(analyzer):
    result = analyzer.analyze(
        params={"redirect": "https://other.example/path"}
    )

    assert result.has_type(
        OpenRedirectIndicatorType.ABSOLUTE_URL
    )
    assert result.has_type(
        OpenRedirectIndicatorType.EXTERNAL_URL
    )


def test_external_host(analyzer):
    result = analyzer.analyze(
        params={"next": "https://evil.example/path"},
        target_host="example.com",
    )

    assert result.has_type(
        OpenRedirectIndicatorType.EXTERNAL_HOST
    )


def test_same_host_absolute_url(analyzer):
    result = analyzer.analyze(
        params={"next": "https://example.com/path"},
        target_host="example.com",
    )

    assert result.has_type(
        OpenRedirectIndicatorType.ABSOLUTE_URL
    )
    assert not result.has_type(
        OpenRedirectIndicatorType.EXTERNAL_HOST
    )


def test_protocol_relative_url(analyzer):
    result = analyzer.analyze(
        params={"next": "//other.example/path"}
    )

    assert result.has_type(
        OpenRedirectIndicatorType.PROTOCOL_RELATIVE_URL
    )
    assert result.has_type(
        OpenRedirectIndicatorType.USER_CONTROLLED_DESTINATION
    )


@pytest.mark.parametrize(
    "parameter, indicator_type",
    [
        ("redirect", OpenRedirectIndicatorType.REDIRECT_PARAMETER),
        ("redirect_uri", OpenRedirectIndicatorType.REDIRECT_PARAMETER),
        ("redirect_url", OpenRedirectIndicatorType.REDIRECT_PARAMETER),
        ("url", OpenRedirectIndicatorType.URL_PARAMETER),
        ("return_url", OpenRedirectIndicatorType.RETURN_URL_PARAMETER),
        ("next", OpenRedirectIndicatorType.NEXT_PARAMETER),
        ("continue", OpenRedirectIndicatorType.CONTINUE_PARAMETER),
        ("destination", OpenRedirectIndicatorType.DESTINATION_PARAMETER),
    ],
)
def test_redirect_parameter_names(
    analyzer,
    parameter,
    indicator_type,
):
    result = analyzer.analyze(
        params={parameter: "/local/path"}
    )

    assert result.has_type(indicator_type)


def test_location_argument(analyzer):
    result = analyzer.analyze(
        location="https://other.example/path"
    )

    assert result.has_type(
        OpenRedirectIndicatorType.LOCATION_HEADER
    )
    assert result.has_type(
        OpenRedirectIndicatorType.ABSOLUTE_URL
    )


def test_location_header(analyzer):
    result = analyzer.analyze(
        headers={"Location": "https://other.example/path"}
    )

    assert result.has_type(
        OpenRedirectIndicatorType.LOCATION_HEADER
    )


def test_redirect_response(analyzer):
    result = analyzer.analyze(
        status_code=302
    )

    assert result.has_type(
        OpenRedirectIndicatorType.REDIRECT_RESPONSE
    )


def test_non_redirect_status(analyzer):
    result = analyzer.analyze(
        status_code=200
    )

    assert not result.has_type(
        OpenRedirectIndicatorType.REDIRECT_RESPONSE
    )


def test_local_destination(analyzer):
    result = analyzer.analyze(
        params={"next": "/dashboard"}
    )

    assert result.has_type(
        OpenRedirectIndicatorType.NEXT_PARAMETER
    )
    assert not result.has_type(
        OpenRedirectIndicatorType.EXTERNAL_URL
    )


def test_empty_destination(analyzer):
    result = analyzer.analyze(
        params={"next": ""}
    )

    assert result.detected
    assert result.has_type(
        OpenRedirectIndicatorType.NEXT_PARAMETER
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"url": 123},
        {"params": "invalid"},
        {"location": 123},
        {"status_code": "302"},
        {"headers": "invalid"},
        {"target_host": 123},
    ],
)
def test_invalid_types(analyzer, kwargs):
    with pytest.raises(TypeError):
        analyzer.analyze(**kwargs)


def test_names_and_values(analyzer):
    result = analyzer.analyze(
        params={"redirect": "https://other.example"}
    )

    assert "redirect" in result.names
    assert any(
        indicator.value == "https://other.example"
        for indicator in result.indicators
    )


def test_multiple_sources(analyzer):
    result = analyzer.analyze(
        url="https://example.com/?next=https://one.example",
        params={"redirect": "https://two.example"},
        location="https://three.example",
        status_code=302,
    )

    assert result.detected
    assert result.count >= 7


def test_case_insensitive_parameter(analyzer):
    result = analyzer.analyze(
        params={"NEXT": "https://other.example"}
    )

    assert result.has_type(
        OpenRedirectIndicatorType.NEXT_PARAMETER
    )
