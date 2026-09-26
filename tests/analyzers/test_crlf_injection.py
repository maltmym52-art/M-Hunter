import pytest

from m_hunter.analyzers.crlf_injection import (
    CRLFInjectionAnalyzer,
    CRLFInjectionIndicatorType,
)


@pytest.fixture
def analyzer():
    return CRLFInjectionAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()
    assert result.detected is False
    assert result.count == 0
    assert result.types == ()


def test_raw_crlf(analyzer):
    result = analyzer.analyze(
        url="https://example.test/?next=one\r\ntwo"
    )
    assert result.detected
    assert result.has_type(CRLFInjectionIndicatorType.CRLF)


def test_encoded_crlf(analyzer):
    result = analyzer.analyze(
        url="https://example.test/?next=one%0d%0aInjected: yes"
    )
    assert result.detected
    assert result.has_type(CRLFInjectionIndicatorType.CRLF_ENCODED)


def test_encoded_crlf_decodes_to_crlf(analyzer):
    result = analyzer.analyze(
        params={"next": "one%0D%0Atwo"}
    )
    assert result.has_type(CRLFInjectionIndicatorType.CRLF)


def test_lf_injection(analyzer):
    result = analyzer.analyze(
        params={"next": "one%0Atwo"}
    )
    assert result.has_type(CRLFInjectionIndicatorType.LF_INJECTION)


def test_cr_injection(analyzer):
    result = analyzer.analyze(
        params={"next": "one%0Dtwo"}
    )
    assert result.has_type(CRLFInjectionIndicatorType.CR_INJECTION)


def test_header_value(analyzer):
    result = analyzer.analyze(
        headers={"Location": "https://example.test"}
    )
    assert result.has_type(CRLFInjectionIndicatorType.HEADER_INJECTION)


def test_location_header(analyzer):
    result = analyzer.analyze(
        location="https://example.test"
    )
    assert result.has_type(CRLFInjectionIndicatorType.LOCATION_HEADER)


def test_set_cookie_header(analyzer):
    result = analyzer.analyze(
        set_cookie="session=abc"
    )
    assert result.has_type(CRLFInjectionIndicatorType.SET_COOKIE_HEADER)


def test_response_location(analyzer):
    result = analyzer.analyze(
        response_headers={"Location": "https://example.test"}
    )
    assert result.has_type(CRLFInjectionIndicatorType.LOCATION_HEADER)


def test_response_set_cookie(analyzer):
    result = analyzer.analyze(
        response_headers={"Set-Cookie": "session=abc"}
    )
    assert result.has_type(CRLFInjectionIndicatorType.SET_COOKIE_HEADER)


def test_generic_response_header(analyzer):
    result = analyzer.analyze(
        response_headers={"X-Test": "value"}
    )
    assert result.has_type(CRLFInjectionIndicatorType.RESPONSE_HEADER)


def test_multiple_parameters(analyzer):
    result = analyzer.analyze(
        params={
            "next": "one%0d%0atwo",
            "redirect": "safe",
        }
    )
    assert result.detected
    assert "next" in result.names


def test_multiple_indicator_types(analyzer):
    result = analyzer.analyze(
        url="https://example.test/?x=%0d%0a",
        response_headers={"Location": "https://example.test"},
    )
    assert result.count >= 2
    assert len(result.types) >= 2


def test_value_preserved(analyzer):
    value = "one%0d%0aInjected: yes"
    result = analyzer.analyze(params={"next": value})
    assert any(
        indicator.value == value
        for indicator in result.indicators
    )


def test_non_string_url_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(url=123)


def test_non_dict_params_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(params=[])


def test_non_dict_headers_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(headers=[])


def test_non_dict_response_headers_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(response_headers=[])


def test_non_string_parameter_value_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(params={"next": 123})


def test_non_string_header_value_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(headers={"Location": 123})


def test_non_string_response_header_value_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(response_headers={"Location": 123})


def test_names_are_unique(analyzer):
    result = analyzer.analyze(
        params={
            "next": "%0d%0a",
            "next2": "%0d%0a",
        }
    )
    assert result.names == ("next", "next2")
