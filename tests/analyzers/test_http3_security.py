import pytest

from m_hunter.analyzers.http3_security import (
    HTTP3Analysis,
    HTTP3Indicator,
    HTTP3IndicatorType,
    HTTP3SecurityAnalyzer,
)


@pytest.fixture
def analyzer():
    return HTTP3SecurityAnalyzer()


def test_name(analyzer):
    assert analyzer.name == "http3_security"


def test_description(analyzer):
    assert "HTTP/3" in analyzer.description


def test_analysis_type(analyzer):
    result = analyzer.analyze(
        scheme="h3"
    )

    assert isinstance(result, HTTP3Analysis)


def test_http3_scheme(analyzer):
    result = analyzer.analyze(
        scheme="h3"
    )

    assert result.has_type(
        HTTP3IndicatorType.HTTP3_SCHEME
    )


def test_http3_scheme_case_insensitive(analyzer):
    result = analyzer.analyze(
        scheme="H3"
    )

    assert result.has_type(
        HTTP3IndicatorType.HTTP3_SCHEME
    )


def test_http3_alpn(analyzer):
    result = analyzer.analyze(
        alpn="h3,h3-29"
    )

    assert result.has_type(
        HTTP3IndicatorType.HTTP3_ALPN
    )


def test_http3_alpn_case_insensitive(analyzer):
    result = analyzer.analyze(
        alpn="H3"
    )

    assert result.has_type(
        HTTP3IndicatorType.HTTP3_ALPN
    )


def test_http3_protocol(analyzer):
    result = analyzer.analyze(
        protocol="HTTP/3"
    )

    assert result.has_type(
        HTTP3IndicatorType.HTTP3_PROTOCOL
    )


def test_quic_protocol(analyzer):
    result = analyzer.analyze(
        protocol="QUIC"
    )

    assert result.has_type(
        HTTP3IndicatorType.QUIC_PROTOCOL
    )


def test_both_protocol_indicators(analyzer):
    result = analyzer.analyze(
        protocol="HTTP/3 over QUIC"
    )

    assert result.has_type(
        HTTP3IndicatorType.HTTP3_PROTOCOL
    )
    assert result.has_type(
        HTTP3IndicatorType.QUIC_PROTOCOL
    )


def test_alt_svc_h3(analyzer):
    result = analyzer.analyze(
        alt_svc='h3=":443"'
    )

    assert result.has_type(
        HTTP3IndicatorType.ALT_SVC_H3
    )


def test_alt_svc_h3_case_insensitive(analyzer):
    result = analyzer.analyze(
        alt_svc='H3=":443"'
    )

    assert result.has_type(
        HTTP3IndicatorType.ALT_SVC_H3
    )


def test_authority(analyzer):
    result = analyzer.analyze(
        authority="example.com"
    )

    assert result.has_type(
        HTTP3IndicatorType.AUTHORITY_CONTEXT
    )


def test_pseudo_headers(analyzer):
    result = analyzer.analyze(
        pseudo_headers=[
            ":method",
            ":scheme",
            ":authority",
            ":path",
        ]
    )

    assert result.has_type(
        HTTP3IndicatorType.PSEUDO_HEADER
    )
    assert result.count == 4


def test_non_pseudo_headers_ignored(analyzer):
    result = analyzer.analyze(
        pseudo_headers=[
            "host",
            "content-type",
        ]
    )

    assert not result.detected


def test_quic_error(analyzer):
    result = analyzer.analyze(
        quic_error="connection close"
    )

    assert result.has_type(
        HTTP3IndicatorType.QUIC_ERROR
    )


def test_http3_error(analyzer):
    result = analyzer.analyze(
        http3_error="stream error"
    )

    assert result.has_type(
        HTTP3IndicatorType.HTTP3_ERROR
    )


def test_downgrade(analyzer):
    result = analyzer.analyze(
        downgrade=True
    )

    assert result.has_type(
        HTTP3IndicatorType.DOWNGRADE_INDICATOR
    )


def test_fallback(analyzer):
    result = analyzer.analyze(
        fallback=True
    )

    assert result.has_type(
        HTTP3IndicatorType.FALLBACK_INDICATOR
    )


def test_malformed_protocol(analyzer):
    result = analyzer.analyze(
        malformed_protocol="invalid frame"
    )

    assert result.has_type(
        HTTP3IndicatorType.MALFORMED_PROTOCOL
    )


def test_empty_analysis(analyzer):
    result = analyzer.analyze()

    assert not result.detected
    assert result.count == 0


def test_indicator_properties(analyzer):
    result = analyzer.analyze(
        scheme="h3",
        alpn="h3",
    )

    assert result.count == 2
    assert result.types
    assert result.names


def test_indicator_value(analyzer):
    result = analyzer.analyze(
        scheme="h3"
    )

    indicator = result.indicators[0]

    assert indicator.value == "h3"


def test_frozen_indicator():
    indicator = HTTP3Indicator(
        type=HTTP3IndicatorType.HTTP3_SCHEME,
        name="HTTP/3",
        value="h3",
    )

    with pytest.raises(Exception):
        indicator.value = "h3-29"


def test_frozen_analysis(analyzer):
    result = analyzer.analyze(
        scheme="h3"
    )

    with pytest.raises(Exception):
        result.detected = False


def test_invalid_scheme(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            scheme=3
        )


def test_invalid_alpn(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            alpn=3
        )


def test_invalid_protocol(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            protocol=3
        )


def test_invalid_pseudo_headers(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            pseudo_headers=":method"
        )


def test_invalid_pseudo_header_entry(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            pseudo_headers=[":method", 3]
        )


def test_invalid_downgrade(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            downgrade=1
        )


def test_invalid_fallback(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            fallback=1
        )
