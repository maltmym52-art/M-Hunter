from m_hunter.analyzers.http2_security import (
    HTTP2SecurityAnalyzer,
    HTTP2SecurityIndicatorType,
)


def analyzer():
    return HTTP2SecurityAnalyzer()


def test_clean_input():
    result = analyzer().analyze("https://example.com")

    assert result.detected is False
    assert result.count == 0
    assert result.indicators == []


def test_h2_scheme():
    result = analyzer().analyze("h2://example.com")

    assert result.detected is True
    assert result.has_type(
        HTTP2SecurityIndicatorType.HTTP2_SCHEME
    )


def test_h2c_scheme():
    result = analyzer().analyze("h2c://example.com")

    assert result.has_type(
        HTTP2SecurityIndicatorType.HTTP2_SCHEME
    )


def test_h2_protocol():
    result = analyzer().analyze(
        "https://example.com",
        protocol="h2",
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )


def test_http2_protocol_name():
    result = analyzer().analyze(
        "https://example.com",
        protocol="HTTP/2",
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )


def test_alpn_h2():
    result = analyzer().analyze(
        "https://example.com",
        alpn="h2",
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.HTTP2_ALPN
    )


def test_alpn_h2c():
    result = analyzer().analyze(
        "https://example.com",
        alpn="h2c",
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.HTTP2_ALPN
    )


def test_authority_header():
    result = analyzer().analyze(
        "https://example.com",
        headers={":authority": "example.com"},
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.AUTHORITY_HEADER
    )


def test_pseudo_header():
    result = analyzer().analyze(
        "https://example.com",
        headers={":method": "GET"},
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.PSEUDO_HEADER
    )


def test_h2c_header_upgrade():
    result = analyzer().analyze(
        "https://example.com",
        headers={"Upgrade": "h2c"},
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.H2C_UPGRADE
    )


def test_duplicate_pseudo_header():
    result = analyzer().analyze(
        "https://example.com",
        pseudo_headers=[
            ":method",
            ":path",
            ":method",
        ],
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.DUPLICATE_PSEUDO_HEADER
    )


def test_pseudo_header_order():
    result = analyzer().analyze(
        "https://example.com",
        pseudo_headers=[
            ":method",
            "x-test",
            ":path",
        ],
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.INVALID_PSEUDO_HEADER_ORDER
    )


def test_valid_pseudo_header_order():
    result = analyzer().analyze(
        "https://example.com",
        pseudo_headers=[
            ":method",
            ":path",
            "x-test",
        ],
    )

    assert not result.has_type(
        HTTP2SecurityIndicatorType.INVALID_PSEUDO_HEADER_ORDER
    )


def test_settings_exposure():
    result = analyzer().analyze(
        "https://example.com",
        settings={"max_concurrent_streams": 100},
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.SETTINGS_EXPOSURE
    )


def test_explicit_h2c_upgrade_context():
    result = analyzer().analyze(
        "https://example.com",
        h2c_upgrade=True,
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.H2C_UPGRADE
    )


def test_prior_knowledge():
    result = analyzer().analyze(
        "https://example.com",
        prior_knowledge=True,
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.PRIOR_KNOWLEDGE
    )


def test_protocol_error():
    result = analyzer().analyze(
        "https://example.com",
        response_text="HTTP/2 protocol error",
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.HTTP2_ERROR
    )


def test_stream_error():
    result = analyzer().analyze(
        "https://example.com",
        response_text="stream error",
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.STREAM_ERROR
    )


def test_goaway_error():
    result = analyzer().analyze(
        "https://example.com",
        response_text="GOAWAY received",
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.GOAWAY_ERROR
    )


def test_error_case_insensitive():
    result = analyzer().analyze(
        "https://example.com",
        response_text="HTTP2 PROTOCOL ERROR",
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.HTTP2_ERROR
    )


def test_multiple_indicators():
    result = analyzer().analyze(
        "h2://example.com",
        protocol="h2",
        alpn="h2",
        headers={
            ":authority": "example.com",
            "Upgrade": "h2c",
        },
        settings={"max_frame_size": 16384},
        prior_knowledge=True,
    )

    assert result.detected is True
    assert result.count >= 5
    assert len(result.types) == result.count
    assert len(result.names) == result.count


def test_indicator_fields():
    result = analyzer().analyze(
        "https://example.com",
        protocol="h2",
    )

    indicator = result.indicators[0]

    assert indicator.type == HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    assert indicator.name == "protocol"
    assert indicator.value == "h2"
    assert indicator.evidence


def test_has_type_false():
    result = analyzer().analyze("https://example.com")

    assert result.has_type(
        HTTP2SecurityIndicatorType.HTTP2_ERROR
    ) is False


def test_analysis_count_matches_indicators():
    result = analyzer().analyze(
        "h2://example.com",
        protocol="h2",
        alpn="h2",
    )

    assert result.count == len(result.indicators)


def test_h2c_upgrade_header_is_case_insensitive():
    result = analyzer().analyze(
        "https://example.com",
        headers={"upgrade": "H2C"},
    )

    assert result.has_type(
        HTTP2SecurityIndicatorType.H2C_UPGRADE
    )


def test_non_h2_upgrade_not_detected_as_h2c():
    result = analyzer().analyze(
        "https://example.com",
        headers={"Upgrade": "websocket"},
    )

    assert not result.has_type(
        HTTP2SecurityIndicatorType.H2C_UPGRADE
    )
