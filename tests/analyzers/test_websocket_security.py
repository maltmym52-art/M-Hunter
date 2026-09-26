from m_hunter.analyzers.websocket_security import (
    WebSocketSecurityAnalyzer,
    WebSocketSecurityIndicatorType,
)


def analyzer():
    return WebSocketSecurityAnalyzer()


def test_clean_request():
    result = analyzer().analyze(
        "https://example.com",
        headers={"accept": "text/html"},
    )

    assert result.detected is False
    assert result.count == 0


def test_ws_scheme():
    result = analyzer().analyze("ws://example.com/socket")

    assert result.has_type(
        WebSocketSecurityIndicatorType.WEBSOCKET_SCHEME
    )


def test_wss_scheme():
    result = analyzer().analyze("wss://example.com/socket")

    assert result.has_type(
        WebSocketSecurityIndicatorType.WEBSOCKET_SCHEME
    )


def test_upgrade_header():
    result = analyzer().analyze(
        "https://example.com/socket",
        headers={"Upgrade": "websocket"},
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.UPGRADE_HEADER
    )


def test_connection_upgrade():
    result = analyzer().analyze(
        "https://example.com/socket",
        headers={"Connection": "keep-alive, Upgrade"},
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.CONNECTION_UPGRADE
    )


def test_origin_header():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "https://app.example.com"},
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.ORIGIN_HEADER
    )


def test_wildcard_origin():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "*"},
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.CORS_LIKE_ORIGIN
    )


def test_null_origin():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "null"},
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.CORS_LIKE_ORIGIN
    )


def test_missing_origin_with_upgrade():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Upgrade": "websocket"},
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.MISSING_ORIGIN
    )


def test_missing_origin_with_ws_scheme():
    result = analyzer().analyze(
        "ws://example.com/socket",
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.MISSING_ORIGIN
    )


def test_subprotocol():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={
            "Sec-WebSocket-Protocol": "chat",
        },
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.SUBPROTOCOL
    )


def test_explicit_subprotocol_argument():
    result = analyzer().analyze(
        "wss://example.com/socket",
        subprotocol="graphql-transport-ws",
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.SUBPROTOCOL
    )


def test_authorization_context():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={
            "Authorization": "Bearer token",
        },
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.AUTHENTICATION_CONTEXT
    )


def test_authenticated_context():
    result = analyzer().analyze(
        "wss://example.com/socket",
        authenticated=True,
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.AUTHENTICATION_CONTEXT
    )


def test_session_context():
    result = analyzer().analyze(
        "wss://example.com/socket",
        session_present=True,
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.SESSION_CONTEXT
    )


def test_cookie_session_context():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Cookie": "session=abc"},
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.SESSION_CONTEXT
    )


def test_sensitive_path():
    result = analyzer().analyze(
        "wss://example.com/admin/socket",
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.SENSITIVE_PATH
    )


def test_websocket_error():
    result = analyzer().analyze(
        "wss://example.com/socket",
        response_text="WebSocket handshake failed",
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.WEBSOCKET_ERROR
    )


def test_multiple_indicators():
    result = analyzer().analyze(
        "wss://example.com/admin/socket",
        headers={
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Origin": "*",
            "Authorization": "Bearer token",
            "Cookie": "session=abc",
            "Sec-WebSocket-Protocol": "chat",
        },
        response_text="WebSocket handshake failed",
    )

    assert result.detected
    assert result.count >= 8
    assert len(result.types) >= 8


def test_has_type_false():
    result = analyzer().analyze(
        "https://example.com",
        headers={"accept": "text/html"},
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.UPGRADE_HEADER
    ) is False


def test_indicator_metadata():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "*"},
    )

    indicator = result.indicators[-1]

    assert indicator.name == "origin"
    assert indicator.value == "*"
    assert indicator.type == (
        WebSocketSecurityIndicatorType.CORS_LIKE_ORIGIN
    )
    assert indicator.evidence


def test_types_are_unique():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={
            "Upgrade": "websocket",
            "Connection": "Upgrade",
        },
    )

    assert len(result.types) == len(set(result.types))


def test_names_are_unique():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "*"},
    )

    assert len(result.names) == len(set(result.names))


def test_header_names_are_case_insensitive():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={"uPgRaDe": "websocket"},
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.UPGRADE_HEADER
    )


def test_response_subprotocol():
    result = analyzer().analyze(
        "wss://example.com/socket",
        response_headers={
            "Sec-WebSocket-Protocol": "chat",
        },
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.SUBPROTOCOL
    )


def test_response_error_case_insensitive():
    result = analyzer().analyze(
        "wss://example.com/socket",
        response_text="ORIGIN NOT ALLOWED",
    )

    assert result.has_type(
        WebSocketSecurityIndicatorType.WEBSOCKET_ERROR
    )


def test_indicator_count_matches_list():
    result = analyzer().analyze(
        "wss://example.com/socket",
        headers={
            "Upgrade": "websocket",
            "Origin": "*",
        },
    )

    assert result.count == len(result.indicators)
