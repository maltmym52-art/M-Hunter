from dataclasses import dataclass
from enum import Enum


class WebSocketSecurityIndicatorType(str, Enum):
    WEBSOCKET_SCHEME = "websocket_scheme"
    UPGRADE_HEADER = "upgrade_header"
    CONNECTION_UPGRADE = "connection_upgrade"
    ORIGIN_HEADER = "origin_header"
    MISSING_ORIGIN = "missing_origin"
    CORS_LIKE_ORIGIN = "cors_like_origin"
    SUBPROTOCOL = "subprotocol"
    AUTHENTICATION_CONTEXT = "authentication_context"
    SESSION_CONTEXT = "session_context"
    SENSITIVE_PATH = "sensitive_path"
    WEBSOCKET_ERROR = "websocket_error"


@dataclass(frozen=True)
class WebSocketSecurityIndicator:
    type: WebSocketSecurityIndicatorType
    evidence: str
    name: str
    value: str


@dataclass
class WebSocketSecurityAnalysis:
    detected: bool
    count: int
    types: list[WebSocketSecurityIndicatorType]
    names: list[str]
    indicators: list[WebSocketSecurityIndicator]

    def has_type(
        self,
        indicator_type: WebSocketSecurityIndicatorType,
    ) -> bool:
        return indicator_type in self.types


class WebSocketSecurityAnalyzer:
    name = "websocket_security"
    description = (
        "Detects indicators associated with WebSocket security."
    )

    _SENSITIVE_PATH_MARKERS = {
        "admin",
        "account",
        "profile",
        "dashboard",
        "billing",
        "payment",
        "orders",
        "private",
        "internal",
        "user",
        "users",
        "session",
        "auth",
    }

    _WEBSOCKET_ERROR_MARKERS = {
        "websocket error",
        "websocket handshake",
        "upgrade required",
        "invalid websocket",
        "origin not allowed",
        "origin rejected",
        "handshake failed",
    }

    def analyze(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        response_headers: dict[str, str] | None = None,
        response_text: str = "",
        authenticated: bool = False,
        session_present: bool = False,
        subprotocol: str | None = None,
    ) -> WebSocketSecurityAnalysis:
        indicators: list[WebSocketSecurityIndicator] = []

        request_headers = self._normalize_headers(headers or {})
        returned_headers = self._normalize_headers(
            response_headers or {}
        )

        lowered_url = url.lower()

        if lowered_url.startswith("ws://") or lowered_url.startswith(
            "wss://"
        ):
            indicators.append(
                WebSocketSecurityIndicator(
                    type=WebSocketSecurityIndicatorType.WEBSOCKET_SCHEME,
                    evidence="WebSocket URL scheme detected.",
                    name="url",
                    value=url,
                )
            )

        if request_headers.get("upgrade", "").lower() == "websocket":
            indicators.append(
                WebSocketSecurityIndicator(
                    type=WebSocketSecurityIndicatorType.UPGRADE_HEADER,
                    evidence="WebSocket Upgrade header detected.",
                    name="upgrade",
                    value=request_headers["upgrade"],
                )
            )

        connection = request_headers.get("connection", "").lower()
        if "upgrade" in connection:
            indicators.append(
                WebSocketSecurityIndicator(
                    type=(
                        WebSocketSecurityIndicatorType.CONNECTION_UPGRADE
                    ),
                    evidence="Connection: Upgrade context detected.",
                    name="connection",
                    value=request_headers["connection"],
                )
            )

        origin = request_headers.get("origin")
        if origin:
            indicators.append(
                WebSocketSecurityIndicator(
                    type=WebSocketSecurityIndicatorType.ORIGIN_HEADER,
                    evidence="WebSocket Origin header detected.",
                    name="origin",
                    value=origin,
                )
            )

            if origin == "*" or origin.lower() == "null":
                indicators.append(
                    WebSocketSecurityIndicator(
                        type=(
                            WebSocketSecurityIndicatorType.CORS_LIKE_ORIGIN
                        ),
                        evidence=(
                            "Broad or null Origin value detected in "
                            "WebSocket context."
                        ),
                        name="origin",
                        value=origin,
                    )
                )
        elif (
            request_headers.get("upgrade", "").lower() == "websocket"
            or lowered_url.startswith("ws://")
            or lowered_url.startswith("wss://")
        ):
            indicators.append(
                WebSocketSecurityIndicator(
                    type=WebSocketSecurityIndicatorType.MISSING_ORIGIN,
                    evidence=(
                        "WebSocket context detected without an Origin "
                        "header."
                    ),
                    name="origin",
                    value="missing",
                )
            )

        protocol = (
            subprotocol
            or request_headers.get("sec-websocket-protocol")
            or returned_headers.get("sec-websocket-protocol")
        )

        if protocol:
            indicators.append(
                WebSocketSecurityIndicator(
                    type=WebSocketSecurityIndicatorType.SUBPROTOCOL,
                    evidence="WebSocket subprotocol detected.",
                    name="sec-websocket-protocol",
                    value=protocol,
                )
            )

        authorization = request_headers.get("authorization")
        if authorization or authenticated:
            indicators.append(
                WebSocketSecurityIndicator(
                    type=(
                        WebSocketSecurityIndicatorType.AUTHENTICATION_CONTEXT
                    ),
                    evidence="Authentication context detected.",
                    name="authorization",
                    value=(
                        authorization
                        if authorization
                        else "authenticated"
                    ),
                )
            )

        if session_present or "cookie" in request_headers:
            indicators.append(
                WebSocketSecurityIndicator(
                    type=WebSocketSecurityIndicatorType.SESSION_CONTEXT,
                    evidence="Session context detected.",
                    name="cookie",
                    value=(
                        request_headers.get("cookie", "present")
                    ),
                )
            )

        if any(
            marker in lowered_url
            for marker in self._SENSITIVE_PATH_MARKERS
        ):
            indicators.append(
                WebSocketSecurityIndicator(
                    type=WebSocketSecurityIndicatorType.SENSITIVE_PATH,
                    evidence=(
                        "Potentially sensitive WebSocket path detected."
                    ),
                    name="url",
                    value=url,
                )
            )

        lowered_response = response_text.lower()
        for marker in self._WEBSOCKET_ERROR_MARKERS:
            if marker in lowered_response:
                indicators.append(
                    WebSocketSecurityIndicator(
                        type=WebSocketSecurityIndicatorType.WEBSOCKET_ERROR,
                        evidence=(
                            f"WebSocket-related response marker "
                            f"detected: {marker}."
                        ),
                        name="response",
                        value=marker,
                    )
                )

        types = list(dict.fromkeys(
            indicator.type for indicator in indicators
        ))
        names = list(dict.fromkeys(
            indicator.name for indicator in indicators
        ))

        return WebSocketSecurityAnalysis(
            detected=bool(indicators),
            count=len(indicators),
            types=types,
            names=names,
            indicators=indicators,
        )

    @staticmethod
    def _normalize_headers(
        headers: dict[str, str],
    ) -> dict[str, str]:
        return {
            str(name).lower(): str(value)
            for name, value in headers.items()
        }
