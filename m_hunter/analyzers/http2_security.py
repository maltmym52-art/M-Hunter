from dataclasses import dataclass
from enum import Enum
from typing import Any


class HTTP2SecurityIndicatorType(str, Enum):
    HTTP2_SCHEME = "http2_scheme"
    HTTP2_ALPN = "http2_alpn"
    HTTP2_PROTOCOL = "http2_protocol"
    AUTHORITY_HEADER = "authority_header"
    PSEUDO_HEADER = "pseudo_header"
    DUPLICATE_PSEUDO_HEADER = "duplicate_pseudo_header"
    INVALID_PSEUDO_HEADER_ORDER = "invalid_pseudo_header_order"
    HTTP2_ERROR = "http2_error"
    STREAM_ERROR = "stream_error"
    GOAWAY_ERROR = "goaway_error"
    SETTINGS_EXPOSURE = "settings_exposure"
    H2C_UPGRADE = "h2c_upgrade"
    PRIOR_KNOWLEDGE = "prior_knowledge"


@dataclass(frozen=True)
class HTTP2SecurityIndicator:
    type: HTTP2SecurityIndicatorType
    evidence: str
    name: str
    value: Any = None


@dataclass
class HTTP2SecurityAnalysis:
    detected: bool
    count: int
    types: list[HTTP2SecurityIndicatorType]
    names: list[str]
    indicators: list[HTTP2SecurityIndicator]

    def has_type(self, indicator_type: HTTP2SecurityIndicatorType) -> bool:
        return indicator_type in self.types


class HTTP2SecurityAnalyzer:
    name = "http2_security"
    description = "Detect HTTP/2 security-relevant protocol indicators"

    _ERROR_MARKERS = (
        "http/2 protocol error",
        "http2 protocol error",
        "protocol_error",
        "stream error",
        "stream_error",
        "goaway",
        "enhance_your_calm",
        "http_1_1_required",
    )

    def analyze(
        self,
        url: str = "",
        *,
        protocol: str | None = None,
        alpn: str | None = None,
        headers: dict[str, str] | None = None,
        response_text: str = "",
        settings: dict[str, Any] | None = None,
        pseudo_headers: list[str] | None = None,
        h2c_upgrade: bool = False,
        prior_knowledge: bool = False,
    ) -> HTTP2SecurityAnalysis:
        indicators: list[HTTP2SecurityIndicator] = []

        headers = headers or {}
        pseudo_headers = pseudo_headers or []

        def add(
            indicator_type: HTTP2SecurityIndicatorType,
            evidence: str,
            name: str,
            value: Any = None,
        ) -> None:
            indicators.append(
                HTTP2SecurityIndicator(
                    type=indicator_type,
                    evidence=evidence,
                    name=name,
                    value=value,
                )
            )

        if url.lower().startswith(("h2://", "h2c://")):
            add(
                HTTP2SecurityIndicatorType.HTTP2_SCHEME,
                "HTTP/2-specific URL scheme detected.",
                "url",
                url,
            )

        if protocol and protocol.lower() in {
            "h2",
            "h2c",
            "http/2",
            "http2",
        }:
            add(
                HTTP2SecurityIndicatorType.HTTP2_PROTOCOL,
                "HTTP/2 protocol identifier detected.",
                "protocol",
                protocol,
            )

        if alpn and alpn.lower() in {"h2", "h2c"}:
            add(
                HTTP2SecurityIndicatorType.HTTP2_ALPN,
                "HTTP/2 ALPN identifier detected.",
                "alpn",
                alpn,
            )

        for name, value in headers.items():
            lower_name = name.lower()

            if lower_name == ":authority":
                add(
                    HTTP2SecurityIndicatorType.AUTHORITY_HEADER,
                    "HTTP/2 :authority pseudo-header detected.",
                    name,
                    value,
                )

            if lower_name.startswith(":"):
                add(
                    HTTP2SecurityIndicatorType.PSEUDO_HEADER,
                    "HTTP/2 pseudo-header detected.",
                    name,
                    value,
                )

            if lower_name == "upgrade" and value.lower().strip() == "h2c":
                add(
                    HTTP2SecurityIndicatorType.H2C_UPGRADE,
                    "HTTP/1.1 to cleartext HTTP/2 upgrade indicator detected.",
                    name,
                    value,
                )

        seen_pseudo: set[str] = set()
        for name in pseudo_headers:
            if name in seen_pseudo:
                add(
                    HTTP2SecurityIndicatorType.DUPLICATE_PSEUDO_HEADER,
                    "Duplicate HTTP/2 pseudo-header detected.",
                    name,
                    name,
                )
            seen_pseudo.add(name)

        if pseudo_headers:
            regular_seen = False
            for name in pseudo_headers:
                if not name.startswith(":"):
                    regular_seen = True
                    continue

                if regular_seen:
                    add(
                        HTTP2SecurityIndicatorType.INVALID_PSEUDO_HEADER_ORDER,
                        "HTTP/2 pseudo-header appears after a regular header.",
                        name,
                        name,
                    )

        if settings:
            add(
                HTTP2SecurityIndicatorType.SETTINGS_EXPOSURE,
                "HTTP/2 SETTINGS information is present.",
                "settings",
                settings,
            )

        if h2c_upgrade:
            add(
                HTTP2SecurityIndicatorType.H2C_UPGRADE,
                "Explicit h2c upgrade context detected.",
                "h2c_upgrade",
                True,
            )

        if prior_knowledge:
            add(
                HTTP2SecurityIndicatorType.PRIOR_KNOWLEDGE,
                "HTTP/2 prior-knowledge connection context detected.",
                "prior_knowledge",
                True,
            )

        text = response_text.lower()
        for marker in self._ERROR_MARKERS:
            if marker in text:
                if "goaway" in marker or "enhance_your_calm" in marker:
                    indicator_type = HTTP2SecurityIndicatorType.GOAWAY_ERROR
                elif "stream" in marker:
                    indicator_type = HTTP2SecurityIndicatorType.STREAM_ERROR
                else:
                    indicator_type = HTTP2SecurityIndicatorType.HTTP2_ERROR

                add(
                    indicator_type,
                    f"HTTP/2 error marker detected: {marker}.",
                    "response",
                    marker,
                )

        types = [indicator.type for indicator in indicators]
        names = [indicator.name for indicator in indicators]

        return HTTP2SecurityAnalysis(
            detected=bool(indicators),
            count=len(indicators),
            types=types,
            names=names,
            indicators=indicators,
        )
