from dataclasses import dataclass, field
from enum import Enum


class HTTP3IndicatorType(str, Enum):
    HTTP3_SCHEME = "http3_scheme"
    HTTP3_ALPN = "http3_alpn"
    HTTP3_PROTOCOL = "http3_protocol"
    QUIC_PROTOCOL = "quic_protocol"
    ALT_SVC_H3 = "alt_svc_h3"
    AUTHORITY_CONTEXT = "authority_context"
    PSEUDO_HEADER = "pseudo_header"
    QUIC_ERROR = "quic_error"
    HTTP3_ERROR = "http3_error"
    DOWNGRADE_INDICATOR = "downgrade_indicator"
    FALLBACK_INDICATOR = "fallback_indicator"
    MALFORMED_PROTOCOL = "malformed_protocol"


@dataclass(frozen=True)
class HTTP3Indicator:
    type: HTTP3IndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class HTTP3Analysis:
    detected: bool
    indicators: tuple[HTTP3Indicator, ...] = field(
        default_factory=tuple
    )

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[HTTP3IndicatorType, ...]:
        return tuple(
            indicator.type
            for indicator in self.indicators
        )

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(
            indicator.name
            for indicator in self.indicators
        )

    def has_type(
        self,
        indicator_type: HTTP3IndicatorType,
    ) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class HTTP3SecurityAnalyzer:
    name = "http3_security"
    description = (
        "Analyze HTTP/3 and QUIC security indicators"
    )

    def analyze(
        self,
        *,
        scheme: str | None = None,
        alpn: str | None = None,
        protocol: str | None = None,
        alt_svc: str | None = None,
        authority: str | None = None,
        pseudo_headers: list[str] | tuple[str, ...] | None = None,
        quic_error: str | None = None,
        http3_error: str | None = None,
        downgrade: bool = False,
        fallback: bool = False,
        malformed_protocol: str | None = None,
    ) -> HTTP3Analysis:
        indicators: list[HTTP3Indicator] = []

        if scheme is not None:
            if not isinstance(scheme, str):
                raise TypeError(
                    "scheme must be a string or None"
                )

            lowered = scheme.lower()

            if lowered == "https":
                pass
            elif lowered in {"h3", "http3"}:
                indicators.append(
                    HTTP3Indicator(
                        type=HTTP3IndicatorType.HTTP3_SCHEME,
                        name="HTTP/3 scheme detected",
                        value=scheme,
                    )
                )

        if alpn is not None:
            if not isinstance(alpn, str):
                raise TypeError(
                    "alpn must be a string or None"
                )

            tokens = {
                token.strip().lower()
                for token in alpn.split(",")
                if token.strip()
            }

            for token in tokens:
                if token.startswith("h3"):
                    indicators.append(
                        HTTP3Indicator(
                            type=HTTP3IndicatorType.HTTP3_ALPN,
                            name="HTTP/3 ALPN detected",
                            value=token,
                        )
                    )

        if protocol is not None:
            if not isinstance(protocol, str):
                raise TypeError(
                    "protocol must be a string or None"
                )

            lowered = protocol.lower()

            if "http/3" in lowered or "h3" in lowered:
                indicators.append(
                    HTTP3Indicator(
                        type=HTTP3IndicatorType.HTTP3_PROTOCOL,
                        name="HTTP/3 protocol detected",
                        value=protocol,
                    )
                )

            if "quic" in lowered:
                indicators.append(
                    HTTP3Indicator(
                        type=HTTP3IndicatorType.QUIC_PROTOCOL,
                        name="QUIC protocol detected",
                        value=protocol,
                    )
                )

        if alt_svc is not None:
            if not isinstance(alt_svc, str):
                raise TypeError(
                    "alt_svc must be a string or None"
                )

            if "h3" in alt_svc.lower():
                indicators.append(
                    HTTP3Indicator(
                        type=HTTP3IndicatorType.ALT_SVC_H3,
                        name="Alt-Svc advertises HTTP/3",
                        value=alt_svc,
                    )
                )

        if authority is not None:
            if not isinstance(authority, str):
                raise TypeError(
                    "authority must be a string or None"
                )

            indicators.append(
                HTTP3Indicator(
                    type=HTTP3IndicatorType.AUTHORITY_CONTEXT,
                    name="HTTP/3 authority context detected",
                    value=authority,
                )
            )

        if pseudo_headers is not None:
            if not isinstance(
                pseudo_headers,
                (list, tuple),
            ):
                raise TypeError(
                    "pseudo_headers must be a list or tuple"
                )

            for header in pseudo_headers:
                if not isinstance(header, str):
                    raise TypeError(
                        "pseudo_headers entries must be strings"
                    )

                if header.startswith(":"):
                    indicators.append(
                        HTTP3Indicator(
                            type=HTTP3IndicatorType.PSEUDO_HEADER,
                            name="HTTP/3 pseudo-header detected",
                            value=header,
                        )
                    )

        if quic_error is not None:
            if not isinstance(quic_error, str):
                raise TypeError(
                    "quic_error must be a string or None"
                )

            if quic_error.strip():
                indicators.append(
                    HTTP3Indicator(
                        type=HTTP3IndicatorType.QUIC_ERROR,
                        name="QUIC error detected",
                        value=quic_error,
                    )
                )

        if http3_error is not None:
            if not isinstance(http3_error, str):
                raise TypeError(
                    "http3_error must be a string or None"
                )

            if http3_error.strip():
                indicators.append(
                    HTTP3Indicator(
                        type=HTTP3IndicatorType.HTTP3_ERROR,
                        name="HTTP/3 error detected",
                        value=http3_error,
                    )
                )

        if not isinstance(downgrade, bool):
            raise TypeError(
                "downgrade must be a boolean"
            )

        if downgrade:
            indicators.append(
                HTTP3Indicator(
                    type=HTTP3IndicatorType.DOWNGRADE_INDICATOR,
                    name="HTTP/3 downgrade indicator detected",
                )
            )

        if not isinstance(fallback, bool):
            raise TypeError(
                "fallback must be a boolean"
            )

        if fallback:
            indicators.append(
                HTTP3Indicator(
                    type=HTTP3IndicatorType.FALLBACK_INDICATOR,
                    name="HTTP/3 fallback indicator detected",
                )
            )

        if malformed_protocol is not None:
            if not isinstance(malformed_protocol, str):
                raise TypeError(
                    "malformed_protocol must be a string or None"
                )

            if malformed_protocol.strip():
                indicators.append(
                    HTTP3Indicator(
                        type=HTTP3IndicatorType.MALFORMED_PROTOCOL,
                        name="Malformed HTTP/3 protocol indicator detected",
                        value=malformed_protocol,
                    )
                )

        return HTTP3Analysis(
            detected=bool(indicators),
            indicators=tuple(indicators),
        )
