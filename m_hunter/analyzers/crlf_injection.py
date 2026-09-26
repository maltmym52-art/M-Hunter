from dataclasses import dataclass
from enum import Enum
from urllib.parse import unquote


class CRLFInjectionIndicatorType(str, Enum):
    CRLF = "crlf"
    CRLF_ENCODED = "crlf_encoded"
    LF_INJECTION = "lf_injection"
    CR_INJECTION = "cr_injection"
    HEADER_INJECTION = "header_injection"
    LOCATION_HEADER = "location_header"
    SET_COOKIE_HEADER = "set_cookie_header"
    RESPONSE_HEADER = "response_header"


@dataclass(frozen=True)
class CRLFInjectionIndicator:
    type: CRLFInjectionIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class CRLFInjectionAnalysis:
    detected: bool
    count: int
    types: tuple[CRLFInjectionIndicatorType, ...]
    names: tuple[str, ...]
    indicators: tuple[CRLFInjectionIndicator, ...]

    def has_type(self, indicator_type: CRLFInjectionIndicatorType) -> bool:
        return indicator_type in self.types


class CRLFInjectionAnalyzer:
    """Detects CRLF/header-injection indicators without executing payloads."""

    CRLF_MARKERS = ("\r\n", "\n\r")
    LF_MARKERS = ("\n",)
    CR_MARKERS = ("\r",)

    HEADER_NAMES = {
        "location",
        "set-cookie",
        "content-type",
        "content-disposition",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-original-url",
        "x-rewrite-url",
    }

    def _value_indicators(
        self,
        value: str,
        name: str | None = None,
    ) -> list[CRLFInjectionIndicator]:
        indicators: list[CRLFInjectionIndicator] = []

        decoded = unquote(value)

        if any(marker in value for marker in self.CRLF_MARKERS):
            indicators.append(
                CRLFInjectionIndicator(
                    CRLFInjectionIndicatorType.CRLF,
                    "Raw CRLF sequence detected.",
                    name,
                    value,
                )
            )

        if "%0d" in value.lower() or "%0a" in value.lower():
            indicators.append(
                CRLFInjectionIndicator(
                    CRLFInjectionIndicatorType.CRLF_ENCODED,
                    "Encoded CR/LF sequence detected.",
                    name,
                    value,
                )
            )

        if any(marker in decoded for marker in self.CRLF_MARKERS):
            indicators.append(
                CRLFInjectionIndicator(
                    CRLFInjectionIndicatorType.CRLF,
                    "Decoded CRLF sequence detected.",
                    name,
                    value,
                )
            )

        if "\n" in decoded and "\r\n" not in decoded:
            indicators.append(
                CRLFInjectionIndicator(
                    CRLFInjectionIndicatorType.LF_INJECTION,
                    "Decoded LF character detected.",
                    name,
                    value,
                )
            )

        if "\r" in decoded and "\r\n" not in decoded:
            indicators.append(
                CRLFInjectionIndicator(
                    CRLFInjectionIndicatorType.CR_INJECTION,
                    "Decoded CR character detected.",
                    name,
                    value,
                )
            )

        return indicators

    def analyze(
        self,
        *,
        url: str | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        response_headers: dict[str, str] | None = None,
        location: str | None = None,
        set_cookie: str | None = None,
    ) -> CRLFInjectionAnalysis:
        for value, field_name in (
            (url, "url"),
            (location, "location"),
            (set_cookie, "set_cookie"),
        ):
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string or None")

        for mapping, field_name in (
            (params, "params"),
            (headers, "headers"),
            (response_headers, "response_headers"),
        ):
            if mapping is not None and not isinstance(mapping, dict):
                raise TypeError(f"{field_name} must be a dictionary or None")

        indicators: list[CRLFInjectionIndicator] = []

        if url is not None:
            indicators.extend(self._value_indicators(url, "url"))

        if params:
            for name, value in params.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise TypeError("params must contain string names and values")
                indicators.extend(self._value_indicators(value, name))

        if headers:
            for name, value in headers.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise TypeError(
                        "headers must contain string names and values"
                    )

                indicators.extend(self._value_indicators(value, name))

                if name.lower() in self.HEADER_NAMES:
                    indicators.append(
                        CRLFInjectionIndicator(
                            CRLFInjectionIndicatorType.HEADER_INJECTION,
                            f"Potentially injectable HTTP header: {name}.",
                            name,
                            value,
                        )
                    )

        if location is not None:
            indicators.extend(self._value_indicators(location, "location"))
            indicators.append(
                CRLFInjectionIndicator(
                    CRLFInjectionIndicatorType.LOCATION_HEADER,
                    "Location header value supplied for analysis.",
                    "Location",
                    location,
                )
            )

        if set_cookie is not None:
            indicators.extend(self._value_indicators(set_cookie, "set-cookie"))
            indicators.append(
                CRLFInjectionIndicator(
                    CRLFInjectionIndicatorType.SET_COOKIE_HEADER,
                    "Set-Cookie header value supplied for analysis.",
                    "Set-Cookie",
                    set_cookie,
                )
            )

        if response_headers:
            for name, value in response_headers.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise TypeError(
                        "response_headers must contain string names and values"
                    )

                indicators.extend(self._value_indicators(value, name))

                lowered = name.lower()

                if lowered == "location":
                    indicators.append(
                        CRLFInjectionIndicator(
                            CRLFInjectionIndicatorType.LOCATION_HEADER,
                            "Location response header detected.",
                            name,
                            value,
                        )
                    )

                elif lowered == "set-cookie":
                    indicators.append(
                        CRLFInjectionIndicator(
                            CRLFInjectionIndicatorType.SET_COOKIE_HEADER,
                            "Set-Cookie response header detected.",
                            name,
                            value,
                        )
                    )

                else:
                    indicators.append(
                        CRLFInjectionIndicator(
                            CRLFInjectionIndicatorType.RESPONSE_HEADER,
                            f"Response header detected: {name}.",
                            name,
                            value,
                        )
                    )

        unique_types: list[CRLFInjectionIndicatorType] = []
        names: list[str] = []

        for indicator in indicators:
            if indicator.type not in unique_types:
                unique_types.append(indicator.type)

            if indicator.name is not None and indicator.name not in names:
                names.append(indicator.name)

        return CRLFInjectionAnalysis(
            detected=bool(indicators),
            count=len(indicators),
            types=tuple(unique_types),
            names=tuple(names),
            indicators=tuple(indicators),
        )
