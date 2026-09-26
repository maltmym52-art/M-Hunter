from dataclasses import dataclass
from enum import Enum
from typing import Any

from m_hunter.core.response import HttpResponse


class CachePoisoningIndicatorType(str, Enum):
    CACHE_HEADER = "cache_header"
    CACHE_STATUS = "cache_status"
    CACHE_CONTROL = "cache_control"
    VARY_HEADER = "vary_header"
    CACHE_KEY_INDICATOR = "cache_key_indicator"
    UNKEYED_INPUT = "unkeyed_input"
    RESPONSE_VARIATION = "response_variation"
    AGE_HEADER = "age_header"
    ETAG_HEADER = "etag_header"


@dataclass(frozen=True)
class CachePoisoningIndicator:
    type: CachePoisoningIndicatorType
    evidence: str
    name: str
    value: str


@dataclass
class CachePoisoningAnalysis:
    detected: bool
    count: int
    types: list[str]
    names: list[str]
    indicators: list[CachePoisoningIndicator]

    def has_type(self, indicator_type: CachePoisoningIndicatorType) -> bool:
        return indicator_type.value in self.types


class CachePoisoningAnalyzer:
    CACHE_HEADERS = {
        "x-cache",
        "x-cache-hits",
        "x-cache-status",
        "cf-cache-status",
        "x-proxy-cache",
        "x-cache-lookup",
    }

    CACHE_CONTROL_HEADERS = {
        "cache-control",
        "surrogate-control",
        "cdn-cache-control",
    }

    CACHE_METADATA_HEADERS = {
        "age": CachePoisoningIndicatorType.AGE_HEADER,
        "etag": CachePoisoningIndicatorType.ETAG_HEADER,
        "vary": CachePoisoningIndicatorType.VARY_HEADER,
    }

    CACHE_KEY_HEADERS = {
        "vary",
        "cache-control",
        "surrogate-control",
        "cdn-cache-control",
    }

    def analyze(
        self,
        response: HttpResponse | None = None,
        *,
        headers: dict[str, str] | None = None,
        response_body: str | None = None,
        baseline_body: str | None = None,
        candidate_body: str | None = None,
        baseline_headers: dict[str, str] | None = None,
        candidate_headers: dict[str, str] | None = None,
    ) -> CachePoisoningAnalysis:
        indicators: list[CachePoisoningIndicator] = []

        if response is not None:
            headers = response.headers
            response_body = response.text

        headers = headers or {}

        normalized_headers = {
            str(name).lower(): str(value)
            for name, value in headers.items()
        }

        for name, value in normalized_headers.items():
            if name in self.CACHE_HEADERS:
                indicators.append(
                    CachePoisoningIndicator(
                        CachePoisoningIndicatorType.CACHE_STATUS,
                        f"{name}: {value}",
                        name,
                        value,
                    )
                )

            elif name in self.CACHE_CONTROL_HEADERS:
                indicators.append(
                    CachePoisoningIndicator(
                        CachePoisoningIndicatorType.CACHE_CONTROL,
                        f"{name}: {value}",
                        name,
                        value,
                    )
                )

            elif name in self.CACHE_METADATA_HEADERS:
                indicator_type = self.CACHE_METADATA_HEADERS[name]
                indicators.append(
                    CachePoisoningIndicator(
                        indicator_type,
                        f"{name}: {value}",
                        name,
                        value,
                    )
                )

        vary_value = normalized_headers.get("vary")
        if vary_value:
            indicators.append(
                CachePoisoningIndicator(
                    CachePoisoningIndicatorType.CACHE_KEY_INDICATOR,
                    f"Vary header defines cache variation: {vary_value}",
                    "vary",
                    vary_value,
                )
            )

        if candidate_body is not None and baseline_body is not None:
            if candidate_body != baseline_body:
                indicators.append(
                    CachePoisoningIndicator(
                        CachePoisoningIndicatorType.RESPONSE_VARIATION,
                        "Candidate response body differs from baseline response body",
                        "response_body",
                        candidate_body[:500],
                    )
                )

        if (
            baseline_headers is not None
            and candidate_headers is not None
        ):
            normalized_baseline = {
                str(name).lower(): str(value)
                for name, value in baseline_headers.items()
            }
            normalized_candidate = {
                str(name).lower(): str(value)
                for name, value in candidate_headers.items()
            }

            if normalized_baseline != normalized_candidate:
                indicators.append(
                    CachePoisoningIndicator(
                        CachePoisoningIndicatorType.RESPONSE_VARIATION,
                        "Candidate response headers differ from baseline response headers",
                        "response_headers",
                        str(normalized_candidate),
                    )
                )

        if response_body:
            body_lower = response_body.lower()

            unkeyed_markers = (
                "x-forwarded-host",
                "x-forwarded-proto",
                "x-original-url",
                "x-rewrite-url",
            )

            for marker in unkeyed_markers:
                if marker in body_lower:
                    indicators.append(
                        CachePoisoningIndicator(
                            CachePoisoningIndicatorType.UNKEYED_INPUT,
                            f"Response body references cache-sensitive input marker: {marker}",
                            marker,
                            marker,
                        )
                    )

        unique_indicators: list[CachePoisoningIndicator] = []
        seen: set[tuple[str, str, str]] = set()

        for indicator in indicators:
            key = (
                indicator.type.value,
                indicator.name,
                indicator.value,
            )
            if key not in seen:
                seen.add(key)
                unique_indicators.append(indicator)

        types = list(dict.fromkeys(
            indicator.type.value
            for indicator in unique_indicators
        ))

        names = list(dict.fromkeys(
            indicator.name
            for indicator in unique_indicators
        ))

        return CachePoisoningAnalysis(
            detected=bool(unique_indicators),
            count=len(unique_indicators),
            types=types,
            names=names,
            indicators=unique_indicators,
        )
