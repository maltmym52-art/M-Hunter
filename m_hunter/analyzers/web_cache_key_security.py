from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qsl, urlsplit

from m_hunter.analyzers.base import BaseAnalyzer


class WebCacheKeyIndicatorType(str, Enum):
    CACHEABLE_RESPONSE = "cacheable_response"
    CACHE_KEY_QUERY_PARAMETER = "cache_key_query_parameter"
    UNKEYED_QUERY_PARAMETER = "unkeyed_query_parameter"
    SENSITIVE_QUERY_PARAMETER = "sensitive_query_parameter"
    DUPLICATE_QUERY_PARAMETER = "duplicate_query_parameter"
    FRAGMENT_PRESENT = "fragment_present"
    COOKIE_PRESENT = "cookie_present"
    AUTHORIZATION_PRESENT = "authorization_present"
    CACHE_CONTROL_PRIVATE = "cache_control_private"
    CACHE_CONTROL_NO_STORE = "cache_control_no_store"
    CACHE_CONTROL_NO_CACHE = "cache_control_no_cache"
    VARY_PRESENT = "vary_present"
    VARY_MISSING = "vary_missing"


@dataclass(frozen=True)
class WebCacheKeyIndicator:
    type: WebCacheKeyIndicatorType
    value: str = ""


@dataclass(frozen=True)
class WebCacheKeyAnalysis:
    indicators: tuple[WebCacheKeyIndicator, ...]

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[WebCacheKeyIndicatorType, ...]:
        return tuple(indicator.type for indicator in self.indicators)

    def has_type(self, indicator_type: WebCacheKeyIndicatorType) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class WebCacheKeySecurityAnalyzer(BaseAnalyzer):
    name = "web_cache_key_security"
    description = "Analyze cache-key and cache-related request/response signals."

    SENSITIVE_PARAMETERS = {
        "token",
        "access_token",
        "auth",
        "authorization",
        "api_key",
        "apikey",
        "password",
        "passwd",
        "secret",
        "session",
        "sessionid",
        "sid",
        "code",
        "state",
    }

    def analyze(
        self,
        response,
        *,
        request_url: str | None = None,
        cacheable: bool = False,
        cache_key_parameters: set[str] | None = None,
        unkeyed_parameters: set[str] | None = None,
        vary_header: str | None = None,
        cookie_present: bool = False,
        authorization_present: bool = False,
    ) -> WebCacheKeyAnalysis:
        indicators: list[WebCacheKeyIndicator] = []

        if cacheable:
            indicators.append(
                WebCacheKeyIndicator(
                    WebCacheKeyIndicatorType.CACHEABLE_RESPONSE
                )
            )

        cache_key_parameters = cache_key_parameters or set()
        unkeyed_parameters = unkeyed_parameters or set()

        if request_url:
            parsed = urlsplit(request_url)
            query = parse_qsl(parsed.query, keep_blank_values=True)

            if parsed.fragment:
                indicators.append(
                    WebCacheKeyIndicator(
                        WebCacheKeyIndicatorType.FRAGMENT_PRESENT,
                        parsed.fragment,
                    )
                )

            names = [name for name, _ in query]
            unique_names = set(names)

            for name in sorted(unique_names & cache_key_parameters):
                indicators.append(
                    WebCacheKeyIndicator(
                        WebCacheKeyIndicatorType.CACHE_KEY_QUERY_PARAMETER,
                        name,
                    )
                )

            for name in sorted(unique_names & unkeyed_parameters):
                indicators.append(
                    WebCacheKeyIndicator(
                        WebCacheKeyIndicatorType.UNKEYED_QUERY_PARAMETER,
                        name,
                    )
                )

            for name in sorted(unique_names & self.SENSITIVE_PARAMETERS):
                indicators.append(
                    WebCacheKeyIndicator(
                        WebCacheKeyIndicatorType.SENSITIVE_QUERY_PARAMETER,
                        name,
                    )
                )

            for name in sorted(unique_names):
                if names.count(name) > 1:
                    indicators.append(
                        WebCacheKeyIndicator(
                            WebCacheKeyIndicatorType.DUPLICATE_QUERY_PARAMETER,
                            name,
                        )
                    )

        if cookie_present:
            indicators.append(
                WebCacheKeyIndicator(
                    WebCacheKeyIndicatorType.COOKIE_PRESENT
                )
            )

        if authorization_present:
            indicators.append(
                WebCacheKeyIndicator(
                    WebCacheKeyIndicatorType.AUTHORIZATION_PRESENT
                )
            )

        vary = (vary_header or "").strip()

        if vary:
            indicators.append(
                WebCacheKeyIndicator(
                    WebCacheKeyIndicatorType.VARY_PRESENT,
                    vary,
                )
            )
        else:
            indicators.append(
                WebCacheKeyIndicator(
                    WebCacheKeyIndicatorType.VARY_MISSING
                )
            )

        cache_control = ""

        if response is not None:
            getter = getattr(response, "get_header", None)

            if callable(getter):
                cache_control = getter("cache-control") or ""

        directives = {
            directive.strip().lower()
            for directive in cache_control.split(",")
            if directive.strip()
        }

        if "private" in directives:
            indicators.append(
                WebCacheKeyIndicator(
                    WebCacheKeyIndicatorType.CACHE_CONTROL_PRIVATE
                )
            )

        if "no-store" in directives:
            indicators.append(
                WebCacheKeyIndicator(
                    WebCacheKeyIndicatorType.CACHE_CONTROL_NO_STORE
                )
            )

        if "no-cache" in directives:
            indicators.append(
                WebCacheKeyIndicator(
                    WebCacheKeyIndicatorType.CACHE_CONTROL_NO_CACHE
                )
            )

        return WebCacheKeyAnalysis(tuple(indicators))
