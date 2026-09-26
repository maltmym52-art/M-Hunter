from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

from m_hunter.core.response import HttpResponse


class WebCacheDeceptionIndicatorType(str, Enum):
    CACHE_HEADER = "cache_header"
    CACHEABLE_RESPONSE = "cacheable_response"
    STATIC_EXTENSION = "static_extension"
    PATH_VARIATION = "path_variation"
    SENSITIVE_CONTENT = "sensitive_content"
    PRIVATE_CONTENT = "private_content"
    CACHE_STATUS = "cache_status"
    AGE_HEADER = "age_header"
    VARY_HEADER = "vary_header"
    CONTENT_TYPE_MISMATCH = "content_type_mismatch"


@dataclass(frozen=True)
class WebCacheDeceptionIndicator:
    type: WebCacheDeceptionIndicatorType
    evidence: str
    name: str
    value: str


@dataclass
class WebCacheDeceptionAnalysis:
    detected: bool
    count: int
    types: list[str]
    names: list[str]
    indicators: list[WebCacheDeceptionIndicator]

    def has_type(self, indicator_type: WebCacheDeceptionIndicatorType) -> bool:
        return indicator_type.value in self.types


class WebCacheDeceptionAnalyzer:
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

    STATIC_EXTENSIONS = {
        ".css",
        ".js",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
        ".txt",
        ".xml",
    }

    SENSITIVE_MARKERS = {
        "account",
        "profile",
        "dashboard",
        "settings",
        "billing",
        "payment",
        "orders",
        "order",
        "private",
        "user",
        "users",
        "admin",
        "email",
        "token",
        "session",
        "invoice",
    }

    def analyze(
        self,
        response: HttpResponse | None = None,
        *,
        url: str | None = None,
        headers: dict[str, str] | None = None,
        response_body: str | None = None,
        content_type: str | None = None,
        path: str | None = None,
    ) -> WebCacheDeceptionAnalysis:
        indicators: list[WebCacheDeceptionIndicator] = []

        if response is not None:
            url = response.url
            headers = response.headers
            response_body = response.text
            content_type = response.get_content_type()

        headers = headers or {}
        normalized_headers = {
            str(name).lower(): str(value)
            for name, value in headers.items()
        }

        parsed = urlparse(url or "")
        effective_path = path or parsed.path

        if not content_type:
            content_type = self._content_type(normalized_headers)

        for name, value in normalized_headers.items():
            if name in self.CACHE_HEADERS:
                indicators.append(
                    WebCacheDeceptionIndicator(
                        WebCacheDeceptionIndicatorType.CACHE_STATUS,
                        f"{name}: {value}",
                        name,
                        value,
                    )
                )

            if name in self.CACHE_CONTROL_HEADERS:
                indicators.append(
                    WebCacheDeceptionIndicator(
                        WebCacheDeceptionIndicatorType.CACHE_HEADER,
                        f"{name}: {value}",
                        name,
                        value,
                    )
                )

                if self._appears_cacheable(value):
                    indicators.append(
                        WebCacheDeceptionIndicator(
                            WebCacheDeceptionIndicatorType.CACHEABLE_RESPONSE,
                            f"{name} permits caching: {value}",
                            name,
                            value,
                        )
                    )

            if name == "age":
                indicators.append(
                    WebCacheDeceptionIndicator(
                        WebCacheDeceptionIndicatorType.AGE_HEADER,
                        f"Age: {value}",
                        name,
                        value,
                    )
                )

            if name == "vary":
                indicators.append(
                    WebCacheDeceptionIndicator(
                        WebCacheDeceptionIndicatorType.VARY_HEADER,
                        f"Vary: {value}",
                        name,
                        value,
                    )
                )

        if self._has_static_extension(effective_path):
            indicators.append(
                WebCacheDeceptionIndicator(
                    WebCacheDeceptionIndicatorType.STATIC_EXTENSION,
                    f"Static-looking extension detected in path: {effective_path}",
                    "path",
                    effective_path,
                )
            )

        if self._has_path_variation(effective_path):
            indicators.append(
                WebCacheDeceptionIndicator(
                    WebCacheDeceptionIndicatorType.PATH_VARIATION,
                    f"Path contains an additional cache-looking suffix: {effective_path}",
                    "path",
                    effective_path,
                )
            )

        path_lower = effective_path.lower()
        body_lower = (response_body or "").lower()

        sensitive_matches = [
            marker
            for marker in self.SENSITIVE_MARKERS
            if marker in path_lower or marker in body_lower
        ]

        if sensitive_matches:
            value = ", ".join(sorted(set(sensitive_matches)))
            indicators.append(
                WebCacheDeceptionIndicator(
                    WebCacheDeceptionIndicatorType.SENSITIVE_CONTENT,
                    f"Potentially sensitive content marker(s): {value}",
                    "sensitive_markers",
                    value,
                )
            )

        private_directives = (
            "private",
            "no-store",
            "no-cache",
            "must-revalidate",
        )

        cache_control = normalized_headers.get("cache-control", "")
        if any(
            directive in cache_control.lower()
            for directive in private_directives
        ):
            indicators.append(
                WebCacheDeceptionIndicator(
                    WebCacheDeceptionIndicatorType.PRIVATE_CONTENT,
                    f"Response contains private cache directive: {cache_control}",
                    "cache-control",
                    cache_control,
                )
            )

        if (
            content_type
            and self._has_static_extension(effective_path)
            and not self._looks_static_content_type(content_type)
        ):
            indicators.append(
                WebCacheDeceptionIndicator(
                    WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH,
                    (
                        f"Static-looking path returned non-static "
                        f"content type: {content_type}"
                    ),
                    "content-type",
                    content_type,
                )
            )

        unique: list[WebCacheDeceptionIndicator] = []
        seen: set[tuple[str, str, str]] = set()

        for indicator in indicators:
            key = (
                indicator.type.value,
                indicator.name,
                indicator.value,
            )
            if key not in seen:
                seen.add(key)
                unique.append(indicator)

        types = list(dict.fromkeys(
            indicator.type.value for indicator in unique
        ))

        names = list(dict.fromkeys(
            indicator.name for indicator in unique
        ))

        return WebCacheDeceptionAnalysis(
            detected=bool(unique),
            count=len(unique),
            types=types,
            names=names,
            indicators=unique,
        )

    @staticmethod
    def _content_type(headers: dict[str, str]) -> str | None:
        value = headers.get("content-type")
        if value is None:
            return None
        return value.split(";", 1)[0].strip().lower()

    @staticmethod
    def _appears_cacheable(value: str) -> bool:
        lowered = value.lower()

        if "no-store" in lowered:
            return False

        if "private" in lowered:
            return False

        return (
            "public" in lowered
            or "max-age=" in lowered
            or "s-maxage=" in lowered
        )

    def _has_static_extension(self, path: str) -> bool:
        lowered = path.lower().split("?", 1)[0]
        return any(
            lowered.endswith(extension)
            for extension in self.STATIC_EXTENSIONS
        )

    @staticmethod
    def _has_path_variation(path: str) -> bool:
        lowered = path.lower().split("?", 1)[0]

        return any(
            marker in lowered
            for marker in (
                ".css/",
                ".js/",
                ".jpg/",
                ".jpeg/",
                ".png/",
                ".gif/",
                ".svg/",
                ".txt/",
                ".xml/",
            )
        )

    @staticmethod
    def _looks_static_content_type(content_type: str) -> bool:
        lowered = content_type.lower()

        return (
            lowered.startswith("text/css")
            or lowered.startswith("text/javascript")
            or lowered.startswith("application/javascript")
            or lowered.startswith("image/")
            or lowered.startswith("font/")
            or lowered.startswith("application/font")
        )
