from dataclasses import dataclass, field
from enum import Enum


class CacheControlIndicatorType(str, Enum):
    CACHE_CONTROL_PRESENT = "cache_control_present"
    CACHE_CONTROL_MISSING = "cache_control_missing"
    NO_STORE = "no_store"
    NO_CACHE = "no_cache"
    PRIVATE = "private"
    PUBLIC = "public"
    MUST_REVALIDATE = "must_revalidate"
    S_MAXAGE = "s_maxage"
    MAX_AGE = "max_age"
    PRAGMA_PRESENT = "pragma_present"
    EXPIRES_PRESENT = "expires_present"
    AGE_PRESENT = "age_present"
    VARY_PRESENT = "vary_present"
    SURROGATE_CONTROL_PRESENT = "surrogate_control_present"
    CACHEABLE_RESPONSE = "cacheable_response"
    SENSITIVE_CONTENT = "sensitive_content"
    PUBLIC_SENSITIVE_CONTENT = "public_sensitive_content"
    MISSING_VARY = "missing_vary"
    CONFLICTING_CACHE_DIRECTIVES = "conflicting_cache_directives"
    MULTIPLE_CACHE_CONTROL = "multiple_cache_control"


@dataclass(frozen=True)
class CacheControlIndicator:
    type: CacheControlIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class CacheControlAnalysis:
    detected: bool
    indicators: tuple[CacheControlIndicator, ...] = field(
        default_factory=tuple
    )

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[CacheControlIndicatorType, ...]:
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
        indicator_type: CacheControlIndicatorType,
    ) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class CacheControlSecurityAnalyzer:
    name = "cache_control_security"
    description = (
        "Analyze HTTP cache-control and response caching indicators"
    )

    def analyze(
        self,
        *,
        cache_control: str | None = None,
        pragma: str | None = None,
        expires: str | None = None,
        age: str | None = None,
        vary: str | None = None,
        surrogate_control: str | None = None,
        sensitive_content: bool = False,
        multiple_cache_control: bool = False,
    ) -> CacheControlAnalysis:
        indicators: list[CacheControlIndicator] = []

        if not isinstance(sensitive_content, bool):
            raise TypeError(
                "sensitive_content must be a boolean"
            )

        if not isinstance(multiple_cache_control, bool):
            raise TypeError(
                "multiple_cache_control must be a boolean"
            )

        if cache_control is not None:
            if not isinstance(cache_control, str):
                raise TypeError(
                    "cache_control must be a string or None"
                )

            value = cache_control.strip()
            lowered = value.lower()

            if value:
                indicators.append(
                    CacheControlIndicator(
                        type=CacheControlIndicatorType.CACHE_CONTROL_PRESENT,
                        name="Cache-Control header is present",
                        value=value,
                    )
                )

                directives = {
                    item.strip().split("=", 1)[0].strip().lower()
                    for item in value.split(",")
                    if item.strip()
                }

                if "no-store" in directives:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.NO_STORE,
                            name="Cache-Control no-store directive",
                            value=value,
                        )
                    )

                if "no-cache" in directives:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.NO_CACHE,
                            name="Cache-Control no-cache directive",
                            value=value,
                        )
                    )

                if "private" in directives:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.PRIVATE,
                            name="Cache-Control private directive",
                            value=value,
                        )
                    )

                if "public" in directives:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.PUBLIC,
                            name="Cache-Control public directive",
                            value=value,
                        )
                    )

                if "must-revalidate" in directives:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.MUST_REVALIDATE,
                            name="Cache-Control must-revalidate directive",
                            value=value,
                        )
                    )

                if "s-maxage" in directives:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.S_MAXAGE,
                            name="Cache-Control s-maxage directive",
                            value=value,
                        )
                    )

                if "max-age" in directives:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.MAX_AGE,
                            name="Cache-Control max-age directive",
                            value=value,
                        )
                    )

                if "public" in directives and "private" in directives:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.CONFLICTING_CACHE_DIRECTIVES,
                            name="Conflicting public and private cache directives",
                            value=value,
                        )
                    )

                if "no-store" in directives and "public" in directives:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.CONFLICTING_CACHE_DIRECTIVES,
                            name="Conflicting no-store and public cache directives",
                            value=value,
                        )
                    )

                if (
                    "public" in directives
                    or "max-age" in directives
                    or "s-maxage" in directives
                ):
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.CACHEABLE_RESPONSE,
                            name="Response contains cacheability directives",
                            value=value,
                        )
                    )

        else:
            indicators.append(
                CacheControlIndicator(
                    type=CacheControlIndicatorType.CACHE_CONTROL_MISSING,
                    name="Cache-Control header is missing",
                )
            )

        if pragma is not None:
            if not isinstance(pragma, str):
                raise TypeError(
                    "pragma must be a string or None"
                )

            if pragma.strip():
                indicators.append(
                    CacheControlIndicator(
                        type=CacheControlIndicatorType.PRAGMA_PRESENT,
                        name="Pragma header is present",
                        value=pragma.strip(),
                    )
                )

        if expires is not None:
            if not isinstance(expires, str):
                raise TypeError(
                    "expires must be a string or None"
                )

            if expires.strip():
                indicators.append(
                    CacheControlIndicator(
                        type=CacheControlIndicatorType.EXPIRES_PRESENT,
                        name="Expires header is present",
                        value=expires.strip(),
                    )
                )

        if age is not None:
            if not isinstance(age, str):
                raise TypeError(
                    "age must be a string or None"
                )

            if age.strip():
                indicators.append(
                    CacheControlIndicator(
                        type=CacheControlIndicatorType.AGE_PRESENT,
                        name="Age header is present",
                        value=age.strip(),
                    )
                )

        if vary is not None:
            if not isinstance(vary, str):
                raise TypeError(
                    "vary must be a string or None"
                )

            if vary.strip():
                indicators.append(
                    CacheControlIndicator(
                        type=CacheControlIndicatorType.VARY_PRESENT,
                        name="Vary header is present",
                        value=vary.strip(),
                    )
                )

        if surrogate_control is not None:
            if not isinstance(surrogate_control, str):
                raise TypeError(
                    "surrogate_control must be a string or None"
                )

            if surrogate_control.strip():
                indicators.append(
                    CacheControlIndicator(
                        type=CacheControlIndicatorType.SURROGATE_CONTROL_PRESENT,
                        name="Surrogate-Control header is present",
                        value=surrogate_control.strip(),
                    )
                )

        if sensitive_content:
            indicators.append(
                CacheControlIndicator(
                    type=CacheControlIndicatorType.SENSITIVE_CONTENT,
                    name="Sensitive content context detected",
                )
            )

            if cache_control is not None:
                lowered = cache_control.lower()

                if (
                    "public" in lowered
                    or "s-maxage" in lowered
                ):
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.PUBLIC_SENSITIVE_CONTENT,
                            name="Sensitive content has public/shared-cache directives",
                            value=cache_control,
                        )
                    )

                if vary is None:
                    indicators.append(
                        CacheControlIndicator(
                            type=CacheControlIndicatorType.MISSING_VARY,
                            name="Sensitive cacheable response has no Vary header",
                        )
                    )

        if multiple_cache_control:
            indicators.append(
                CacheControlIndicator(
                    type=CacheControlIndicatorType.MULTIPLE_CACHE_CONTROL,
                    name="Multiple Cache-Control headers detected",
                )
            )

        return CacheControlAnalysis(
            detected=bool(indicators),
            indicators=tuple(indicators),
        )
