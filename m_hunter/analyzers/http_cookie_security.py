from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CookieSecurityIndicatorType(str, Enum):
    COOKIE_PRESENT = "cookie_present"
    SECURE_MISSING = "secure_missing"
    HTTPONLY_MISSING = "httponly_missing"
    SAMESITE_MISSING = "samesite_missing"
    SAMESITE_NONE = "samesite_none"
    SAMESITE_INVALID = "samesite_invalid"
    DOMAIN_BROAD = "domain_broad"
    DOMAIN_MISSING = "domain_missing"
    PATH_BROAD = "path_broad"
    PATH_MISSING = "path_missing"
    SESSION_COOKIE = "session_cookie"
    PERSISTENT_COOKIE = "persistent_cookie"
    LONG_LIVED_COOKIE = "long_lived_cookie"
    PREFIX_VIOLATION = "prefix_violation"
    DUPLICATE_COOKIE = "duplicate_cookie"
    MULTIPLE_COOKIES = "multiple_cookies"


@dataclass(frozen=True)
class CookieSecurityIndicator:
    type: CookieSecurityIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class CookieSecurityAnalysis:
    indicators: tuple[CookieSecurityIndicator, ...]

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[CookieSecurityIndicatorType, ...]:
        return tuple(item.type for item in self.indicators)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.indicators)

    def has_type(self, indicator_type: CookieSecurityIndicatorType) -> bool:
        return indicator_type in self.types


class HttpCookieSecurityAnalyzer:
    name = "http_cookie_security"
    description = "Analyze HTTP cookies for security-sensitive configuration issues."

    VALID_SAMESITE = {"strict", "lax", "none"}

    def analyze(
        self,
        *,
        cookie_name: str,
        secure: bool = False,
        httponly: bool = False,
        samesite: str | None = None,
        domain: str | None = None,
        path: str | None = None,
        max_age: int | None = None,
        expires_seconds: int | None = None,
        is_session_cookie: bool = True,
        duplicate_cookie: bool = False,
        cookie_count: int = 1,
    ) -> CookieSecurityAnalysis:
        indicators: list[CookieSecurityIndicator] = []

        indicators.append(
            CookieSecurityIndicator(
                CookieSecurityIndicatorType.COOKIE_PRESENT,
                "Cookie is present",
                cookie_name,
            )
        )

        if not secure:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.SECURE_MISSING,
                    "Secure attribute is missing",
                    cookie_name,
                )
            )

        if not httponly:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.HTTPONLY_MISSING,
                    "HttpOnly attribute is missing",
                    cookie_name,
                )
            )

        if samesite is None:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.SAMESITE_MISSING,
                    "SameSite attribute is missing",
                    cookie_name,
                )
            )
        else:
            normalized_samesite = samesite.strip().lower()

            if normalized_samesite not in self.VALID_SAMESITE:
                indicators.append(
                    CookieSecurityIndicator(
                        CookieSecurityIndicatorType.SAMESITE_INVALID,
                        "SameSite attribute has an invalid value",
                        samesite,
                    )
                )
            elif normalized_samesite == "none":
                indicators.append(
                    CookieSecurityIndicator(
                        CookieSecurityIndicatorType.SAMESITE_NONE,
                        "SameSite=None is configured",
                        cookie_name,
                    )
                )

        if domain:
            normalized_domain = domain.strip()

            if normalized_domain == "." or normalized_domain.startswith("."):
                indicators.append(
                    CookieSecurityIndicator(
                        CookieSecurityIndicatorType.DOMAIN_BROAD,
                        "Cookie Domain attribute is broadly scoped",
                        domain,
                    )
                )
        else:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.DOMAIN_MISSING,
                    "Cookie Domain attribute is not explicitly defined",
                    cookie_name,
                )
            )

        if path:
            normalized_path = path.strip()

            if normalized_path == "/":
                indicators.append(
                    CookieSecurityIndicator(
                        CookieSecurityIndicatorType.PATH_BROAD,
                        "Cookie Path attribute is broadly scoped",
                        path,
                    )
                )
        else:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.PATH_MISSING,
                    "Cookie Path attribute is not explicitly defined",
                    cookie_name,
                )
            )

        if is_session_cookie:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.SESSION_COOKIE,
                    "Cookie is configured as a session cookie",
                    cookie_name,
                )
            )
        else:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.PERSISTENT_COOKIE,
                    "Cookie is configured as a persistent cookie",
                    cookie_name,
                )
            )

        lifetime = max_age if max_age is not None else expires_seconds

        if lifetime is not None and lifetime > 31536000:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.LONG_LIVED_COOKIE,
                    "Cookie lifetime exceeds one year",
                    str(lifetime),
                )
            )

        if cookie_name.startswith("__Host-"):
            if not secure or domain is not None or path != "/":
                indicators.append(
                    CookieSecurityIndicator(
                        CookieSecurityIndicatorType.PREFIX_VIOLATION,
                        "__Host- cookie prefix requirements are not satisfied",
                        cookie_name,
                    )
                )

        if cookie_name.startswith("__Secure-") and not secure:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.PREFIX_VIOLATION,
                    "__Secure- cookie prefix requires Secure",
                    cookie_name,
                )
            )

        if duplicate_cookie:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.DUPLICATE_COOKIE,
                    "Duplicate cookie name detected",
                    cookie_name,
                )
            )

        if cookie_count > 1:
            indicators.append(
                CookieSecurityIndicator(
                    CookieSecurityIndicatorType.MULTIPLE_COOKIES,
                    "Multiple cookies are present",
                    str(cookie_count),
                )
            )

        return CookieSecurityAnalysis(tuple(indicators))
