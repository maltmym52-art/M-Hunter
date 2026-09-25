from dataclasses import dataclass, field
from enum import Enum
import re


class CSRFIndicatorType(str, Enum):
    STATE_CHANGING_METHOD = "state_changing_method"
    FORM_WITHOUT_CSRF_TOKEN = "form_without_csrf_token"
    CSRF_TOKEN_PRESENT = "csrf_token_present"
    SAME_SITE_COOKIE_MISSING = "samesite_cookie_missing"
    ORIGIN_VALIDATION_MISSING = "origin_validation_missing"
    REFERER_VALIDATION_MISSING = "referer_validation_missing"


@dataclass(frozen=True)
class CSRFIndicator:
    type: CSRFIndicatorType
    evidence: str
    position: int | None = None


@dataclass
class CSRFAnalysis:
    detected: bool = False
    indicator_count: int = 0
    types: list[CSRFIndicatorType] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    indicators: list[CSRFIndicator] = field(default_factory=list)

    @property
    def state_changing(self) -> bool:
        return CSRFIndicatorType.STATE_CHANGING_METHOD in self.types

    @property
    def token_present(self) -> bool:
        return CSRFIndicatorType.CSRF_TOKEN_PRESENT in self.types

    @property
    def missing_token(self) -> bool:
        return CSRFIndicatorType.FORM_WITHOUT_CSRF_TOKEN in self.types


class CSRFAnalyzer:
    """
    Passive CSRF indicator analyzer.

    This analyzer identifies request/form/cookie signals that may be
    relevant to CSRF. It does not submit forged requests and does not
    confirm exploitability.
    """

    STATE_CHANGING_METHODS = {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }

    TOKEN_NAMES = {
        "csrf",
        "csrf_token",
        "csrftoken",
        "_csrf",
        "_csrf_token",
        "xsrf",
        "xsrf_token",
        "xsrf-token",
        "x-csrf-token",
        "x-xsrf-token",
    }

    FORM_METHOD_PATTERN = re.compile(
        r'<form\b[^>]*\bmethod\s*=\s*["\']?'
        r'(post|put|patch|delete)',
        re.IGNORECASE,
    )

    TOKEN_PATTERN = re.compile(
        r'(csrf[_-]?token|xsrf[_-]?token|x-csrf-token|x-xsrf-token)',
        re.IGNORECASE,
    )

    def analyze(
        self,
        method: str,
        *,
        body: str | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> CSRFAnalysis:
        method = method.upper().strip()

        indicators: list[CSRFIndicator] = []

        if method in self.STATE_CHANGING_METHODS:
            indicators.append(
                CSRFIndicator(
                    type=CSRFIndicatorType.STATE_CHANGING_METHOD,
                    evidence=f"HTTP method: {method}",
                )
            )

        body = body or ""
        headers = headers or {}
        cookies = cookies or {}

        body_lower = body.lower()

        token_found = False

        for name in self.TOKEN_NAMES:
            if name.lower() in body_lower:
                token_found = True
                position = body_lower.find(name.lower())
                indicators.append(
                    CSRFIndicator(
                        type=CSRFIndicatorType.CSRF_TOKEN_PRESENT,
                        evidence=f"CSRF token marker: {name}",
                        position=position,
                    )
                )
                break

        if not token_found:
            match = self.TOKEN_PATTERN.search(body)
            if match:
                token_found = True
                indicators.append(
                    CSRFIndicator(
                        type=CSRFIndicatorType.CSRF_TOKEN_PRESENT,
                        evidence=f"CSRF token marker: {match.group(1)}",
                        position=match.start(),
                    )
                )

        form_match = self.FORM_METHOD_PATTERN.search(body)

        if form_match and not token_found:
            indicators.append(
                CSRFIndicator(
                    type=CSRFIndicatorType.FORM_WITHOUT_CSRF_TOKEN,
                    evidence="State-changing form without a detected CSRF token",
                    position=form_match.start(),
                )
            )

        if (
            method in self.STATE_CHANGING_METHODS
            and body
            and not token_found
            and not form_match
        ):
            indicators.append(
                CSRFIndicator(
                    type=CSRFIndicatorType.FORM_WITHOUT_CSRF_TOKEN,
                    evidence="State-changing request without a detected CSRF token",
                )
            )

        cookie_names = {
            name.lower(): value
            for name, value in cookies.items()
        }

        session_cookie_names = {
            "session",
            "sessionid",
            "session_id",
            "sid",
            "jsessionid",
            "phpsessid",
            "asp.net_sessionid",
        }

        has_session_cookie = bool(
            session_cookie_names.intersection(cookie_names)
        )

        if has_session_cookie:
            samesite_present = any(
                name.lower().startswith("samesite")
                or "samesite" in name.lower()
                for name in cookie_names
            )

            if not samesite_present:
                indicators.append(
                    CSRFIndicator(
                        type=CSRFIndicatorType.SAME_SITE_COOKIE_MISSING,
                        evidence="Session cookie present without detected SameSite metadata",
                    )
                )

        header_names = {name.lower() for name in headers}

        if method in self.STATE_CHANGING_METHODS:
            if "origin" not in header_names:
                indicators.append(
                    CSRFIndicator(
                        type=CSRFIndicatorType.ORIGIN_VALIDATION_MISSING,
                        evidence="Origin header not present in analyzed request context",
                    )
                )

            if "referer" not in header_names:
                indicators.append(
                    CSRFIndicator(
                        type=CSRFIndicatorType.REFERER_VALIDATION_MISSING,
                        evidence="Referer header not present in analyzed request context",
                    )
                )

        types = []
        names = []

        for indicator in indicators:
            if indicator.type not in types:
                types.append(indicator.type)
            if indicator.type.value not in names:
                names.append(indicator.type.value)

        return CSRFAnalysis(
            detected=bool(indicators),
            indicator_count=len(indicators),
            types=types,
            names=names,
            indicators=indicators,
        )
