from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HttpCookieSecurityValidation:
    indicator: str
    reason: str
    requires_response_change: bool = True


class HttpCookieSecurityValidator:
    """Validate HTTP cookie security indicators."""

    SECURITY_INDICATORS = {
        "SECURE_MISSING",
        "HTTPONLY_MISSING",
        "SAMESITE_MISSING",
        "SAMESITE_NONE",
        "SAMESITE_INVALID",
        "DOMAIN_BROAD",
        "PATH_BROAD",
        "LONG_LIVED_COOKIE",
        "PREFIX_VIOLATION",
        "DUPLICATE_COOKIE",
    }

    def validate(self, indicator_type: str) -> HttpCookieSecurityValidation:
        indicator_type = getattr(indicator_type, "name", indicator_type)

        if indicator_type in self.SECURITY_INDICATORS:
            return HttpCookieSecurityValidation(
                indicator=indicator_type,
                reason=(
                    "The indicator represents potentially security-relevant "
                    "cookie configuration."
                ),
                requires_response_change=True,
            )

        return HttpCookieSecurityValidation(
            indicator=indicator_type,
            reason=(
                "The indicator is informational and does not by itself "
                "establish a security issue."
            ),
            requires_response_change=False,
        )

    def is_security_relevant(self, indicator_type: str) -> bool:
        indicator_type = getattr(indicator_type, "name", indicator_type)
        return indicator_type in self.SECURITY_INDICATORS

    def validate_all(
        self,
        indicator_types: list[str],
    ) -> list[HttpCookieSecurityValidation]:
        return [self.validate(item) for item in indicator_types]
