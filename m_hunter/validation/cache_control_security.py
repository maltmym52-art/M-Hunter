from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CacheControlValidation:
    indicator: str
    reason: str
    requires_response_change: bool = True


class CacheControlSecurityValidator:
    """Validate whether Cache-Control indicators represent security-relevant behavior."""

    SECURITY_INDICATORS = {
        "PUBLIC_SENSITIVE_CONTENT",
        "MISSING_VARY",
        "CONFLICTING_CACHE_DIRECTIVES",
        "MULTIPLE_CACHE_CONTROL",
    }

    def validate(self, indicator_type: str) -> CacheControlValidation:
        indicator_type = getattr(indicator_type, "name", indicator_type)
        if indicator_type in self.SECURITY_INDICATORS:
            return CacheControlValidation(
                indicator=indicator_type,
                reason="The indicator represents potentially security-relevant cache behavior.",
                requires_response_change=True,
            )

        return CacheControlValidation(
            indicator=indicator_type,
            reason="The indicator is informational and does not by itself establish a security issue.",
            requires_response_change=False,
        )

    def is_security_relevant(self, indicator_type: str) -> bool:
        indicator_type = getattr(indicator_type, "name", indicator_type)
        return indicator_type in self.SECURITY_INDICATORS

    def validate_all(
        self,
        indicator_types: list[str],
    ) -> list[CacheControlValidation]:
        return [self.validate(indicator_type) for indicator_type in indicator_types]
