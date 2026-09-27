from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityHeadersValidation:
    indicator: str
    reason: str
    requires_response_change: bool = True


class SecurityHeadersBaselineValidator:
    """Validate security-header baseline indicators."""

    SECURITY_INDICATORS = {
        "X_CONTENT_TYPE_OPTIONS_MISSING",
        "NOSNIFF_MISSING",
        "X_XSS_PROTECTION_UNSAFE",
        "CROSS_DOMAIN_POLICY_UNSAFE",
        "CLEAR_SITE_DATA_WILDCARD",
        "MULTIPLE_SECURITY_HEADER",
    }

    def validate(self, indicator_type: str) -> SecurityHeadersValidation:
        indicator_type = getattr(indicator_type, "name", indicator_type)

        if indicator_type in self.SECURITY_INDICATORS:
            return SecurityHeadersValidation(
                indicator=indicator_type,
                reason=(
                    "The indicator represents a potentially security-relevant "
                    "security-header configuration."
                ),
                requires_response_change=True,
            )

        return SecurityHeadersValidation(
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
    ) -> list[SecurityHeadersValidation]:
        return [self.validate(item) for item in indicator_types]
