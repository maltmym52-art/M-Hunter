from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HttpResponseSecurityValidation:
    indicator: str
    reason: str
    requires_response_change: bool = True


class HttpResponseSecurityValidator:
    """Validate HTTP response information-disclosure indicators."""

    SECURITY_INDICATORS = {
        "SERVER_VERSION_DISCLOSURE",
        "X_POWERED_BY",
        "DEBUG_DISCLOSURE",
        "STACK_TRACE_DISCLOSURE",
        "EXCEPTION_DISCLOSURE",
        "INTERNAL_PATH_DISCLOSURE",
        "INTERNAL_IP_DISCLOSURE",
        "DIRECTORY_LISTING",
        "ERROR_DETAILS_DISCLOSURE",
    }

    def validate(self, indicator_type: str) -> HttpResponseSecurityValidation:
        indicator_type = getattr(indicator_type, "name", indicator_type)

        if indicator_type in self.SECURITY_INDICATORS:
            return HttpResponseSecurityValidation(
                indicator=indicator_type,
                reason=(
                    "The indicator represents potentially security-relevant "
                    "HTTP response information disclosure."
                ),
                requires_response_change=True,
            )

        return HttpResponseSecurityValidation(
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
    ) -> list[HttpResponseSecurityValidation]:
        return [self.validate(item) for item in indicator_types]
