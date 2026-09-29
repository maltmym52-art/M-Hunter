from __future__ import annotations

from m_hunter.findings.security_headers_baseline import (
    SecurityHeadersBaselineFinding,
)
from m_hunter.validation.security_headers_baseline import (
    SecurityHeadersBaselineValidator,
)


class SecurityHeadersBaselinePipeline:
    """Connect security-header analysis, validation, and finding generation."""

    def __init__(self) -> None:
        self.validator = SecurityHeadersBaselineValidator()

    def run(
        self,
        analysis,
        target: str,
        *,
        endpoint: str | None = None,
    ):
        findings = []
        indicator_types = {
            getattr(item.type, "name", item.type)
            for item in analysis.indicators
        }

        for indicator in analysis.indicators:
            indicator_type = getattr(indicator.type, "name", indicator.type)

            if any(
                required in indicator_types
                for required in SecurityHeadersBaselineFinding.DUPLICATE_INDICATORS.get(
                    indicator_type, ()
                )
            ):
                continue

            validation = self.validator.validate(indicator_type)

            if not validation.requires_response_change:
                continue

            if indicator_type not in SecurityHeadersBaselineFinding.METADATA:
                continue

            findings.append(
                SecurityHeadersBaselineFinding.build(
                    indicator_type,
                    target,
                    endpoint=endpoint,
                    evidence=indicator.value or "",
                )
            )

        return findings
