from __future__ import annotations

from m_hunter.findings.cache_control_security import CacheControlSecurityFinding
from m_hunter.validation.cache_control_security import CacheControlSecurityValidator


class CacheControlSecurityPipeline:
    """Connect Cache-Control analysis, validation, and finding generation."""

    def __init__(self) -> None:
        self.validator = CacheControlSecurityValidator()

    def run(
        self,
        analysis,
        target: str,
        *,
        endpoint: str | None = None,
    ):
        findings = []

        for indicator in analysis.indicators:
            indicator_type = getattr(indicator.type, "name", indicator.type)

            validation = self.validator.validate(indicator_type)

            if not validation.requires_response_change:
                continue

            if indicator_type not in CacheControlSecurityFinding.METADATA:
                continue

            findings.append(
                CacheControlSecurityFinding.build(
                    indicator_type,
                    target,
                    endpoint=endpoint,
                    evidence=indicator.value or "",
                )
            )

        return findings
