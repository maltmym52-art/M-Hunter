from __future__ import annotations

from m_hunter.findings.http_response_security import (
    HttpResponseSecurityFinding,
)
from m_hunter.validation.http_response_security import (
    HttpResponseSecurityValidator,
)


class HttpResponseSecurityPipeline:
    """Connect HTTP response analysis, validation, and finding generation."""

    def __init__(self) -> None:
        self.validator = HttpResponseSecurityValidator()

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

            if indicator_type not in HttpResponseSecurityFinding.METADATA:
                continue

            findings.append(
                HttpResponseSecurityFinding.build(
                    indicator_type,
                    target,
                    endpoint=endpoint,
                    evidence=indicator.value or "",
                )
            )

        return findings
