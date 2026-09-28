from __future__ import annotations

from m_hunter.findings.http_cookie_security import (
    HttpCookieSecurityFinding,
)
from m_hunter.validation.http_cookie_security import (
    HttpCookieSecurityValidator,
)


class HttpCookieSecurityPipeline:
    """Connect cookie analysis, validation, and finding generation."""

    def __init__(self) -> None:
        self.validator = HttpCookieSecurityValidator()

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

            if indicator_type not in HttpCookieSecurityFinding.METADATA:
                continue

            findings.append(
                HttpCookieSecurityFinding.build(
                    indicator_type,
                    target,
                    endpoint=endpoint,
                    evidence=indicator.value or "",
                )
            )

        return findings
