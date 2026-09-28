from typing import Any

from m_hunter.core.finding import Finding
from m_hunter.findings.converter import FindingConverter


class FindingAnalyzer:
    """Converts structured analyzer results into security findings."""

    def create_finding(
        self,
        *,
        title: str,
        severity: str,
        confidence: str,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        cwe: str | None = None,
        owasp: str | None = None,
    ) -> Finding:
        return FindingConverter.create_from_fields(
            title=title,
            severity=severity,
            confidence=confidence,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cwe=cwe,
            owasp=owasp,
        )

    def from_analysis(
        self,
        *,
        analysis: dict[str, Any],
        title: str,
        severity: str,
        confidence: str,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        cwe: str | None = None,
        owasp: str | None = None,
    ) -> Finding | None:
        if not analysis:
            return None

        return self.create_finding(
            title=title,
            severity=severity,
            confidence=confidence,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cwe=cwe,
            owasp=owasp,
        )
