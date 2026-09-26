from collections import defaultdict

from m_hunter.analyzers.crlf_injection import (
    CRLFInjectionAnalysis,
    CRLFInjectionIndicator,
    CRLFInjectionIndicatorType,
)
from m_hunter.core.finding import Finding


class CRLFInjectionFindingAnalyzer:
    METADATA = {
        CRLFInjectionIndicatorType.CRLF: (
            "CRLF injection indicator",
            "Medium",
            "Medium",
            "CWE-113",
            "A03:2021",
        ),
        CRLFInjectionIndicatorType.CRLF_ENCODED: (
            "Encoded CRLF injection indicator",
            "Medium",
            "Medium",
            "CWE-113",
            "A03:2021",
        ),
        CRLFInjectionIndicatorType.LF_INJECTION: (
            "LF injection indicator",
            "Medium",
            "Medium",
            "CWE-113",
            "A03:2021",
        ),
        CRLFInjectionIndicatorType.CR_INJECTION: (
            "CR injection indicator",
            "Medium",
            "Medium",
            "CWE-113",
            "A03:2021",
        ),
        CRLFInjectionIndicatorType.HEADER_INJECTION: (
            "HTTP header injection indicator",
            "High",
            "Medium",
            "CWE-113",
            "A03:2021",
        ),
        CRLFInjectionIndicatorType.LOCATION_HEADER: (
            "Location header indicator",
            "Low",
            "High",
            "CWE-113",
            "A03:2021",
        ),
        CRLFInjectionIndicatorType.SET_COOKIE_HEADER: (
            "Set-Cookie header indicator",
            "Low",
            "High",
            "CWE-113",
            "A03:2021",
        ),
        CRLFInjectionIndicatorType.RESPONSE_HEADER: (
            "Response header indicator",
            "Info",
            "High",
            "CWE-113",
            "A03:2021",
        ),
    }

    REMEDIATION = (
        "Reject CR and LF characters in untrusted header values, "
        "use framework-safe response APIs, validate and canonicalize "
        "redirect/header destinations, and prevent user-controlled "
        "input from directly constructing HTTP response headers."
    )

    def analyze(
        self,
        analysis: CRLFInjectionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, CRLFInjectionAnalysis):
            raise TypeError("analysis must be a CRLFInjectionAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        if not analysis.detected:
            return []

        grouped: dict[
            CRLFInjectionIndicatorType,
            list[CRLFInjectionIndicator],
        ] = defaultdict(list)

        for indicator in analysis.indicators:
            grouped[indicator.type].append(indicator)

        findings: list[Finding] = []

        for indicator_type, indicators in grouped.items():
            metadata = self.METADATA[indicator_type]

            title, severity, confidence, cwe, owasp = metadata

            evidence = "\n".join(
                (
                    f"- {indicator.evidence}"
                    + (
                        f" Value: {indicator.value}"
                        if indicator.value is not None
                        else ""
                    )
                )
                for indicator in indicators
            )

            description = (
                f"{title} detected during HTTP input/response analysis. "
                "The presence of a CR/LF or header-related indicator alone "
                "does not prove an exploitable CRLF/header injection "
                "vulnerability; controlled validation is required."
            )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=description,
                    evidence=evidence,
                    remediation=self.REMEDIATION,
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
