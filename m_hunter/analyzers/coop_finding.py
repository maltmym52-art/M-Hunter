from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.coop import (
    COOPAnalysis,
    COOPIndicatorType,
)
from m_hunter.core.finding import Finding


class COOPFindingAnalyzer(FindingAnalyzer):
    name = "coop_finding"

    METADATA = {
        COOPIndicatorType.POLICY_PRESENT: (
            "Cross-Origin-Opener-Policy header is present",
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COOPIndicatorType.POLICY_MISSING: (
            "Cross-Origin-Opener-Policy header is missing",
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COOPIndicatorType.SAME_ORIGIN: (
            "Cross-Origin-Opener-Policy uses same-origin",
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COOPIndicatorType.SAME_ORIGIN_ALLOW_POPUPS: (
            "Cross-Origin-Opener-Policy allows same-origin popups",
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COOPIndicatorType.UNSAFE_NONE: (
            "Cross-Origin-Opener-Policy uses unsafe-none",
            "Medium",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COOPIndicatorType.INVALID_POLICY: (
            "Cross-Origin-Opener-Policy contains an invalid policy",
            "Medium",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        COOPIndicatorType.MULTIPLE_POLICIES: (
            "Multiple Cross-Origin-Opener-Policy values are present",
            "Low",
            "Medium",
            "CWE-16",
            "A05:2021",
        ),
    }

    def analyze(
        self,
        analysis: COOPAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, COOPAnalysis):
            raise TypeError(
                "analysis must be an instance of COOPAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                "target must be a non-empty string"
            )

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError(
                "endpoint must be a string or None"
            )

        findings: list[Finding] = []

        for indicator in analysis.indicators:
            metadata = self.METADATA.get(indicator.type)

            if metadata is None:
                continue

            title, severity, confidence, cwe, owasp = metadata

            if indicator.type == COOPIndicatorType.POLICY_MISSING:
                evidence = (
                    "Cross-Origin-Opener-Policy header is missing"
                )
            elif indicator.value:
                evidence = (
                    f"{indicator.name}: {indicator.value}"
                )
            else:
                evidence = indicator.name

            description = (
                f"COOP analysis detected the indicator "
                f"'{indicator.type.value}'. This indicator provides "
                f"security context and does not by itself prove an "
                f"exploitable vulnerability."
            )

            remediation = (
                "Configure Cross-Origin-Opener-Policy according to "
                "the application's cross-origin isolation requirements. "
                "Use a restrictive policy where appropriate."
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
                    remediation=remediation,
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
