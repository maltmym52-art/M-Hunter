from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.coep import (
    COEPAnalysis,
    COEPIndicatorType,
)
from m_hunter.core.finding import Finding


class COEPFindingAnalyzer(FindingAnalyzer):
    name = "coep_finding"

    METADATA = {
        COEPIndicatorType.POLICY_PRESENT: (
            "Cross-Origin-Embedder-Policy header is present",
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COEPIndicatorType.POLICY_MISSING: (
            "Cross-Origin-Embedder-Policy header is missing",
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COEPIndicatorType.REQUIRE_CORP: (
            "Cross-Origin-Embedder-Policy uses require-corp",
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COEPIndicatorType.CREDENTIALLESS: (
            "Cross-Origin-Embedder-Policy uses credentialless",
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COEPIndicatorType.UNSAFE_NONE: (
            "Cross-Origin-Embedder-Policy uses unsafe-none",
            "Medium",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        COEPIndicatorType.INVALID_POLICY: (
            "Cross-Origin-Embedder-Policy contains an invalid policy",
            "Medium",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        COEPIndicatorType.MULTIPLE_POLICIES: (
            "Multiple Cross-Origin-Embedder-Policy values are present",
            "Low",
            "Medium",
            "CWE-16",
            "A05:2021",
        ),
    }

    def analyze(
        self,
        analysis: COEPAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, COEPAnalysis):
            raise TypeError(
                "analysis must be an instance of COEPAnalysis"
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

            if indicator.type == COEPIndicatorType.POLICY_MISSING:
                evidence = (
                    "Cross-Origin-Embedder-Policy header is missing"
                )
            elif indicator.value:
                evidence = (
                    f"{indicator.name}: {indicator.value}"
                )
            else:
                evidence = indicator.name

            description = (
                f"COEP analysis detected the indicator "
                f"'{indicator.type.value}'. This indicator provides "
                f"security context and does not by itself prove an "
                f"exploitable vulnerability."
            )

            remediation = (
                "Configure Cross-Origin-Embedder-Policy according to "
                "the application's cross-origin isolation requirements. "
                "Use require-corp or credentialless where appropriate "
                "and verify compatibility with required cross-origin "
                "resources."
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
