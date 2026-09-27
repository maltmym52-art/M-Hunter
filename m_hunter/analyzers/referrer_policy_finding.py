from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.referrer_policy import (
    ReferrerPolicyAnalysis,
    ReferrerPolicyIndicatorType,
)
from m_hunter.core.finding import Finding


class ReferrerPolicyFindingAnalyzer(FindingAnalyzer):
    name = "referrer_policy_finding"

    METADATA = {
        ReferrerPolicyIndicatorType.POLICY_PRESENT:
            ("Info", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.POLICY_MISSING:
            ("Low", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.UNSAFE_URL:
            ("Medium", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.NO_REFERRER_WHEN_DOWNGRADE:
            ("Low", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.ORIGIN_WHEN_CROSS_ORIGIN:
            ("Info", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.STRICT_ORIGIN_WHEN_CROSS_ORIGIN:
            ("Info", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.SAME_ORIGIN:
            ("Info", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.STRICT_ORIGIN:
            ("Info", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.NO_REFERRER:
            ("Info", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.INVALID_POLICY:
            ("Medium", "High", "CWE-200", "A05:2021"),
        ReferrerPolicyIndicatorType.MULTIPLE_POLICIES:
            ("Low", "Medium", "CWE-200", "A05:2021"),
    }

    TITLES = {
        ReferrerPolicyIndicatorType.POLICY_PRESENT:
            "Referrer-Policy Present",
        ReferrerPolicyIndicatorType.POLICY_MISSING:
            "Referrer-Policy Missing",
        ReferrerPolicyIndicatorType.UNSAFE_URL:
            "Unsafe Referrer-Policy",
        ReferrerPolicyIndicatorType.NO_REFERRER_WHEN_DOWNGRADE:
            "Weak Referrer-Policy",
        ReferrerPolicyIndicatorType.ORIGIN_WHEN_CROSS_ORIGIN:
            "Origin Referrer-Policy",
        ReferrerPolicyIndicatorType.STRICT_ORIGIN_WHEN_CROSS_ORIGIN:
            "Strict Origin Referrer-Policy",
        ReferrerPolicyIndicatorType.SAME_ORIGIN:
            "Same-Origin Referrer-Policy",
        ReferrerPolicyIndicatorType.STRICT_ORIGIN:
            "Strict-Origin Referrer-Policy",
        ReferrerPolicyIndicatorType.NO_REFERRER:
            "No-Referrer Policy",
        ReferrerPolicyIndicatorType.INVALID_POLICY:
            "Invalid Referrer-Policy",
        ReferrerPolicyIndicatorType.MULTIPLE_POLICIES:
            "Multiple Referrer-Policy Values",
    }

    def analyze(
        self,
        analysis: ReferrerPolicyAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(
            analysis,
            ReferrerPolicyAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of "
                "ReferrerPolicyAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                "target must be a non-empty string"
            )

        if endpoint is not None and not isinstance(
            endpoint,
            str,
        ):
            raise TypeError(
                "endpoint must be a string or None"
            )

        findings: list[Finding] = []

        for indicator in analysis.indicators:
            metadata = self.METADATA.get(
                indicator.type
            )

            if metadata is None:
                continue

            severity, confidence, cwe, owasp = metadata

            title = self.TITLES.get(
                indicator.type,
                indicator.type.value.replace(
                    "_",
                    " ",
                ).title(),
            )

            evidence = indicator.evidence

            if indicator.value:
                evidence = (
                    f"{evidence}; "
                    f"value={indicator.value}"
                )

            description = (
                "Referrer-Policy analysis identified "
                f"{indicator.type.value}. "
                "The indicator provides security context "
                "and does not by itself prove sensitive "
                "information disclosure."
            )

            remediation = (
                "Review the Referrer-Policy configuration "
                "and use a restrictive policy appropriate "
                "for the application's privacy and "
                "security requirements."
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
