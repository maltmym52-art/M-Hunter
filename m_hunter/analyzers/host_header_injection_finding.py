from collections import defaultdict

from m_hunter.analyzers.host_header_injection import (
    HostHeaderInjectionAnalysis,
    HostHeaderInjectionIndicator,
    HostHeaderInjectionIndicatorType,
)
from m_hunter.core.finding import Finding


class HostHeaderInjectionFindingAnalyzer:
    METADATA = {
        HostHeaderInjectionIndicatorType.HOST_HEADER: (
            "Host header injection indicator",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HostHeaderInjectionIndicatorType.FORWARDED_HOST: (
            "X-Forwarded-Host injection indicator",
            "Low",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HostHeaderInjectionIndicatorType.X_HOST: (
            "X-Host injection indicator",
            "Low",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HostHeaderInjectionIndicatorType.FORWARDED_HEADER: (
            "Forwarded header injection indicator",
            "Low",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HostHeaderInjectionIndicatorType.HOST_OVERRIDE: (
            "Host override header indicator",
            "Low",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HostHeaderInjectionIndicatorType.EXTERNAL_HOST: (
            "External host trust indicator",
            "High",
            "Medium",
            "CWE-20",
            "A05:2021",
        ),
        HostHeaderInjectionIndicatorType.ABSOLUTE_URL: (
            "Host-derived absolute URL indicator",
            "Medium",
            "Medium",
            "CWE-601",
            "A07:2021",
        ),
        HostHeaderInjectionIndicatorType.PASSWORD_RESET_LINK: (
            "Password reset link host indicator",
            "High",
            "Medium",
            "CWE-640",
            "A07:2021",
        ),
        HostHeaderInjectionIndicatorType.EMAIL_LINK: (
            "Email link host indicator",
            "Medium",
            "Medium",
            "CWE-640",
            "A07:2021",
        ),
        HostHeaderInjectionIndicatorType.CANONICAL_URL: (
            "Canonical URL host indicator",
            "Low",
            "Medium",
            "CWE-601",
            "A07:2021",
        ),
        HostHeaderInjectionIndicatorType.HOST_MISMATCH: (
            "Host mismatch indicator",
            "Medium",
            "Medium",
            "CWE-16",
            "A05:2021",
        ),
    }

    REMEDIATION = (
        "Do not trust client-controlled Host or forwarding headers when "
        "constructing security-sensitive URLs. Use a configured canonical "
        "host, validate trusted proxy headers, allow only expected hosts, "
        "and avoid deriving password-reset or email links directly from "
        "untrusted request headers."
    )

    def analyze(
        self,
        analysis: HostHeaderInjectionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(
            analysis,
            HostHeaderInjectionAnalysis,
        ):
            raise TypeError(
                "analysis must be a HostHeaderInjectionAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        if not analysis.detected:
            return []

        grouped: dict[
            HostHeaderInjectionIndicatorType,
            list[HostHeaderInjectionIndicator],
        ] = defaultdict(list)

        for indicator in analysis.indicators:
            grouped[indicator.type].append(indicator)

        findings: list[Finding] = []

        for indicator_type, indicators in grouped.items():
            title, severity, confidence, cwe, owasp = (
                self.METADATA[indicator_type]
            )

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
                f"{title} detected during HTTP host analysis. "
                "The presence of a host-related indicator alone does not "
                "prove an exploitable Host Header Injection vulnerability; "
                "controlled validation is required."
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
