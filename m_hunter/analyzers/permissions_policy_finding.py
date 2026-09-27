from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.permissions_policy import (
    PermissionsPolicyAnalysis,
    PermissionsPolicyIndicatorType,
)
from m_hunter.core.finding import Finding


class PermissionsPolicyFindingAnalyzer(FindingAnalyzer):
    name = "permissions_policy_finding"

    METADATA = {
        PermissionsPolicyIndicatorType.POLICY_PRESENT: (
            "Permissions-Policy header is present",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.POLICY_MISSING: (
            "Permissions-Policy header is missing",
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.WILDCARD_SOURCE: (
            "Permissions-Policy allows a feature from all origins",
            "High",
            "High",
            "CWE-942",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.SELF_SOURCE: (
            "Permissions-Policy allows a feature from the same origin",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.ORIGIN_SOURCE: (
            "Permissions-Policy allows a feature from an explicit origin",
            "Low",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.CAMERA: (
            "Permissions-Policy contains camera permission configuration",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.MICROPHONE: (
            "Permissions-Policy contains microphone permission configuration",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.GEOLOCATION: (
            "Permissions-Policy contains geolocation permission configuration",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.PAYMENT: (
            "Permissions-Policy contains payment permission configuration",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.USB: (
            "Permissions-Policy contains USB permission configuration",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.FULLSCREEN: (
            "Permissions-Policy contains fullscreen permission configuration",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.DISPLAY_CAPTURE: (
            "Permissions-Policy contains display-capture permission configuration",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.INVALID_DIRECTIVE: (
            "Permissions-Policy contains an invalid or unknown directive",
            "Medium",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.INVALID_SOURCE: (
            "Permissions-Policy contains an invalid source expression",
            "Medium",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        PermissionsPolicyIndicatorType.MULTIPLE_POLICIES: (
            "Multiple Permissions-Policy headers are present",
            "Low",
            "Medium",
            "CWE-16",
            "A05:2021",
        ),
    }

    def analyze(
        self,
        analysis: PermissionsPolicyAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, PermissionsPolicyAnalysis):
            raise TypeError(
                "analysis must be an instance of PermissionsPolicyAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        findings: list[Finding] = []

        for indicator in analysis.indicators:
            metadata = self.METADATA.get(indicator.type)
            if metadata is None:
                continue

            title, severity, confidence, cwe, owasp = metadata

            evidence = indicator.name
            if indicator.type == PermissionsPolicyIndicatorType.POLICY_MISSING:
                evidence = "Permissions-Policy header is missing"
            elif indicator.value:
                evidence = f"{indicator.name}: {indicator.value}"

            description = (
                f"Permissions-Policy analysis detected the indicator "
                f"'{indicator.type.value}'. This indicator provides "
                f"security context and does not by itself prove an "
                f"exploitable vulnerability."
            )

            remediation = (
                "Define an explicit Permissions-Policy that disables "
                "unnecessary powerful browser features and restricts "
                "allowed origins to trusted sources."
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
