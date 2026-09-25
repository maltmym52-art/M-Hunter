from m_hunter.analyzers.api_security import (
    APIAnalysis,
    APIIndicatorType,
)
from m_hunter.core.finding import Finding


class APISecurityFindingAnalyzer:
    METADATA = {
        APIIndicatorType.MISSING_SECURITY_HEADER: (
            "Low",
            "High",
            "A recommended API security header is missing.",
        ),
        APIIndicatorType.EXCESSIVE_DATA_EXPOSURE: (
            "Medium",
            "Medium",
            "Potentially sensitive data appears to be exposed "
            "in the API response.",
        ),
        APIIndicatorType.VERBOSE_ERROR: (
            "Medium",
            "High",
            "The API response contains verbose error or exception "
            "information that may disclose internal details.",
        ),
        APIIndicatorType.DEBUG_INFORMATION: (
            "Medium",
            "High",
            "The API response appears to expose development or "
            "debug information.",
        ),
        APIIndicatorType.SERVER_DISCLOSURE: (
            "Low",
            "High",
            "The API response discloses server implementation "
            "information through response headers.",
        ),
        APIIndicatorType.VERSION_DISCLOSURE: (
            "Low",
            "High",
            "The API response may disclose a specific server "
            "software version.",
        ),
        APIIndicatorType.UNRESTRICTED_METHOD: (
            "Medium",
            "Medium",
            "An HTTP method was observed that is not included "
            "in the expected method set. Further authorization "
            "and access-control validation is required.",
        ),
        APIIndicatorType.MISSING_CONTENT_TYPE: (
            "Low",
            "High",
            "The API response does not specify a content type.",
        ),
        APIIndicatorType.WEAK_CONTENT_TYPE: (
            "Low",
            "High",
            "The API response uses a weak or unexpected content type.",
        ),
        APIIndicatorType.CORS_MISCONFIGURATION: (
            "High",
            "High",
            "A wildcard CORS origin is combined with credential "
            "support, which requires immediate security validation.",
        ),
    }

    REMEDIATION = (
        "Apply appropriate API security controls based on the "
        "observed behavior. Minimize sensitive data exposure, "
        "avoid verbose errors and debug information, restrict "
        "unnecessary HTTP methods, use appropriate content types, "
        "limit server information disclosure, and configure CORS "
        "according to the application's trust boundaries."
    )

    def analyze(
        self,
        analysis: APIAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, APIAnalysis):
            raise TypeError(
                "analysis must be an APIAnalysis instance"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        findings: list[Finding] = []
        grouped = {}

        for indicator in analysis.indicators:
            grouped.setdefault(indicator.type, []).append(
                indicator
            )

        for indicator_type, indicators in grouped.items():
            metadata = self.METADATA.get(indicator_type)

            if metadata is None:
                continue

            severity, confidence, description = metadata

            evidence_lines = [
                f"Indicator type: {indicator_type.value}",
                f"Evidence count: {len(indicators)}",
            ]

            for indicator in indicators:
                evidence_lines.append(
                    f"Evidence: {indicator.evidence}"
                )

                if indicator.name:
                    evidence_lines.append(
                        f"Name: {indicator.name}"
                    )

                if indicator.value:
                    evidence_lines.append(
                        f"Value: {indicator.value}"
                    )

            findings.append(
                Finding(
                    title=(
                        "API security indicator: "
                        f"{indicator_type.value.replace('_', ' ')}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=(
                        f"{description} Further validation is "
                        "required to determine whether the observed "
                        "behavior represents an exploitable security "
                        "issue."
                    ),
                    evidence="\n".join(evidence_lines),
                    remediation=self.REMEDIATION,
                    cwe="CWE-200",
                    owasp="API3:2023",
                )
            )

        return findings
