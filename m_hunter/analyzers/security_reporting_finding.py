from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.security_reporting import (
    SecurityReportingAnalysis,
    SecurityReportingIndicatorType,
)
from m_hunter.core.finding import Finding


class SecurityReportingFindingAnalyzer(FindingAnalyzer):
    name = "security_reporting_finding"

    METADATA = {
        SecurityReportingIndicatorType.REPORTING_ENDPOINTS_PRESENT: (
            "Reporting-Endpoints header is present",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING: (
            "Reporting-Endpoints header is missing",
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.REPORT_TO_PRESENT: (
            "Report-To header is present",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.REPORT_TO_MISSING: (
            "Report-To header is missing",
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.ENDPOINT_PRESENT: (
            "Security reporting endpoint is configured",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.GROUP_PRESENT: (
            "Security reporting group is configured",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.CSP_REPORT_ONLY: (
            "Content-Security-Policy-Report-Only is configured",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS: (
            "Reporting-Endpoints contains an invalid definition",
            "Medium",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.INVALID_REPORT_TO: (
            "Report-To contains an invalid configuration",
            "Medium",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.MULTIPLE_REPORTING_ENDPOINTS: (
            "Multiple Reporting-Endpoints headers are present",
            "Low",
            "Medium",
            "CWE-16",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.MULTIPLE_REPORT_TO: (
            "Multiple Report-To headers are present",
            "Low",
            "Medium",
            "CWE-16",
            "A05:2021",
        ),
        SecurityReportingIndicatorType.REPORTING_ENDPOINT_URL: (
            "Security reporting endpoint URL is configured",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
    }

    def analyze(
        self,
        analysis: SecurityReportingAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, SecurityReportingAnalysis):
            raise TypeError(
                "analysis must be an instance of SecurityReportingAnalysis"
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

            (
                title,
                severity,
                confidence,
                cwe,
                owasp,
            ) = metadata

            if indicator.type in {
                SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING,
                SecurityReportingIndicatorType.REPORT_TO_MISSING,
            }:
                evidence = indicator.name
            elif indicator.value:
                evidence = f"{indicator.name}: {indicator.value}"
            else:
                evidence = indicator.name

            description = (
                "The response contains a security reporting configuration "
                "that should be reviewed in the context of the application's "
                "security policy reporting requirements."
            )

            if indicator.type == (
                SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING
            ):
                description = (
                    "The response does not define a Reporting-Endpoints "
                    "header. Modern reporting configurations may use this "
                    "header to define destinations for security reports."
                )

            elif indicator.type == (
                SecurityReportingIndicatorType.REPORT_TO_MISSING
            ):
                description = (
                    "The response does not define a Report-To header. "
                    "Legacy reporting configurations may use this header "
                    "to define reporting groups and destinations."
                )

            elif indicator.type == (
                SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS
            ):
                description = (
                    "The Reporting-Endpoints header contains a definition "
                    "that does not follow the expected endpoint structure."
                )

            elif indicator.type == (
                SecurityReportingIndicatorType.INVALID_REPORT_TO
            ):
                description = (
                    "The Report-To header does not contain the expected "
                    "JSON object structure for reporting configuration."
                )

            elif indicator.type == (
                SecurityReportingIndicatorType.MULTIPLE_REPORTING_ENDPOINTS
            ):
                description = (
                    "Multiple Reporting-Endpoints header values were "
                    "observed. Their interaction should be reviewed for "
                    "consistent reporting behavior."
                )

            elif indicator.type == (
                SecurityReportingIndicatorType.MULTIPLE_REPORT_TO
            ):
                description = (
                    "Multiple Report-To header values were observed. "
                    "Their interaction should be reviewed for consistent "
                    "reporting behavior."
                )

            elif indicator.type == (
                SecurityReportingIndicatorType.CSP_REPORT_ONLY
            ):
                description = (
                    "The response uses Content-Security-Policy-Report-Only, "
                    "which provides a reporting-oriented CSP policy without "
                    "enforcing the policy in the same way as an enforcing CSP."
                )

            remediation = (
                "Configure security reporting deliberately and ensure that "
                "reporting endpoints are valid, trusted, reachable, and "
                "appropriate for the application's security monitoring "
                "requirements."
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
