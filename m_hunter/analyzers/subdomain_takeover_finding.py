from m_hunter.analyzers.subdomain_takeover import (
    SubdomainTakeoverAnalysis,
    SubdomainTakeoverIndicator,
    SubdomainTakeoverIndicatorType,
)
from m_hunter.core.finding import Finding


class SubdomainTakeoverFindingAnalyzer:
    name = "subdomain_takeover_finding"

    _METADATA = {
        SubdomainTakeoverIndicatorType.CNAME_PRESENT: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.CNAME_EXTERNAL: {
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.CNAME_DANGLING: {
            "severity": "High",
            "confidence": "High",
            "cwe": "CWE-350",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.NXDOMAIN: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-350",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.DNS_ERROR: {
            "severity": "Low",
            "confidence": "Low",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-350",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE: {
            "severity": "High",
            "confidence": "High",
            "cwe": "CWE-350",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.HOST_NOT_FOUND: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-350",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.RESOURCE_NOT_FOUND: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-350",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.SERVICE_UNAVAILABLE: {
            "severity": "Low",
            "confidence": "Low",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
        },
        SubdomainTakeoverIndicatorType.HTTP_404: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-404",
            "owasp": "A05:2021",
        },
    }

    def create_findings(
        self,
        analysis: SubdomainTakeoverAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        return [
            self._create_finding(
                indicator,
                target=target,
                endpoint=endpoint,
                parameter=parameter,
            )
            for indicator in analysis.indicators
        ]

    def _create_finding(
        self,
        indicator: SubdomainTakeoverIndicator,
        *,
        target: str,
        endpoint: str | None,
        parameter: str | None,
    ) -> Finding:
        metadata = self._METADATA[indicator.type]

        return Finding(
            title=self._title(indicator),
            severity=metadata["severity"],
            confidence=metadata["confidence"],
            target=target,
            endpoint=endpoint,
            parameter=parameter,
            description=(
                f"Detected a subdomain takeover-related indicator: "
                f"{indicator.name}. Observed value: {indicator.value}. "
                "This analytical indicator does not by itself prove that "
                "the subdomain is vulnerable to takeover."
            ),
            evidence=f"{indicator.name}: {indicator.value}",
            remediation=(
                "Remove stale DNS records and unused third-party service "
                "bindings. Verify that CNAME targets remain owned and "
                "controlled, and remove references to deprovisioned "
                "resources."
            ),
            cwe=metadata["cwe"],
            owasp=metadata["owasp"],
        )

    @staticmethod
    def _title(indicator: SubdomainTakeoverIndicator) -> str:
        titles = {
            SubdomainTakeoverIndicatorType.CNAME_PRESENT:
                "CNAME Record Detected",
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL:
                "External CNAME Target Detected",
            SubdomainTakeoverIndicatorType.CNAME_DANGLING:
                "Potential Dangling CNAME",
            SubdomainTakeoverIndicatorType.NXDOMAIN:
                "NXDOMAIN Subdomain Indicator",
            SubdomainTakeoverIndicatorType.DNS_ERROR:
                "DNS Resolution Error",
            SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET:
                "Unresolved CNAME Target",
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT:
                "Third-Party Service Fingerprint",
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE:
                "Potential Subdomain Takeover Signature",
            SubdomainTakeoverIndicatorType.HOST_NOT_FOUND:
                "Host Not Found Indicator",
            SubdomainTakeoverIndicatorType.RESOURCE_NOT_FOUND:
                "Remote Resource Not Found",
            SubdomainTakeoverIndicatorType.SERVICE_UNAVAILABLE:
                "Third-Party Service Unavailable",
            SubdomainTakeoverIndicatorType.HTTP_404:
                "HTTP 404 Subdomain Indicator",
        }

        return titles[indicator.type]

    def analyze(
        self,
        analysis: SubdomainTakeoverAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        return self.create_findings(
            analysis,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
        )
