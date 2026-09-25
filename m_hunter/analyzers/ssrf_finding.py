from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.ssrf import SSRFAnalysis, SSRFIndicatorType
from m_hunter.core.finding import Finding


class SSRFFindingAnalyzer(FindingAnalyzer):
    name = "ssrf_findings"
    description = "Converts SSRF indicators into findings"

    INDICATOR_METADATA = {
        SSRFIndicatorType.INTERNAL_IP: {
            "title": "Internal Network Address Indicator",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The response contains an internal or private IP "
                "address associated with controlled SSRF testing. "
                "This is an indicator requiring further validation."
            ),
        },
        SSRFIndicatorType.INTERNAL_HOSTNAME: {
            "title": "Internal Hostname Indicator",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The response contains an internal hostname "
                "associated with controlled SSRF testing. "
                "The indicator alone does not prove SSRF."
            ),
        },
        SSRFIndicatorType.LOOPBACK: {
            "title": "Loopback Address Indicator",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "The response contains a loopback address associated "
                "with controlled SSRF testing."
            ),
        },
        SSRFIndicatorType.LINK_LOCAL: {
            "title": "Link-Local Address Indicator",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "The response contains a link-local address that may "
                "be relevant to server-side request behavior."
            ),
        },
        SSRFIndicatorType.CLOUD_METADATA: {
            "title": "Cloud Metadata Endpoint Indicator",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "The response contains a cloud metadata endpoint or "
                "metadata-related indicator. Further controlled "
                "validation is required."
            ),
        },
        SSRFIndicatorType.LOCAL_FILE: {
            "title": "Local File URI Indicator",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "The response contains a local file URI associated "
                "with controlled testing. This does not by itself "
                "prove server-side file access."
            ),
        },
    }

    REMEDIATION = (
        "Validate and restrict server-side URL destinations using "
        "an allowlist. Block loopback, private, link-local, and "
        "metadata destinations after DNS resolution and prevent "
        "unsafe URI schemes where they are not required."
    )

    def analyze(
        self,
        analysis: SSRFAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, SSRFAnalysis):
            raise TypeError(
                "analysis must be an SSRFAnalysis"
            )

        if not analysis.detected:
            return []

        findings: list[Finding] = []

        for indicator_type in analysis.types:
            metadata = self.INDICATOR_METADATA.get(
                indicator_type,
                {
                    "title": "SSRF Indicator",
                    "severity": "Low",
                    "confidence": "Low",
                    "description": (
                        "An SSRF-related indicator was detected "
                        "and requires further validation."
                    ),
                },
            )

            indicators = [
                indicator
                for indicator in analysis.indicators
                if indicator.type == indicator_type
            ]

            evidence = [
                f"indicator type: {indicator_type}",
                f"indicator count: {len(indicators)}",
            ]

            for indicator in indicators:
                evidence.append(
                    f"evidence: {indicator.evidence}"
                )

            findings.append(
                self.create_finding(
                    title=metadata["title"],
                    severity=metadata["severity"],
                    confidence=metadata["confidence"],
                    target=target,
                    endpoint=endpoint,
                    parameter=parameter,
                    description=metadata["description"],
                    evidence="; ".join(evidence),
                    remediation=self.REMEDIATION,
                    cwe="CWE-918",
                    owasp="A10:2021",
                )
            )

        return findings
