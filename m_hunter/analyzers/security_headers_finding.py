from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.security_headers import SecurityHeadersAnalyzer
from m_hunter.core.finding import Finding


class SecurityHeadersFindingAnalyzer(FindingAnalyzer):
    name = "security_headers_findings"
    description = "Converts security header analysis into findings"

    HEADER_METADATA = {
        "strict-transport-security": {
            "title": "Missing Strict-Transport-Security Header",
            "severity": "Medium",
            "confidence": "High",
            "description": (
                "The HTTP response does not include "
                "the Strict-Transport-Security header."
            ),
            "remediation": (
                "Configure Strict-Transport-Security for HTTPS responses "
                "with an appropriate max-age and deployment policy."
            ),
            "cwe": "CWE-319",
            "owasp": "A05:2021",
        },
        "content-security-policy": {
            "title": "Missing Content-Security-Policy Header",
            "severity": "Medium",
            "confidence": "High",
            "description": (
                "The HTTP response does not include "
                "a Content-Security-Policy header."
            ),
            "remediation": (
                "Define and deploy an appropriate Content-Security-Policy "
                "that restricts untrusted resource execution."
            ),
            "cwe": "CWE-693",
            "owasp": "A05:2021",
        },
        "x-content-type-options": {
            "title": "Missing X-Content-Type-Options Header",
            "severity": "Low",
            "confidence": "High",
            "description": (
                "The HTTP response does not include "
                "the X-Content-Type-Options header."
            ),
            "remediation": (
                "Set X-Content-Type-Options to nosniff "
                "where appropriate."
            ),
            "cwe": "CWE-693",
            "owasp": "A05:2021",
        },
        "x-frame-options": {
            "title": "Missing X-Frame-Options Header",
            "severity": "Low",
            "confidence": "High",
            "description": (
                "The HTTP response does not include "
                "the X-Frame-Options header."
            ),
            "remediation": (
                "Configure X-Frame-Options or an appropriate "
                "CSP frame-ancestors policy."
            ),
            "cwe": "CWE-1021",
            "owasp": "A05:2021",
        },
        "referrer-policy": {
            "title": "Missing Referrer-Policy Header",
            "severity": "Low",
            "confidence": "High",
            "description": (
                "The HTTP response does not include "
                "a Referrer-Policy header."
            ),
            "remediation": (
                "Configure an appropriate Referrer-Policy "
                "for the application."
            ),
            "cwe": "CWE-200",
            "owasp": "A05:2021",
        },
        "permissions-policy": {
            "title": "Missing Permissions-Policy Header",
            "severity": "Low",
            "confidence": "High",
            "description": (
                "The HTTP response does not include "
                "a Permissions-Policy header."
            ),
            "remediation": (
                "Configure Permissions-Policy to restrict "
                "browser features that the application does not need."
            ),
            "cwe": "CWE-693",
            "owasp": "A05:2021",
        },
    }

    def analyze(
        self,
        analysis: dict,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for header_name in analysis.get("missing", []):
            metadata = self.HEADER_METADATA.get(header_name)

            if metadata is None:
                continue

            evidence = (
                f"HTTP response from {endpoint or target} "
                f"is missing the {header_name} header."
            )

            finding = self.create_finding(
                title=metadata["title"],
                severity=metadata["severity"],
                confidence=metadata["confidence"],
                target=target,
                endpoint=endpoint,
                description=metadata["description"],
                evidence=evidence,
                remediation=metadata["remediation"],
                cwe=metadata["cwe"],
                owasp=metadata["owasp"],
            )

            findings.append(finding)

        return findings

    def analyze_response(
        self,
        response,
        *,
        target: str | None = None,
        endpoint: str | None = None,
    ) -> list[Finding]:
        analyzer = SecurityHeadersAnalyzer()

        analysis = analyzer.analyze(response)

        resolved_target = target or response.url

        return self.analyze(
            analysis,
            target=resolved_target,
            endpoint=endpoint or response.url,
        )
