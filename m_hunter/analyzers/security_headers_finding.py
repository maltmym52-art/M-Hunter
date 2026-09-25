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

    ISSUE_METADATA = {
        "missing_max_age": {
            "title": "Strict-Transport-Security Missing max-age",
            "severity": "Medium",
            "confidence": "High",
            "description": (
                "The Strict-Transport-Security header is present "
                "but does not define a max-age directive."
            ),
            "remediation": (
                "Configure Strict-Transport-Security with an appropriate "
                "max-age value."
            ),
            "cwe": "CWE-319",
            "owasp": "A05:2021",
        },
        "short_max_age": {
            "title": "Strict-Transport-Security max-age Is Too Short",
            "severity": "Low",
            "confidence": "High",
            "description": (
                "The Strict-Transport-Security header uses a "
                "short max-age value."
            ),
            "remediation": (
                "Use an appropriate long-lived HSTS max-age after "
                "confirming the application is fully HTTPS-compatible."
            ),
            "cwe": "CWE-319",
            "owasp": "A05:2021",
        },
        "invalid_max_age": {
            "title": "Invalid Strict-Transport-Security max-age",
            "severity": "Medium",
            "confidence": "High",
            "description": (
                "The Strict-Transport-Security header contains "
                "an invalid max-age value."
            ),
            "remediation": (
                "Configure max-age using a valid numeric value."
            ),
            "cwe": "CWE-319",
            "owasp": "A05:2021",
        },
        "invalid_value": {
            "title": "Invalid Security Header Value",
            "severity": "Medium",
            "confidence": "High",
            "description": (
                "A security header is present but uses a value "
                "that does not match the expected format."
            ),
            "remediation": (
                "Review the security header configuration and "
                "use a standards-compliant value."
            ),
            "cwe": "CWE-693",
            "owasp": "A05:2021",
        },
        "empty_value": {
            "title": "Empty Security Header Value",
            "severity": "Medium",
            "confidence": "High",
            "description": (
                "A security header is present but has an empty value."
            ),
            "remediation": (
                "Configure the security header with an appropriate "
                "non-empty value."
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

            findings.append(
                self.create_finding(
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
            )

        for issue in analysis.get("issues", []):
            issue_name = issue.get("issue")
            header_name = issue.get("header")

            metadata = self.ISSUE_METADATA.get(issue_name)

            if metadata is None:
                continue

            value = analysis.get("present", {}).get(
                header_name,
                "",
            )

            evidence = (
                f"HTTP response from {endpoint or target} "
                f"contains {header_name}: {value!r}; "
                f"detected issue: {issue_name}."
            )

            findings.append(
                self.create_finding(
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
            )

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
