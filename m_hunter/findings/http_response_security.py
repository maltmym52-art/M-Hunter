from __future__ import annotations

from m_hunter.core.finding import Finding


class HttpResponseSecurityFinding:
    """Build Finding objects from HTTP response security indicators."""

    METADATA = {
        "SERVER_VERSION_DISCLOSURE": {
            "title": "Server Version Disclosure",
            "severity": "Low",
            "confidence": "High",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "description": (
                "The HTTP response appears to disclose a server product and "
                "version, providing information that may assist reconnaissance."
            ),
            "remediation": (
                "Minimize server banner information and avoid exposing "
                "unnecessary product or version details."
            ),
        },
        "X_POWERED_BY": {
            "title": "Technology Disclosure via X-Powered-By",
            "severity": "Low",
            "confidence": "High",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "description": (
                "The response exposes technology information through the "
                "X-Powered-By header."
            ),
            "remediation": (
                "Remove or minimize the X-Powered-By header in production responses."
            ),
        },
        "DEBUG_DISCLOSURE": {
            "title": "Debug Information Disclosure",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-489",
            "owasp": "A05:2021",
            "description": (
                "The response exposes debug or development information."
            ),
            "remediation": (
                "Disable debug and development modes in production environments "
                "and prevent diagnostic interfaces from being exposed."
            ),
        },
        "STACK_TRACE_DISCLOSURE": {
            "title": "Stack Trace Disclosure",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-209",
            "owasp": "A05:2021",
            "description": (
                "The response exposes stack trace information that may reveal "
                "implementation details, paths, libraries, or framework behavior."
            ),
            "remediation": (
                "Return generic error responses to clients and keep detailed "
                "stack traces in server-side logs."
            ),
        },
        "EXCEPTION_DISCLOSURE": {
            "title": "Exception Details Disclosure",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-209",
            "owasp": "A05:2021",
            "description": (
                "The response exposes detailed exception information."
            ),
            "remediation": (
                "Suppress detailed exception information in production responses "
                "and log diagnostic details securely on the server."
            ),
        },
        "INTERNAL_PATH_DISCLOSURE": {
            "title": "Internal Filesystem Path Disclosure",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "description": (
                "The response reveals an internal filesystem path that may "
                "disclose application structure or deployment details."
            ),
            "remediation": (
                "Avoid returning internal filesystem paths in client-facing "
                "responses and use generic error messages."
            ),
        },
        "INTERNAL_IP_DISCLOSURE": {
            "title": "Internal IP Address Disclosure",
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-200",
            "owasp": "A05:2021",
            "description": (
                "The response reveals internal network addressing information."
            ),
            "remediation": (
                "Avoid exposing internal IP addresses in client-facing responses "
                "unless explicitly required."
            ),
        },
        "DIRECTORY_LISTING": {
            "title": "Directory Listing Disclosure",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-548",
            "owasp": "A05:2021",
            "description": (
                "The response appears to expose a directory listing, potentially "
                "revealing files and application structure."
            ),
            "remediation": (
                "Disable directory indexing and explicitly control which files "
                "and directories are publicly accessible."
            ),
        },
        "ERROR_DETAILS_DISCLOSURE": {
            "title": "Detailed Error Information Disclosure",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-209",
            "owasp": "A05:2021",
            "description": (
                "The response exposes detailed error information that may reveal "
                "implementation details."
            ),
            "remediation": (
                "Use generic client-facing error messages and retain detailed "
                "diagnostics in protected server-side logs."
            ),
        },
    }

    @classmethod
    def build(
        cls,
        indicator_type: str,
        target: str,
        *,
        endpoint: str | None = None,
        evidence: str = "",
    ) -> Finding:
        metadata = cls.METADATA[indicator_type]

        return Finding(
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

    @classmethod
    def from_analysis(
        cls,
        analysis,
        target: str,
        *,
        endpoint: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for indicator in analysis.indicators:
            indicator_type = getattr(indicator.type, "name", indicator.type)

            if indicator_type not in cls.METADATA:
                continue

            findings.append(
                cls.build(
                    indicator_type,
                    target,
                    endpoint=endpoint,
                    evidence=indicator.value or "",
                )
            )

        return findings
