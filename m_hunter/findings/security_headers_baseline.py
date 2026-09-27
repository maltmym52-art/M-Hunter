from __future__ import annotations

from m_hunter.core.finding import Finding


class SecurityHeadersBaselineFinding:
    """Build Finding objects from security-header baseline indicators."""

    METADATA = {
        "X_CONTENT_TYPE_OPTIONS_MISSING": {
            "title": "X-Content-Type-Options Header Missing",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-693",
            "owasp": "A05:2021",
            "description": (
                "The response does not define X-Content-Type-Options, "
                "leaving MIME-sniffing protections unspecified."
            ),
            "remediation": (
                "Set X-Content-Type-Options to nosniff on applicable responses."
            ),
        },
        "NOSNIFF_MISSING": {
            "title": "MIME Sniffing Protection Missing",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-693",
            "owasp": "A05:2021",
            "description": (
                "The response does not provide the nosniff protection "
                "normally supplied by X-Content-Type-Options."
            ),
            "remediation": (
                "Return X-Content-Type-Options: nosniff where appropriate."
            ),
        },
        "X_XSS_PROTECTION_UNSAFE": {
            "title": "Legacy X-XSS-Protection Configuration",
            "severity": "Low",
            "confidence": "High",
            "cwe": "CWE-693",
            "owasp": "A05:2021",
            "description": (
                "The response enables the legacy X-XSS-Protection mechanism, "
                "which is obsolete and may introduce inconsistent browser behavior."
            ),
            "remediation": (
                "Prefer modern browser security controls such as CSP and "
                "avoid relying on legacy X-XSS-Protection behavior."
            ),
        },
        "EXPECT_CT_DEPRECATED": {
            "title": "Deprecated Expect-CT Header",
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
            "description": (
                "The response uses the deprecated Expect-CT header."
            ),
            "remediation": (
                "Remove Expect-CT and rely on current certificate validation "
                "and browser security mechanisms."
            ),
        },
        "CROSS_DOMAIN_POLICY_UNSAFE": {
            "title": "Broad Cross-Domain Policy",
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-942",
            "owasp": "A05:2021",
            "description": (
                "The cross-domain policy permits broader access than a "
                "restrictive policy configuration."
            ),
            "remediation": (
                "Use the most restrictive cross-domain policy compatible "
                "with the application's requirements."
            ),
        },
        "CLEAR_SITE_DATA_WILDCARD": {
            "title": "Clear-Site-Data Wildcard Usage",
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
            "description": (
                "Clear-Site-Data uses a wildcard, which can clear multiple "
                "categories of client-side data."
            ),
            "remediation": (
                "Specify only the Clear-Site-Data categories required by "
                "the application's intended behavior."
            ),
        },
        "MULTIPLE_SECURITY_HEADER": {
            "title": "Multiple Security Header Instances",
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
            "description": (
                "Multiple instances of a security-related header were detected."
            ),
            "remediation": (
                "Return one authoritative security-header value unless "
                "multiple instances are explicitly required and consistently handled."
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
