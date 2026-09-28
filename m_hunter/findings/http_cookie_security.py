from __future__ import annotations

from m_hunter.core.finding import Finding


class HttpCookieSecurityFinding:
    """Build Finding objects from HTTP cookie security indicators."""

    METADATA = {
        "SECURE_MISSING": {
            "title": "Cookie Missing Secure Attribute",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-614",
            "owasp": "A05:2021",
            "description": (
                "A cookie does not use the Secure attribute and may therefore "
                "be transmitted over an unencrypted HTTP connection."
            ),
            "remediation": (
                "Set the Secure attribute on cookies that contain sensitive "
                "or session-related information."
            ),
        },
        "HTTPONLY_MISSING": {
            "title": "Cookie Missing HttpOnly Attribute",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-1004",
            "owasp": "A05:2021",
            "description": (
                "A cookie does not use HttpOnly, allowing client-side scripts "
                "to access it when the browser permits."
            ),
            "remediation": (
                "Set HttpOnly on sensitive cookies that do not need to be "
                "accessible through client-side JavaScript."
            ),
        },
        "SAMESITE_MISSING": {
            "title": "Cookie Missing SameSite Attribute",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-1275",
            "owasp": "A01:2021",
            "description": (
                "A cookie does not explicitly define SameSite behavior, "
                "leaving cross-site cookie handling dependent on browser defaults."
            ),
            "remediation": (
                "Set an explicit SameSite value appropriate for the application's "
                "cross-site requirements, preferably Strict or Lax where possible."
            ),
        },
        "SAMESITE_NONE": {
            "title": "Cookie Uses SameSite=None",
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-1275",
            "owasp": "A01:2021",
            "description": (
                "The cookie explicitly permits cross-site sending through "
                "SameSite=None."
            ),
            "remediation": (
                "Use SameSite=Strict or SameSite=Lax where cross-site cookie "
                "behavior is not required."
            ),
        },
        "SAMESITE_INVALID": {
            "title": "Invalid SameSite Cookie Attribute",
            "severity": "Low",
            "confidence": "High",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
            "description": (
                "The cookie specifies an invalid SameSite value."
            ),
            "remediation": (
                "Use a valid SameSite value: Strict, Lax, or None."
            ),
        },
        "DOMAIN_BROAD": {
            "title": "Broad Cookie Domain Scope",
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
            "description": (
                "The cookie Domain attribute is broadly scoped and may expose "
                "the cookie to additional subdomains."
            ),
            "remediation": (
                "Restrict the Domain attribute to the smallest scope required "
                "by the application."
            ),
        },
        "PATH_BROAD": {
            "title": "Broad Cookie Path Scope",
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
            "description": (
                "The cookie Path attribute is scoped to the entire site."
            ),
            "remediation": (
                "Restrict the cookie Path to the smallest application path "
                "that requires access to the cookie."
            ),
        },
        "LONG_LIVED_COOKIE": {
            "title": "Long-Lived Cookie",
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-613",
            "owasp": "A07:2021",
            "description": (
                "The cookie lifetime exceeds one year, increasing the period "
                "during which a compromised persistent cookie may remain usable."
            ),
            "remediation": (
                "Use an appropriate cookie lifetime and rotate or invalidate "
                "long-lived authentication material when necessary."
            ),
        },
        "PREFIX_VIOLATION": {
            "title": "Cookie Prefix Security Requirement Violation",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
            "description": (
                "A cookie using a security-sensitive prefix does not satisfy "
                "the corresponding prefix requirements."
            ),
            "remediation": (
                "Ensure __Host- and __Secure- cookies comply with their "
                "required Secure, Domain, and Path restrictions."
            ),
        },
        "DUPLICATE_COOKIE": {
            "title": "Duplicate Cookie Name Detected",
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-20",
            "owasp": "A05:2021",
            "description": (
                "Multiple cookies with the same name were detected, which can "
                "create ambiguous cookie selection behavior."
            ),
            "remediation": (
                "Avoid duplicate cookie names across scopes unless explicitly "
                "required and ensure cookie precedence is well understood."
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
