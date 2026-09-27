from __future__ import annotations

from m_hunter.core.finding import Finding


class CacheControlSecurityFinding:
    """Build Finding objects from Cache-Control security indicators."""

    METADATA = {
        "PUBLIC_SENSITIVE_CONTENT": {
            "title": "Sensitive Content Is Publicly Cacheable",
            "severity": "High",
            "confidence": "High",
            "cwe": "CWE-524",
            "owasp": "A05:2021",
            "description": (
                "Sensitive content appears to be publicly cacheable, which may "
                "allow shared caches to store and serve sensitive responses."
            ),
            "remediation": (
                "Use private or no-store caching directives for sensitive "
                "responses and ensure cache behavior matches the application's "
                "security requirements."
            ),
        },
        "MISSING_VARY": {
            "title": "Missing Vary Header on Sensitive Cacheable Response",
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-525",
            "owasp": "A05:2021",
            "description": (
                "A sensitive cacheable response does not define an appropriate "
                "Vary header, which may increase the risk of serving a response "
                "across differing request contexts."
            ),
            "remediation": (
                "Define an appropriate Vary header for request headers that "
                "affect the response representation or caching behavior."
            ),
        },
        "CONFLICTING_CACHE_DIRECTIVES": {
            "title": "Conflicting Cache-Control Directives",
            "severity": "Medium",
            "confidence": "High",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
            "description": (
                "The response contains conflicting Cache-Control directives "
                "that may lead to inconsistent cache behavior."
            ),
            "remediation": (
                "Remove conflicting directives and define one clear, intentional "
                "cache policy for the response."
            ),
        },
        "MULTIPLE_CACHE_CONTROL": {
            "title": "Multiple Cache-Control Headers",
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
            "description": (
                "Multiple Cache-Control headers were detected. Different "
                "intermediaries may interpret combined cache directives "
                "differently."
            ),
            "remediation": (
                "Return a single authoritative Cache-Control header containing "
                "the complete intended caching policy."
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
            if indicator.type not in cls.METADATA:
                continue

            findings.append(
                cls.build(
                    indicator.type,
                    target,
                    endpoint=endpoint,
                    evidence=indicator.value,
                )
            )

        return findings
