from m_hunter.analyzers.saml import (
    SAMLAnalysis,
    SAMLIndicatorType,
)
from m_hunter.core.finding import Finding


class SAMLFindingAnalyzer:
    """Converts SAML analysis indicators into structured findings."""

    METADATA = {
        SAMLIndicatorType.SAML_RESPONSE: (
            "SAML response detected.",
            "Info",
            "High",
            "CWE-287",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.RELAY_STATE: (
            "SAML RelayState detected and requires validation.",
            "Low",
            "Medium",
            "CWE-601",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.ISSUER: (
            "SAML issuer detected.",
            "Info",
            "High",
            "CWE-290",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.AUDIENCE: (
            "SAML audience restriction detected.",
            "Info",
            "High",
            "CWE-287",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.DESTINATION: (
            "SAML destination detected and requires validation.",
            "Low",
            "Medium",
            "CWE-601",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.ACS_URL: (
            "SAML ACS endpoint detected and requires strict validation.",
            "Low",
            "Medium",
            "CWE-601",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.SIGNATURE: (
            "SAML signature detected.",
            "Info",
            "High",
            "CWE-347",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.SIGNATURE_ALGORITHM: (
            "SAML signature algorithm detected.",
            "Info",
            "High",
            "CWE-327",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.ASSERTION: (
            "SAML assertion detected.",
            "Info",
            "High",
            "CWE-287",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.NAME_ID: (
            "SAML NameID detected.",
            "Info",
            "High",
            "CWE-200",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.NOT_BEFORE: (
            "SAML NotBefore condition detected.",
            "Info",
            "High",
            "CWE-613",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.NOT_ON_OR_AFTER: (
            "SAML NotOnOrAfter condition detected.",
            "Info",
            "High",
            "CWE-613",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.IN_RESPONSE_TO: (
            "SAML InResponseTo value detected.",
            "Info",
            "High",
            "CWE-352",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.ENCRYPTION: (
            "SAML encryption indicator detected.",
            "Info",
            "High",
            "CWE-311",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.UNSIGNED_ASSERTION: (
            "SAML assertion appears unsigned.",
            "High",
            "High",
            "CWE-347",
            "OWASP A07:2021",
        ),
        SAMLIndicatorType.WEAK_SIGNATURE_ALGORITHM: (
            "Weak SAML signature algorithm detected.",
            "High",
            "High",
            "CWE-327",
            "OWASP A07:2021",
        ),
    }

    DEFAULT_REMEDIATION = (
        "Validate SAML messages against the identity provider and service "
        "provider configuration. Enforce signature verification, strict "
        "issuer/audience/destination/ACS validation, appropriate assertion "
        "lifetime checks, and modern signature algorithms."
    )

    def analyze(
        self,
        analysis: SAMLAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, SAMLAnalysis):
            raise TypeError(
                "analysis must be a SAMLAnalysis"
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
        grouped: dict[SAMLIndicatorType, list] = {}

        for indicator in analysis.indicators:
            grouped.setdefault(indicator.type, []).append(
                indicator
            )

        for indicator_type, indicators in grouped.items():
            metadata = self.METADATA.get(indicator_type)

            if metadata is None:
                continue

            (
                title,
                severity,
                confidence,
                cwe,
                owasp,
            ) = metadata

            evidence_lines = [
                indicator.evidence
                for indicator in indicators
                if indicator.evidence
            ]

            names = [
                indicator.name
                for indicator in indicators
                if indicator.name
            ]

            values = [
                indicator.value
                for indicator in indicators
                if indicator.value
            ]

            evidence_parts = list(
                dict.fromkeys(evidence_lines)
            )

            if names:
                evidence_parts.append(
                    "Parameters: "
                    + ", ".join(dict.fromkeys(names))
                )

            if values:
                evidence_parts.append(
                    "Values: "
                    + ", ".join(dict.fromkeys(values))
                )

            evidence = "\n".join(evidence_parts)

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=(
                        "SAML-related behavior was observed. "
                        "This finding represents an analytical indicator "
                        "and requires contextual validation before being "
                        "treated as a confirmed vulnerability."
                    ),
                    evidence=evidence,
                    remediation=self.DEFAULT_REMEDIATION,
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
