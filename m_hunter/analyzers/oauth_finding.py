from m_hunter.analyzers.oauth import (
    OAuthAnalysis,
    OAuthIndicatorType,
)
from m_hunter.core.finding import Finding


class OAuthFindingAnalyzer:
    """Converts OAuth analysis indicators into structured findings."""

    METADATA = {
        OAuthIndicatorType.REDIRECT_URI: (
            "OAuth redirect URI requires strict allowlist validation.",
            "Medium",
            "Medium",
            "CWE-601",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.STATE_PARAMETER: (
            "OAuth state parameter detected.",
            "Info",
            "High",
            "CWE-352",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.NONCE_PARAMETER: (
            "OAuth nonce parameter detected.",
            "Info",
            "High",
            "CWE-352",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.RESPONSE_TYPE: (
            "OAuth response type detected.",
            "Info",
            "High",
            "CWE-287",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.GRANT_TYPE: (
            "OAuth grant type detected.",
            "Info",
            "High",
            "CWE-287",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.CLIENT_ID: (
            "OAuth client identifier detected.",
            "Info",
            "High",
            "CWE-200",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.SCOPE: (
            "OAuth scope detected.",
            "Info",
            "High",
            "CWE-200",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.TOKEN_IN_URL: (
            "OAuth token-like value appears in URL data.",
            "High",
            "High",
            "CWE-598",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.OPEN_REDIRECT_INDICATOR: (
            "OAuth redirect URI requires open-redirect validation.",
            "Medium",
            "Medium",
            "CWE-601",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.WEAK_STATE_INDICATOR: (
            "OAuth state value appears unusually weak.",
            "Medium",
            "Medium",
            "CWE-330",
            "OWASP A07:2021",
        ),
        OAuthIndicatorType.MISSING_NONCE_INDICATOR: (
            "OAuth nonce was expected but was not observed.",
            "Medium",
            "Medium",
            "CWE-352",
            "OWASP A07:2021",
        ),
    }

    DEFAULT_REMEDIATION = (
        "Validate OAuth configuration against the authorization server "
        "requirements. Use strict redirect URI allowlists, protect "
        "authorization responses with appropriate state and nonce values, "
        "and avoid exposing tokens in URLs."
    )

    def analyze(
        self,
        analysis: OAuthAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, OAuthAnalysis):
            raise TypeError(
                "analysis must be an OAuthAnalysis"
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
        grouped: dict[OAuthIndicatorType, list] = {}

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

            evidence = "\n".join(
                dict.fromkeys(evidence_lines)
            )

            if names:
                evidence += (
                    "\nParameters: "
                    + ", ".join(dict.fromkeys(names))
                )

            if values:
                evidence += (
                    "\nValues: "
                    + ", ".join(dict.fromkeys(values))
                )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=(
                        "OAuth-related behavior was observed. "
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
