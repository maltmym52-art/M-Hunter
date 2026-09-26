from m_hunter.analyzers.jwt import JWTAnalysis, JWTIndicatorType
from m_hunter.core.finding import Finding


class JWTFindingAnalyzer:
    METADATA = {
        JWTIndicatorType.JWT: (
            "JWT detected",
            "Info",
            "High",
            None,
            "OWASP A07:2021",
        ),
        JWTIndicatorType.ALGORITHM: (
            "JWT algorithm detected",
            "Info",
            "High",
            None,
            "OWASP A07:2021",
        ),
        JWTIndicatorType.NONE_ALGORITHM: (
            "JWT 'none' algorithm indicator detected",
            "Critical",
            "High",
            "CWE-327",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.WEAK_ALGORITHM: (
            "Weak JWT algorithm indicator detected",
            "High",
            "High",
            "CWE-327",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.MISSING_EXPIRATION: (
            "JWT missing expiration claim",
            "Medium",
            "Medium",
            "CWE-613",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.LONG_LIVED_TOKEN: (
            "Long-lived JWT indicator detected",
            "Medium",
            "Medium",
            "CWE-613",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.MISSING_ISSUER: (
            "JWT missing issuer claim",
            "Low",
            "Medium",
            "CWE-345",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.MISSING_AUDIENCE: (
            "JWT missing audience claim",
            "Low",
            "Medium",
            "CWE-345",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.MISSING_NOT_BEFORE: (
            "JWT missing not-before claim",
            "Low",
            "Medium",
            "CWE-613",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.MISSING_ISSUED_AT: (
            "JWT missing issued-at claim",
            "Low",
            "Medium",
            "CWE-613",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.JWT_IN_URL: (
            "JWT exposed in URL",
            "High",
            "High",
            "CWE-598",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.JWT_IN_COOKIE: (
            "JWT stored in cookie",
            "Info",
            "High",
            None,
            "OWASP A07:2021",
        ),
        JWTIndicatorType.JWT_IN_AUTHORIZATION: (
            "JWT supplied through Authorization header",
            "Info",
            "High",
            None,
            "OWASP A07:2021",
        ),
        JWTIndicatorType.SENSITIVE_DATA: (
            "Sensitive data detected in JWT claims",
            "High",
            "High",
            "CWE-200",
            "OWASP A07:2021",
        ),
        JWTIndicatorType.INVALID_STRUCTURE: (
            "Invalid JWT structure indicator detected",
            "Medium",
            "Medium",
            None,
            "OWASP A07:2021",
        ),
    }

    REMEDIATION = (
        "Validate JWT signatures and algorithms server-side, reject unsafe "
        "algorithm configurations, enforce appropriate token expiration and "
        "claim validation, avoid placing tokens in URLs, and avoid storing "
        "unnecessary sensitive information inside JWT payloads."
    )

    def analyze(
        self,
        *,
        analysis: JWTAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, JWTAnalysis):
            raise TypeError("analysis must be a JWTAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        findings: list[Finding] = []

        for indicator_type in sorted(
            analysis.types,
            key=lambda item: item.value,
        ):
            metadata = self.METADATA.get(indicator_type)

            if metadata is None:
                continue

            title, severity, confidence, cwe, owasp = metadata

            indicators = [
                indicator
                for indicator in analysis.indicators
                if indicator.type == indicator_type
            ]

            evidence_lines = [
                indicator.evidence
                for indicator in indicators
            ]

            details: list[str] = []

            for indicator in indicators:
                if indicator.name is not None:
                    details.append(f"name={indicator.name}")

                if indicator.value is not None:
                    details.append(f"value={indicator.value}")

            evidence = "\n".join(evidence_lines)

            if details:
                evidence += "\n" + "\n".join(details)

            description = (
                f"{title}. "
                "This is an analytical JWT security indicator and "
                "does not by itself prove a vulnerability. Controlled "
                "validation of JWT behavior and server-side verification "
                "is required."
            )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=description,
                    evidence=evidence,
                    remediation=self.REMEDIATION,
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
