from m_hunter.analyzers.session import (
    SessionAnalysis,
    SessionIndicatorType,
)
from m_hunter.core.finding import Finding


class SessionFindingAnalyzer:
    METADATA = {
        SessionIndicatorType.SESSION_COOKIE: (
            "Session cookie detected",
            "Info",
            "High",
            None,
            "OWASP A07:2021",
        ),
        SessionIndicatorType.SESSION_ID_IN_URL: (
            "Session identifier exposed in URL",
            "Medium",
            "High",
            "CWE-598",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.SESSION_TOKEN: (
            "Session token detected",
            "Info",
            "High",
            "CWE-384",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.SESSION_FIXATION_INDICATOR: (
            "Session fixation indicator detected",
            "High",
            "Medium",
            "CWE-384",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.SESSION_ROTATION: (
            "Session rotation indicator detected",
            "Info",
            "High",
            "CWE-384",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.SESSION_TIMEOUT: (
            "Session timeout indicator detected",
            "Info",
            "High",
            "CWE-613",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.SESSION_LOGOUT: (
            "Session logout indicator detected",
            "Info",
            "High",
            "CWE-613",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.SESSION_INVALIDATION: (
            "Session invalidation indicator detected",
            "Info",
            "High",
            "CWE-613",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.LONG_LIVED_SESSION: (
            "Long-lived session indicator detected",
            "Medium",
            "Medium",
            "CWE-613",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.CONCURRENT_SESSION: (
            "Concurrent session indicator detected",
            "Info",
            "Medium",
            "CWE-613",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.TOKEN_EXPOSURE: (
            "Session token exposure indicator detected",
            "High",
            "High",
            "CWE-598",
            "OWASP A07:2021",
        ),
        SessionIndicatorType.WEAK_SESSION_COOKIE_NAME: (
            "Weak session cookie naming indicator detected",
            "Low",
            "Medium",
            None,
            "OWASP A07:2021",
        ),
    }

    REMEDIATION = (
        "Validate session lifecycle behavior server-side. "
        "Rotate session identifiers after authentication and privilege changes, "
        "invalidate sessions on logout, enforce appropriate expiration and "
        "idle timeouts, avoid exposing session identifiers in URLs, and "
        "protect session tokens from unnecessary disclosure."
    )

    def analyze(
        self,
        *,
        analysis: SessionAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, SessionAnalysis):
            raise TypeError("analysis must be a SessionAnalysis")
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

            details = []
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
                "This is an analytical session-security indicator and "
                "does not by itself prove a vulnerability. Controlled "
                "validation of session behavior is required."
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
