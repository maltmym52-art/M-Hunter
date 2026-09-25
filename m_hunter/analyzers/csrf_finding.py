from collections import defaultdict

from m_hunter.analyzers.csrf import (
    CSRFAnalysis,
    CSRFIndicatorType,
)
from m_hunter.core.finding import Finding


class CSRFFindingAnalyzer:
    """
    Convert CSRF analysis indicators into structured findings.

    Indicators are evidence for further validation and do not by
    themselves confirm an exploitable CSRF vulnerability.
    """

    METADATA = {
        CSRFIndicatorType.FORM_WITHOUT_CSRF_TOKEN: (
            "Medium",
            "Medium",
        ),
        CSRFIndicatorType.SAME_SITE_COOKIE_MISSING: (
            "Medium",
            "Medium",
        ),
        CSRFIndicatorType.ORIGIN_VALIDATION_MISSING: (
            "Low",
            "Low",
        ),
        CSRFIndicatorType.REFERER_VALIDATION_MISSING: (
            "Low",
            "Low",
        ),
        CSRFIndicatorType.STATE_CHANGING_METHOD: (
            "Info",
            "High",
        ),
    }

    def analyze(
        self,
        analysis: CSRFAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, CSRFAnalysis):
            raise TypeError("analysis must be a CSRFAnalysis instance")

        findings: list[Finding] = []

        grouped: dict[CSRFIndicatorType, list[str]] = defaultdict(list)

        for indicator in analysis.indicators:
            grouped[indicator.type].append(indicator.evidence)

        for indicator_type, evidence_items in grouped.items():
            severity, confidence = self.METADATA.get(
                indicator_type,
                ("Low", "Low"),
            )

            if indicator_type == CSRFIndicatorType.FORM_WITHOUT_CSRF_TOKEN:
                title = "Potential CSRF protection weakness: missing CSRF token"
                description = (
                    "A state-changing request or form was observed without "
                    "a detected CSRF token. This is an indicator that may "
                    "require controlled validation of CSRF protections."
                )
                remediation = (
                    "Use unpredictable CSRF tokens for state-changing "
                    "requests and validate them server-side."
                )

            elif indicator_type == CSRFIndicatorType.SAME_SITE_COOKIE_MISSING:
                title = "Session cookie without detected SameSite protection"
                description = (
                    "A session cookie was observed without detected "
                    "SameSite metadata. This can increase CSRF exposure "
                    "depending on the application's other protections."
                )
                remediation = (
                    "Configure appropriate SameSite attributes on "
                    "authentication and session cookies."
                )

            elif indicator_type == CSRFIndicatorType.ORIGIN_VALIDATION_MISSING:
                title = "Origin validation signal missing"
                description = (
                    "The analyzed state-changing request context did not "
                    "contain an Origin header. This alone does not prove "
                    "that server-side Origin validation is absent."
                )
                remediation = (
                    "Where appropriate, validate the Origin header "
                    "server-side for sensitive state-changing operations."
                )

            elif indicator_type == CSRFIndicatorType.REFERER_VALIDATION_MISSING:
                title = "Referer validation signal missing"
                description = (
                    "The analyzed state-changing request context did not "
                    "contain a Referer header. This alone does not prove "
                    "that server-side Referer validation is absent."
                )
                remediation = (
                    "Where appropriate, use strict server-side request "
                    "origin validation as part of CSRF defenses."
                )

            else:
                title = "State-changing request detected"
                description = (
                    "A state-changing HTTP method was observed. This is "
                    "context for evaluating CSRF protections, not evidence "
                    "of a vulnerability."
                )
                remediation = (
                    "Ensure state-changing operations have appropriate "
                    "CSRF protections."
                )

            evidence = (
                f"Indicator: {indicator_type.value}\n"
                f"Target: {target}\n"
                f"Endpoint: {endpoint or 'unknown'}\n"
                f"Evidence count: {len(evidence_items)}\n"
                + "\n".join(
                    f"- {item}" for item in evidence_items
                )
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
                    remediation=remediation,
                    cwe="CWE-352",
                    owasp="A01:2021",
                )
            )

        return findings
