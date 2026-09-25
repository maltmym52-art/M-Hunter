from m_hunter.analyzers.mfa import (
    MFAAnalysis,
    MFAIndicatorType,
)
from m_hunter.core.finding import Finding


class MFAFindingAnalyzer:
    """Convert MFA analysis indicators into structured findings."""

    METADATA = {
        MFAIndicatorType.MFA: (
            "Multi-factor authentication indicator detected.",
            "Info",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.MFA_CHALLENGE: (
            "MFA challenge indicator detected.",
            "Info",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.OTP: (
            "One-time password mechanism detected.",
            "Info",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.TOTP: (
            "TOTP authenticator mechanism detected.",
            "Info",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.SMS_MFA: (
            "SMS-based MFA mechanism detected.",
            "Low",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.EMAIL_MFA: (
            "Email-based MFA mechanism detected.",
            "Low",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.RECOVERY_CODE: (
            "MFA recovery-code mechanism detected.",
            "Low",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.BACKUP_CODE: (
            "MFA backup-code mechanism detected.",
            "Low",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.REMEMBER_DEVICE: (
            "Remember-device MFA behavior detected.",
            "Medium",
            "Medium",
            "CWE-613",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.TRUSTED_DEVICE: (
            "Trusted-device MFA behavior detected.",
            "Medium",
            "Medium",
            "CWE-613",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.MFA_BYPASS_INDICATOR: (
            "Potential MFA bypass indicator detected.",
            "High",
            "Medium",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.MFA_RECOVERY: (
            "MFA recovery mechanism detected.",
            "Medium",
            "Medium",
            "CWE-640",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.MFA_ENROLLMENT: (
            "MFA enrollment mechanism detected.",
            "Low",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.MFA_DISABLE: (
            "MFA disable mechanism detected.",
            "Medium",
            "Medium",
            "CWE-308",
            "OWASP A07:2021",
        ),
        MFAIndicatorType.MFA_VERIFICATION: (
            "MFA verification mechanism detected.",
            "Info",
            "High",
            "CWE-308",
            "OWASP A07:2021",
        ),
    }

    DEFAULT_REMEDIATION = (
        "Enforce MFA consistently for protected operations, require "
        "strong verification for enrollment, recovery, disablement, "
        "and trusted-device changes, protect recovery mechanisms, "
        "and validate all MFA state transitions server-side."
    )

    def analyze(
        self,
        analysis: MFAAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, MFAAnalysis):
            raise TypeError(
                "analysis must be an MFAAnalysis"
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
        grouped = {}

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

            evidence_parts = list(
                dict.fromkeys(
                    indicator.evidence
                    for indicator in indicators
                    if indicator.evidence
                )
            )

            names = list(
                dict.fromkeys(
                    indicator.name
                    for indicator in indicators
                    if indicator.name
                )
            )

            values = list(
                dict.fromkeys(
                    indicator.value
                    for indicator in indicators
                    if indicator.value
                )
            )

            if names:
                evidence_parts.append(
                    "Parameters/headers: "
                    + ", ".join(names)
                )

            if values:
                evidence_parts.append(
                    "Values: "
                    + ", ".join(values)
                )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=(
                        "An MFA-related security indicator was observed. "
                        "The presence of this indicator alone does not "
                        "prove a vulnerability and requires contextual "
                        "validation."
                    ),
                    evidence="\n".join(evidence_parts),
                    remediation=self.DEFAULT_REMEDIATION,
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
