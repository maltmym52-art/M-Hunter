from m_hunter.analyzers.race_condition import (
    RaceConditionAnalysis,
    RaceConditionIndicatorType,
)
from m_hunter.core.finding import Finding


class RaceConditionFindingAnalyzer:
    METADATA = {
        RaceConditionIndicatorType.CONCURRENT_REQUEST: (
            "Concurrent requests detected",
            "Info",
            "High",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.REPEATED_REQUEST: (
            "Repeated requests detected",
            "Info",
            "High",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.STATE_CHANGE: (
            "State change detected",
            "Medium",
            "Medium",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.DUPLICATE_OPERATION: (
            "Duplicate operation accepted",
            "High",
            "High",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.NON_IDEMPOTENT_OPERATION: (
            "Non-idempotent operation detected",
            "Info",
            "High",
            "CWE-352",
            "A04:2021",
        ),
        RaceConditionIndicatorType.SENSITIVE_OPERATION: (
            "Sensitive operation involved",
            "Medium",
            "Medium",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.BALANCE_CHANGE: (
            "Balance-related state change detected",
            "High",
            "High",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.COUPON_REDEMPTION: (
            "Coupon redemption operation detected",
            "Medium",
            "Medium",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.PASSWORD_CHANGE: (
            "Password change operation detected",
            "High",
            "High",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.MFA_OPERATION: (
            "MFA operation detected",
            "High",
            "High",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.TOKEN_ROTATION: (
            "Token rotation operation detected",
            "High",
            "High",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.RESOURCE_CREATION: (
            "Resource creation operation detected",
            "Medium",
            "Medium",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.RESOURCE_DELETION: (
            "Resource deletion operation detected",
            "Medium",
            "Medium",
            "CWE-362",
            "A04:2021",
        ),
        RaceConditionIndicatorType.RESPONSE_VARIATION: (
            "Response variation detected",
            "Medium",
            "Medium",
            "CWE-362",
            "A04:2021",
        ),
    }

    def analyze(
        self,
        analysis: RaceConditionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, RaceConditionAnalysis):
            raise TypeError("analysis must be a RaceConditionAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        findings: list[Finding] = []

        grouped: dict[RaceConditionIndicatorType, list] = {}

        for indicator in analysis.indicators:
            grouped.setdefault(indicator.type, []).append(indicator)

        for indicator_type, indicators in grouped.items():
            metadata = self.METADATA.get(indicator_type)
            if metadata is None:
                continue

            title, severity, confidence, cwe, owasp = metadata

            evidence = "\n".join(
                f"- {indicator.evidence}"
                for indicator in indicators
            )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=(
                        "A race-condition-related indicator was detected. "
                        "Indicator presence alone does not prove a race "
                        "condition vulnerability; controlled concurrent "
                        "validation is required."
                    ),
                    evidence=evidence,
                    remediation=(
                        "Use atomic server-side operations, transactional "
                        "state changes, appropriate locking or concurrency "
                        "controls, idempotency mechanisms, and server-side "
                        "validation for sensitive operations."
                    ),
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
