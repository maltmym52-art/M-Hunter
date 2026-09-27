from dataclasses import dataclass

from m_hunter.analyzers.corp import (
    CORPAnalysis,
    CORPIndicatorType,
)


@dataclass(frozen=True)
class CORPValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    weak_policy_present: bool
    potential_corp_issue: bool
    status: str
    evidence: str


class CORPValidator:
    SECURITY_INDICATORS = {
        CORPIndicatorType.CROSS_ORIGIN,
        CORPIndicatorType.INVALID_POLICY,
        CORPIndicatorType.MULTIPLE_POLICIES,
    }

    def validate(
        self,
        analysis: CORPAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> CORPValidationResult:
        if not isinstance(analysis, CORPAnalysis):
            raise TypeError(
                "analysis must be an instance of CORPAnalysis"
            )

        if not isinstance(baseline_status, int):
            raise TypeError("baseline_status must be an integer")

        if not isinstance(candidate_status, int):
            raise TypeError("candidate_status must be an integer")

        for name, value in {
            "content_changed": content_changed,
            "content_length_changed": content_length_changed,
            "headers_changed": headers_changed,
        }.items():
            if not isinstance(value, bool):
                raise TypeError(f"{name} must be a boolean")

        status_changed = baseline_status != candidate_status

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        security_indicator_present = any(
            indicator.type in self.SECURITY_INDICATORS
            for indicator in analysis.indicators
        )

        weak_policy_present = (
            analysis.detected
            and security_indicator_present
        )

        potential = (
            weak_policy_present
            and response_changed
        )

        if potential:
            status = "potential"
        elif security_indicator_present:
            status = "indicator"
        elif analysis.detected:
            status = "detected"
        else:
            status = "clean"

        evidence_parts = [
            f"baseline_status={baseline_status}",
            f"candidate_status={candidate_status}",
            f"status_changed={status_changed}",
            f"content_changed={content_changed}",
            f"content_length_changed={content_length_changed}",
            f"headers_changed={headers_changed}",
            (
                "security_indicator_present="
                f"{security_indicator_present}"
            ),
        ]

        for indicator in analysis.indicators:
            if indicator.value:
                evidence_parts.append(
                    f"{indicator.type.value}={indicator.value}"
                )
            else:
                evidence_parts.append(indicator.type.value)

        return CORPValidationResult(
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            security_indicator_present=security_indicator_present,
            weak_policy_present=weak_policy_present,
            potential_corp_issue=potential,
            status=status,
            evidence="; ".join(evidence_parts),
        )
