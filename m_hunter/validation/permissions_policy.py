from dataclasses import dataclass

from m_hunter.analyzers.permissions_policy import (
    PermissionsPolicyAnalysis,
    PermissionsPolicyIndicatorType,
)


@dataclass(frozen=True)
class PermissionsPolicyValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    weak_policy_present: bool
    potential_permissions_policy_issue: bool
    status: str
    evidence: str


class PermissionsPolicyValidator:
    SECURITY_INDICATORS = {
        PermissionsPolicyIndicatorType.WILDCARD_SOURCE,
        PermissionsPolicyIndicatorType.INVALID_DIRECTIVE,
        PermissionsPolicyIndicatorType.INVALID_SOURCE,
    }

    def validate(
        self,
        analysis: PermissionsPolicyAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> PermissionsPolicyValidationResult:
        if not isinstance(analysis, PermissionsPolicyAnalysis):
            raise TypeError(
                "analysis must be an instance of PermissionsPolicyAnalysis"
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
            f"security_indicator_present={security_indicator_present}",
        ]

        for indicator in analysis.indicators:
            value = indicator.value
            if value:
                evidence_parts.append(
                    f"{indicator.type.value}={value}"
                )
            else:
                evidence_parts.append(
                    indicator.type.value
                )

        return PermissionsPolicyValidationResult(
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            security_indicator_present=security_indicator_present,
            weak_policy_present=weak_policy_present,
            potential_permissions_policy_issue=potential,
            status=status,
            evidence="; ".join(evidence_parts),
        )
