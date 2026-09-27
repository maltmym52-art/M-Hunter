from dataclasses import dataclass

from m_hunter.analyzers.referrer_policy import (
    ReferrerPolicyAnalysis,
    ReferrerPolicyIndicatorType,
)


@dataclass(frozen=True)
class ReferrerPolicyValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    weak_policy_present: bool
    potential_referrer_policy_issue: bool
    status: str
    evidence: str


class ReferrerPolicyValidator:
    SECURITY_INDICATORS = {
        ReferrerPolicyIndicatorType.UNSAFE_URL,
        ReferrerPolicyIndicatorType.NO_REFERRER_WHEN_DOWNGRADE,
        ReferrerPolicyIndicatorType.INVALID_POLICY,
    }

    def validate(
        self,
        analysis: ReferrerPolicyAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> ReferrerPolicyValidationResult:
        if not isinstance(
            analysis,
            ReferrerPolicyAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of "
                "ReferrerPolicyAnalysis"
            )

        if not isinstance(baseline_status, int):
            raise TypeError(
                "baseline_status must be an integer"
            )

        if not isinstance(candidate_status, int):
            raise TypeError(
                "candidate_status must be an integer"
            )

        for name, value in (
            ("content_changed", content_changed),
            (
                "content_length_changed",
                content_length_changed,
            ),
            ("headers_changed", headers_changed),
        ):
            if not isinstance(value, bool):
                raise TypeError(
                    f"{name} must be a boolean"
                )

        status_changed = (
            baseline_status != candidate_status
        )

        response_changed = bool(
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        security_indicator_present = bool(
            set(analysis.types)
            & self.SECURITY_INDICATORS
        )

        weak_policy_present = bool(
            analysis.detected
            and security_indicator_present
        )

        potential_referrer_policy_issue = bool(
            weak_policy_present
            and response_changed
        )

        if potential_referrer_policy_issue:
            status = "potential"
        elif weak_policy_present:
            status = "indicator"
        elif analysis.detected:
            status = "detected"
        else:
            status = "clean"

        evidence = (
            f"detected={analysis.detected}; "
            f"security_indicator_present="
            f"{security_indicator_present}; "
            f"status_changed={status_changed}; "
            f"content_changed={content_changed}; "
            f"content_length_changed="
            f"{content_length_changed}; "
            f"headers_changed={headers_changed}; "
            f"response_changed={response_changed}"
        )

        return ReferrerPolicyValidationResult(
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            security_indicator_present=(
                security_indicator_present
            ),
            weak_policy_present=weak_policy_present,
            potential_referrer_policy_issue=(
                potential_referrer_policy_issue
            ),
            status=status,
            evidence=evidence,
        )
