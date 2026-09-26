from dataclasses import dataclass

from m_hunter.analyzers.clickjacking import (
    ClickjackingAnalysis,
    ClickjackingIndicatorType,
)


@dataclass(frozen=True)
class ClickjackingValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    framing_policy_weak: bool
    potential_clickjacking: bool
    status: str
    evidence: str


class ClickjackingValidator:
    SECURITY_INDICATORS = {
        ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS,
        ClickjackingIndicatorType.X_FRAME_OPTIONS_ALLOW_FROM,
        ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS,
        ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD,
    }

    def validate(
        self,
        analysis: ClickjackingAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> ClickjackingValidationResult:
        if not isinstance(
            analysis,
            ClickjackingAnalysis,
        ):
            raise TypeError(
                "analysis must be a ClickjackingAnalysis"
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

        types = set(analysis.types)

        security_indicator_present = bool(
            types & self.SECURITY_INDICATORS
        )

        framing_policy_weak = bool(
            types
            & {
                ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS,
                ClickjackingIndicatorType.X_FRAME_OPTIONS_ALLOW_FROM,
                ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS,
                ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD,
            }
        )

        potential_clickjacking = bool(
            analysis.detected
            and security_indicator_present
            and framing_policy_weak
            and response_changed
        )

        if potential_clickjacking:
            status = "potential"
        elif analysis.detected:
            status = "indicator"
        else:
            status = "clean"

        evidence_parts = [
            f"Baseline status: {baseline_status}.",
            f"Candidate status: {candidate_status}.",
            f"Status changed: {status_changed}.",
            f"Content changed: {content_changed}.",
            f"Content length changed: {content_length_changed}.",
            f"Headers changed: {headers_changed}.",
            f"Security indicator present: "
            f"{security_indicator_present}.",
            f"Framing policy weak: {framing_policy_weak}.",
        ]

        return ClickjackingValidationResult(
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
            framing_policy_weak=framing_policy_weak,
            potential_clickjacking=(
                potential_clickjacking
            ),
            status=status,
            evidence=" ".join(evidence_parts),
        )
