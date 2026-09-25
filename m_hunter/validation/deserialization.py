from dataclasses import dataclass, field

from m_hunter.analyzers.deserialization import (
    DeserializationAnalysis,
)
from m_hunter.core.response import HttpResponse


@dataclass
class DeserializationValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    response_changed: bool
    behavior_changed: bool
    potential_deserialization: bool
    status: str
    evidence: list[str] = field(default_factory=list)


class DeserializationValidator:
    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: DeserializationAnalysis,
        *,
        behavior_changed: bool = False,
    ) -> DeserializationValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse instance")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse instance")

        if not isinstance(
            analysis,
            DeserializationAnalysis,
        ):
            raise TypeError(
                "analysis must be a DeserializationAnalysis instance"
            )

        status_changed = (
            baseline.status_code != candidate.status_code
        )
        content_changed = baseline.content != candidate.content
        content_length_changed = (
            baseline.content_length != candidate.content_length
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
        )

        potential_deserialization = analysis.detected and (
            response_changed or behavior_changed
        )

        if not analysis.detected:
            status = "no_indicator"
        elif behavior_changed:
            status = "behavior_changed"
        elif potential_deserialization:
            status = "potential_deserialization"
        else:
            status = "indicator_detected"

        evidence = [
            f"Baseline status: {baseline.status_code}",
            f"Candidate status: {candidate.status_code}",
            f"Status changed: {status_changed}",
            f"Content changed: {content_changed}",
            f"Content length changed: {content_length_changed}",
            f"Response changed: {response_changed}",
            f"Behavior changed: {behavior_changed}",
        ]

        return DeserializationValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            potential_deserialization=potential_deserialization,
            status=status,
            evidence=evidence,
        )
