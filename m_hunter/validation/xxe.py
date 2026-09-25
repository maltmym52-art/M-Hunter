from dataclasses import dataclass, field

from m_hunter.analyzers.xxe import XXEAnalysis
from m_hunter.core.response import HttpResponse


@dataclass
class XXEValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    response_changed: bool
    external_entity_behavior: bool
    potential_xxe: bool
    status: str
    evidence: list[str] = field(default_factory=list)


class XXEValidator:
    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: XXEAnalysis,
        *,
        external_entity_behavior: bool = False,
    ) -> XXEValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse instance")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse instance")

        if not isinstance(analysis, XXEAnalysis):
            raise TypeError("analysis must be an XXEAnalysis instance")

        if not isinstance(external_entity_behavior, bool):
            raise TypeError("external_entity_behavior must be a bool")

        status_changed = (
            baseline.status_code != candidate.status_code
        )

        content_changed = (
            baseline.content != candidate.content
        )

        content_length_changed = (
            baseline.content_length != candidate.content_length
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
        )

        potential_xxe = (
            analysis.detected
            and response_changed
        )

        if not analysis.detected:
            status = "no_indicator"
        elif external_entity_behavior:
            status = "external_entity_behavior"
        elif potential_xxe:
            status = "potential_xxe"
        else:
            status = "indicator_detected"

        evidence = [
            f"Baseline status: {baseline.status_code}",
            f"Candidate status: {candidate.status_code}",
            f"Status changed: {status_changed}",
            f"Content changed: {content_changed}",
            f"Content length changed: {content_length_changed}",
            f"Response changed: {response_changed}",
            f"External entity behavior: {external_entity_behavior}",
        ]

        return XXEValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            response_changed=response_changed,
            external_entity_behavior=external_entity_behavior,
            potential_xxe=potential_xxe,
            status=status,
            evidence=evidence,
        )
