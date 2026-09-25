from dataclasses import dataclass, field

from m_hunter.analyzers.ssti import SSTIAnalysis
from m_hunter.core.response import HttpResponse


@dataclass
class SSTIValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    response_changed: bool
    evaluation_evidence: bool
    potential_ssti: bool
    status: str
    evidence: list[str] = field(default_factory=list)


class SSTIValidator:
    """
    Validate SSTI indicators through controlled baseline/candidate
    response comparison.

    This validator does not execute template payloads and does not
    confirm server-side template evaluation or code execution.
    """

    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: SSTIAnalysis,
        *,
        evaluation_evidence: bool = False,
    ) -> SSTIValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse instance")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse instance")

        if not isinstance(analysis, SSTIAnalysis):
            raise TypeError("analysis must be an SSTIAnalysis instance")

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

        potential_ssti = (
            analysis.detected
            and response_changed
        )

        if not analysis.detected:
            status = "no_indicator"
        elif evaluation_evidence:
            status = "evaluation_evidence"
        elif potential_ssti:
            status = "potential_ssti"
        else:
            status = "indicator_detected"

        evidence = [
            f"Baseline status: {baseline.status_code}",
            f"Candidate status: {candidate.status_code}",
            f"Status changed: {status_changed}",
            f"Content changed: {content_changed}",
            f"Content length changed: {content_length_changed}",
            f"Response changed: {response_changed}",
            f"Evaluation evidence: {evaluation_evidence}",
        ]

        return SSTIValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            response_changed=response_changed,
            evaluation_evidence=evaluation_evidence,
            potential_ssti=potential_ssti,
            status=status,
            evidence=evidence,
        )
