from dataclasses import dataclass, field

from m_hunter.analyzers.csrf import CSRFAnalysis
from m_hunter.core.response import HttpResponse


@dataclass
class CSRFValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    response_changed: bool
    protection_changed: bool
    potential_csrf: bool
    status: str
    evidence: list[str] = field(default_factory=list)


class CSRFValidator:
    """
    Validate CSRF indicators by comparing controlled baseline and
    candidate responses.

    This validator does not forge requests or confirm exploitation.
    """

    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: CSRFAnalysis,
        *,
        protection_changed: bool = False,
    ) -> CSRFValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse instance")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse instance")

        if not isinstance(analysis, CSRFAnalysis):
            raise TypeError("analysis must be a CSRFAnalysis instance")

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

        potential_csrf = (
            analysis.detected
            and response_changed
        )

        if not analysis.detected:
            status = "no_indicator"
        elif potential_csrf:
            status = "potential_csrf"
        else:
            status = "indicator_detected"

        evidence = [
            f"Baseline status: {baseline.status_code}",
            f"Candidate status: {candidate.status_code}",
            f"Status changed: {status_changed}",
            f"Content changed: {content_changed}",
            f"Content length changed: {content_length_changed}",
            f"Response changed: {response_changed}",
            f"Protection changed: {protection_changed}",
        ]

        return CSRFValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            response_changed=response_changed,
            protection_changed=protection_changed,
            potential_csrf=potential_csrf,
            status=status,
            evidence=evidence,
        )
