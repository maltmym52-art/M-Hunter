from dataclasses import dataclass, field

from m_hunter.analyzers.api_security import APIAnalysis
from m_hunter.core.response import HttpResponse


@dataclass
class APIValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    behavior_changed: bool
    potential_api_issue: bool
    status: str
    evidence: list[str] = field(default_factory=list)


class APISecurityValidator:
    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: APIAnalysis,
        *,
        behavior_changed: bool = False,
    ) -> APIValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError(
                "baseline must be an HttpResponse instance"
            )

        if not isinstance(candidate, HttpResponse):
            raise TypeError(
                "candidate must be an HttpResponse instance"
            )

        if not isinstance(analysis, APIAnalysis):
            raise TypeError(
                "analysis must be an APIAnalysis instance"
            )

        status_changed = (
            baseline.status_code
            != candidate.status_code
        )

        content_changed = (
            baseline.content
            != candidate.content
        )

        content_length_changed = (
            baseline.content_length
            != candidate.content_length
        )

        headers_changed = (
            baseline.headers
            != candidate.headers
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        potential_api_issue = (
            analysis.detected
            and (
                response_changed
                or behavior_changed
            )
        )

        if not analysis.detected:
            status = "no_indicator"
        elif behavior_changed:
            status = "behavior_changed"
        elif potential_api_issue:
            status = "potential_api_issue"
        else:
            status = "indicator_detected"

        evidence = [
            f"Baseline status: {baseline.status_code}",
            f"Candidate status: {candidate.status_code}",
            f"Status changed: {status_changed}",
            f"Content changed: {content_changed}",
            (
                "Content length changed: "
                f"{content_length_changed}"
            ),
            f"Headers changed: {headers_changed}",
            f"Response changed: {response_changed}",
            f"Behavior changed: {behavior_changed}",
        ]

        return APIValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            potential_api_issue=potential_api_issue,
            status=status,
            evidence=evidence,
        )
