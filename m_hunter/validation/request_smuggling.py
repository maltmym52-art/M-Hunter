from dataclasses import dataclass, field

from m_hunter.analyzers.request_smuggling import (
    RequestSmugglingAnalysis,
)
from m_hunter.core.response import HttpResponse


@dataclass
class RequestSmugglingValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    response_changed: bool
    parser_behavior_changed: bool
    potential_smuggling: bool
    status: str
    evidence: list[str] = field(default_factory=list)


class RequestSmugglingValidator:
    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: RequestSmugglingAnalysis,
        *,
        parser_behavior_changed: bool = False,
    ) -> RequestSmugglingValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError(
                "baseline must be an HttpResponse instance"
            )

        if not isinstance(candidate, HttpResponse):
            raise TypeError(
                "candidate must be an HttpResponse instance"
            )

        if not isinstance(
            analysis,
            RequestSmugglingAnalysis,
        ):
            raise TypeError(
                "analysis must be a RequestSmugglingAnalysis instance"
            )

        if not isinstance(parser_behavior_changed, bool):
            raise TypeError(
                "parser_behavior_changed must be a bool"
            )

        status_changed = (
            baseline.status_code != candidate.status_code
        )

        content_changed = (
            baseline.content != candidate.content
        )

        content_length_changed = (
            baseline.content_length
            != candidate.content_length
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
        )

        potential_smuggling = (
            analysis.detected
            and (
                response_changed
                or parser_behavior_changed
            )
        )

        if not analysis.detected:
            status = "no_indicator"
        elif parser_behavior_changed:
            status = "parser_behavior_changed"
        elif potential_smuggling:
            status = "potential_smuggling"
        else:
            status = "indicator_detected"

        evidence = [
            f"Baseline status: {baseline.status_code}",
            f"Candidate status: {candidate.status_code}",
            f"Status changed: {status_changed}",
            f"Content changed: {content_changed}",
            f"Content length changed: {content_length_changed}",
            f"Response changed: {response_changed}",
            (
                "Parser behavior changed: "
                f"{parser_behavior_changed}"
            ),
        ]

        return RequestSmugglingValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            response_changed=response_changed,
            parser_behavior_changed=parser_behavior_changed,
            potential_smuggling=potential_smuggling,
            status=status,
            evidence=evidence,
        )
