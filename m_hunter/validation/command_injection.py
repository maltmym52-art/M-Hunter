from dataclasses import dataclass

from m_hunter.analyzers.command_injection import CommandInjectionAnalysis
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class CommandInjectionValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    behavior_changed: bool
    potential_command_injection: bool
    status: str
    evidence: str


class CommandInjectionValidator:
    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: CommandInjectionAnalysis,
        *,
        behavior_changed: bool = False,
    ) -> CommandInjectionValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, CommandInjectionAnalysis):
            raise TypeError(
                "analysis must be a CommandInjectionAnalysis"
            )

        if not isinstance(behavior_changed, bool):
            raise TypeError("behavior_changed must be a boolean")

        status_changed = (
            baseline.status_code != candidate.status_code
        )

        content_changed = (
            baseline.content != candidate.content
        )

        content_length_changed = (
            baseline.content_length != candidate.content_length
        )

        headers_changed = (
            baseline.headers != candidate.headers
        )

        response_changed = any(
            (
                status_changed,
                content_changed,
                content_length_changed,
                headers_changed,
            )
        )

        potential_command_injection = (
            analysis.detected
            and (response_changed or behavior_changed)
        )

        if potential_command_injection:
            status = "potential_command_injection"
        elif behavior_changed:
            status = "behavior_changed"
        elif response_changed:
            status = "response_changed"
        elif analysis.detected:
            status = "indicator_detected"
        else:
            status = "no_indicator"

        evidence_parts = [
            f"Baseline status: {baseline.status_code}",
            f"Candidate status: {candidate.status_code}",
            f"Status changed: {status_changed}",
            f"Content changed: {content_changed}",
            f"Content length changed: {content_length_changed}",
            f"Headers changed: {headers_changed}",
            f"Response changed: {response_changed}",
            f"Behavior changed: {behavior_changed}",
            f"Command-injection indicators detected: {analysis.detected}",
        ]

        return CommandInjectionValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            potential_command_injection=potential_command_injection,
            status=status,
            evidence="\n".join(evidence_parts),
        )
