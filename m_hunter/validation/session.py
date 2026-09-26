from dataclasses import dataclass

from m_hunter.analyzers.session import SessionAnalysis
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class SessionValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    behavior_changed: bool
    potential_session_issue: bool
    status: str
    evidence: tuple[str, ...]


class SessionValidator:
    def compare(
        self,
        *,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: SessionAnalysis,
        behavior_changed: bool = False,
    ) -> SessionValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, SessionAnalysis):
            raise TypeError("analysis must be a SessionAnalysis")

        if not isinstance(behavior_changed, bool):
            raise TypeError("behavior_changed must be a bool")

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
            or baseline.repeated_headers != candidate.repeated_headers
        )

        response_changed = any(
            (
                status_changed,
                content_changed,
                content_length_changed,
                headers_changed,
            )
        )

        potential_session_issue = (
            analysis.detected
            and (response_changed or behavior_changed)
        )

        evidence: list[str] = []

        if status_changed:
            evidence.append(
                "HTTP status changed between baseline and candidate."
            )

        if content_changed:
            evidence.append(
                "Response content changed between baseline and candidate."
            )

        if content_length_changed:
            evidence.append(
                "Response content length changed between baseline and candidate."
            )

        if headers_changed:
            evidence.append(
                "Response headers changed between baseline and candidate."
            )

        if behavior_changed:
            evidence.append(
                "Controlled session behavior changed between baseline and candidate."
            )

        if analysis.detected:
            evidence.append(
                "Session-security indicators were detected during analysis."
            )

        if potential_session_issue:
            status = "potential_session_issue"
        elif behavior_changed:
            status = "behavior_changed"
        elif analysis.detected:
            status = "indicator_detected"
        else:
            status = "no_indicator"

        return SessionValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            potential_session_issue=potential_session_issue,
            status=status,
            evidence=tuple(evidence),
        )
