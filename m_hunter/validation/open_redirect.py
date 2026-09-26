from dataclasses import dataclass

from m_hunter.analyzers.open_redirect import OpenRedirectAnalysis
from m_hunter.core.response import HttpResponse


@dataclass
class OpenRedirectValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    behavior_changed: bool
    potential_open_redirect: bool
    status: str
    evidence: list[str]


class OpenRedirectValidator:
    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: OpenRedirectAnalysis,
        *,
        behavior_changed: bool = False,
    ) -> OpenRedirectValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, OpenRedirectAnalysis):
            raise TypeError("analysis must be an OpenRedirectAnalysis")

        if not isinstance(behavior_changed, bool):
            raise TypeError("behavior_changed must be a boolean")

        status_changed = baseline.status_code != candidate.status_code
        content_changed = baseline.content != candidate.content
        content_length_changed = (
            baseline.content_length != candidate.content_length
        )
        headers_changed = baseline.headers != candidate.headers

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        potential_open_redirect = (
            analysis.detected
            and (response_changed or behavior_changed)
        )

        evidence: list[str] = []

        if status_changed:
            evidence.append(
                f"Status changed: {baseline.status_code} -> "
                f"{candidate.status_code}"
            )

        if content_changed:
            evidence.append("Response content changed.")

        if content_length_changed:
            evidence.append(
                f"Content length changed: {baseline.content_length} -> "
                f"{candidate.content_length}"
            )

        if headers_changed:
            evidence.append("Response headers changed.")

        if behavior_changed:
            evidence.append("Application behavior changed.")

        if potential_open_redirect:
            status = "potential_open_redirect"
        elif behavior_changed:
            status = "behavior_changed"
        elif response_changed:
            status = "response_changed"
        elif analysis.detected:
            status = "indicator_detected"
        else:
            status = "no_indicator"

        return OpenRedirectValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            potential_open_redirect=potential_open_redirect,
            status=status,
            evidence=evidence,
        )
