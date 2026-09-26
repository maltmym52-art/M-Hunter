from dataclasses import dataclass

from m_hunter.analyzers.http_method_security import (
    HTTPMethodSecurityAnalysis,
    HTTPMethodSecurityIndicatorType,
)
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class HTTPMethodSecurityValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    behavior_changed: bool
    security_indicator_present: bool
    potential_http_method_security_issue: bool
    status: str
    evidence: tuple[str, ...]


class HTTPMethodSecurityValidator:
    SECURITY_RELEVANT_TYPES = {
        HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
        HTTPMethodSecurityIndicatorType.TRACK_ENABLED,
        HTTPMethodSecurityIndicatorType.CONNECT_ENABLED,
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER,
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_PARAMETER,
        HTTPMethodSecurityIndicatorType.METHOD_INCONSISTENCY,
    }

    def compare(
        self,
        *,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: HTTPMethodSecurityAnalysis,
        behavior_changed: bool = False,
    ) -> HTTPMethodSecurityValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError(
                "baseline must be an HttpResponse"
            )

        if not isinstance(candidate, HttpResponse):
            raise TypeError(
                "candidate must be an HttpResponse"
            )

        if not isinstance(
            analysis,
            HTTPMethodSecurityAnalysis,
        ):
            raise TypeError(
                "analysis must be an HTTPMethodSecurityAnalysis"
            )

        if not isinstance(behavior_changed, bool):
            raise TypeError(
                "behavior_changed must be a bool"
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
            or baseline.repeated_headers
            != candidate.repeated_headers
        )

        response_changed = any(
            (
                status_changed,
                content_changed,
                content_length_changed,
                headers_changed,
            )
        )

        security_indicator_present = bool(
            analysis.types
            & self.SECURITY_RELEVANT_TYPES
        )

        potential_issue = (
            analysis.detected
            and security_indicator_present
            and (
                response_changed
                or behavior_changed
            )
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
                "Controlled HTTP method behavior changed between baseline and candidate."
            )

        if security_indicator_present:
            evidence.append(
                "Security-relevant HTTP method indicators were detected."
            )
        elif analysis.detected:
            evidence.append(
                "HTTP method indicators were detected, but none "
                "were classified as directly security-relevant "
                "for validation."
            )

        if potential_issue:
            status = "potential_http_method_security_issue"
        elif behavior_changed:
            status = "behavior_changed"
        elif security_indicator_present:
            status = "indicator_detected"
        elif analysis.detected:
            status = "informational_indicator"
        else:
            status = "no_indicator"

        return HTTPMethodSecurityValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            security_indicator_present=security_indicator_present,
            potential_http_method_security_issue=potential_issue,
            status=status,
            evidence=tuple(evidence),
        )
