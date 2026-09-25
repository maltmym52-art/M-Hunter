from dataclasses import dataclass

from m_hunter.analyzers.mfa import MFAAnalysis
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class MFAValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    behavior_changed: bool
    potential_mfa_issue: bool
    status: str
    evidence: str


class MFAValidator:
    """Validate MFA-related behavior using controlled responses."""

    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: MFAAnalysis,
        *,
        behavior_changed: bool = False,
    ) -> MFAValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, MFAAnalysis):
            raise TypeError("analysis must be an MFAAnalysis")

        if not isinstance(behavior_changed, bool):
            raise TypeError("behavior_changed must be a bool")

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

        potential_mfa_issue = (
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
        elif potential_mfa_issue:
            status = "potential_mfa_issue"
        else:
            status = "indicator_detected"

        evidence = []

        if status_changed:
            evidence.append(
                f"status changed: "
                f"{baseline.status_code} -> "
                f"{candidate.status_code}"
            )

        if content_changed:
            evidence.append("response content changed")

        if content_length_changed:
            evidence.append(
                f"content length changed: "
                f"{baseline.content_length} -> "
                f"{candidate.content_length}"
            )

        if headers_changed:
            evidence.append("response headers changed")

        if behavior_changed:
            evidence.append("application behavior changed")

        if analysis.detected:
            evidence.append(
                "MFA security indicators were detected"
            )

        return MFAValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            potential_mfa_issue=potential_mfa_issue,
            status=status,
            evidence="; ".join(evidence),
        )
