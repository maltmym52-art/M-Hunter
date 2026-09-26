from dataclasses import dataclass

from m_hunter.analyzers.crlf_injection import CRLFInjectionAnalysis
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class CRLFInjectionValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    behavior_changed: bool
    potential_crlf_injection: bool
    status: str
    evidence: str


class CRLFInjectionValidator:
    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: CRLFInjectionAnalysis,
        *,
        behavior_changed: bool = False,
    ) -> CRLFInjectionValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, CRLFInjectionAnalysis):
            raise TypeError(
                "analysis must be a CRLFInjectionAnalysis"
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
            baseline.content_length
            != candidate.content_length
        )

        headers_changed = (
            baseline.headers != candidate.headers
            or baseline.repeated_headers
            != candidate.repeated_headers
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        potential_crlf_injection = (
            analysis.detected
            and (response_changed or behavior_changed)
        )

        if potential_crlf_injection:
            status = "potential_crlf_injection"
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
            f"CRLF indicators detected: {analysis.detected}",
        ]

        if analysis.detected:
            evidence_parts.append(
                "Indicator types: "
                + ", ".join(
                    indicator_type.value
                    for indicator_type in analysis.types
                )
            )

        return CRLFInjectionValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            potential_crlf_injection=potential_crlf_injection,
            status=status,
            evidence="\n".join(evidence_parts),
        )
