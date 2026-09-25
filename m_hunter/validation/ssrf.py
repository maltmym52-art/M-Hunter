from dataclasses import dataclass, field

from m_hunter.analyzers.ssrf import SSRFAnalysis
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class SSRFValidationResult:
    baseline: HttpResponse
    candidate: HttpResponse
    analysis: SSRFAnalysis
    indicator_changed: bool
    response_changed: bool
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    potential_ssrf: bool
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def status(self) -> str:
        if self.potential_ssrf:
            return "potential_ssrf"

        if self.analysis.detected:
            return "indicator_detected"

        return "no_indicator"


class SSRFValidator:
    """
    Validates controlled SSRF indicators using baseline/candidate
    response comparison.

    An SSRF indicator plus response behavior change is evidence for
    further validation. It is not proof of server-side request
    execution by itself.
    """

    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: SSRFAnalysis,
    ) -> SSRFValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, SSRFAnalysis):
            raise TypeError("analysis must be an SSRFAnalysis")

        evidence: list[str] = []

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

        indicator_changed = analysis.detected

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

        if indicator_changed:
            evidence.append(
                f"SSRF indicators detected: "
                f"{analysis.indicator_count}"
            )

            for indicator_type in analysis.types:
                evidence.append(
                    f"indicator type: {indicator_type}"
                )

        potential_ssrf = (
            indicator_changed
            and response_changed
        )

        if potential_ssrf:
            evidence.append(
                "SSRF indicator and response behavior "
                "changed together"
            )

        return SSRFValidationResult(
            baseline=baseline,
            candidate=candidate,
            analysis=analysis,
            indicator_changed=indicator_changed,
            response_changed=response_changed,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            potential_ssrf=potential_ssrf,
            evidence=tuple(evidence),
        )
