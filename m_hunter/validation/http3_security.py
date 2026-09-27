from dataclasses import dataclass

from m_hunter.analyzers.http3_security import (
    HTTP3Analysis,
    HTTP3IndicatorType,
)


SECURITY_INDICATORS = {
    HTTP3IndicatorType.QUIC_ERROR,
    HTTP3IndicatorType.HTTP3_ERROR,
    HTTP3IndicatorType.DOWNGRADE_INDICATOR,
    HTTP3IndicatorType.FALLBACK_INDICATOR,
    HTTP3IndicatorType.MALFORMED_PROTOCOL,
}


@dataclass(frozen=True)
class HTTP3ValidationResult:
    baseline_status: int | None
    candidate_status: int | None
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    protocol_security_issue: bool
    potential_http3_security_issue: bool
    status: str
    evidence: str


class HTTP3ValidationAnalyzer:
    name = "http3_security_validation"

    def validate(
        self,
        analysis: HTTP3Analysis,
        *,
        baseline_status: int | None = None,
        candidate_status: int | None = None,
        baseline_content: bytes | str | None = None,
        candidate_content: bytes | str | None = None,
        baseline_content_length: int | None = None,
        candidate_content_length: int | None = None,
        baseline_headers: dict[str, str] | None = None,
        candidate_headers: dict[str, str] | None = None,
    ) -> HTTP3ValidationResult:
        if not isinstance(analysis, HTTP3Analysis):
            raise TypeError("analysis must be an HTTP3Analysis")

        status_changed = (
            baseline_status != candidate_status
        )

        content_changed = (
            baseline_content != candidate_content
        )

        content_length_changed = (
            baseline_content_length
            != candidate_content_length
        )

        headers_changed = (
            (baseline_headers or {})
            != (candidate_headers or {})
        )

        response_changed = any(
            (
                status_changed,
                content_changed,
                content_length_changed,
                headers_changed,
            )
        )

        security_indicator_present = any(
            indicator.type in SECURITY_INDICATORS
            for indicator in analysis.indicators
        )

        protocol_security_issue = (
            analysis.detected
            and security_indicator_present
        )

        potential_http3_security_issue = (
            protocol_security_issue
            and response_changed
        )

        if potential_http3_security_issue:
            status = "potential"
        elif protocol_security_issue:
            status = "detected"
        else:
            status = "not_detected"

        evidence_parts: list[str] = []

        if security_indicator_present:
            evidence_parts.append(
                "Security-relevant HTTP/3 indicator detected"
            )

        if status_changed:
            evidence_parts.append(
                f"status changed: "
                f"{baseline_status}->{candidate_status}"
            )

        if content_changed:
            evidence_parts.append(
                "response content changed"
            )

        if content_length_changed:
            evidence_parts.append(
                "response content length changed"
            )

        if headers_changed:
            evidence_parts.append(
                "response headers changed"
            )

        return HTTP3ValidationResult(
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            security_indicator_present=security_indicator_present,
            protocol_security_issue=protocol_security_issue,
            potential_http3_security_issue=potential_http3_security_issue,
            status=status,
            evidence="; ".join(evidence_parts),
        )

    def analyze(
        self,
        analysis: HTTP3Analysis,
        **kwargs,
    ) -> HTTP3ValidationResult:
        return self.validate(
            analysis,
            **kwargs,
        )
