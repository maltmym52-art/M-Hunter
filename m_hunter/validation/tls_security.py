from dataclasses import dataclass
from typing import Any

from m_hunter.analyzers.tls_security import (
    TLSAnalysis,
    TLSIndicatorType,
)


SECURITY_INDICATORS = {
    TLSIndicatorType.SSLV2,
    TLSIndicatorType.SSLV3,
    TLSIndicatorType.TLS10,
    TLSIndicatorType.TLS11,
    TLSIndicatorType.EXPIRED_CERTIFICATE,
    TLSIndicatorType.SELF_SIGNED_CERTIFICATE,
    TLSIndicatorType.HOSTNAME_MISMATCH,
    TLSIndicatorType.INVALID_CERTIFICATE_CHAIN,
    TLSIndicatorType.WEAK_CIPHER,
    TLSIndicatorType.WEAK_KEY_EXCHANGE,
    TLSIndicatorType.WEAK_SIGNATURE,
}


@dataclass(frozen=True)
class TLSValidationResult:
    baseline_status: int | None
    candidate_status: int | None
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    weak_tls_configuration: bool
    potential_tls_security_issue: bool
    status: str
    evidence: str


class TLSValidationAnalyzer:
    name = "tls_security_validation"

    def validate(
        self,
        analysis: TLSAnalysis,
        *,
        baseline_status: int | None = None,
        candidate_status: int | None = None,
        baseline_content: bytes | str | None = None,
        candidate_content: bytes | str | None = None,
        baseline_content_length: int | None = None,
        candidate_content_length: int | None = None,
        baseline_headers: dict[str, str] | None = None,
        candidate_headers: dict[str, str] | None = None,
    ) -> TLSValidationResult:
        if not isinstance(analysis, TLSAnalysis):
            raise TypeError("analysis must be a TLSAnalysis")

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

        weak_tls_configuration = (
            analysis.detected
            and security_indicator_present
        )

        potential_tls_security_issue = (
            weak_tls_configuration
            and response_changed
        )

        if potential_tls_security_issue:
            status = "potential"
        elif weak_tls_configuration:
            status = "detected"
        else:
            status = "not_detected"

        evidence_parts: list[str] = []

        if security_indicator_present:
            evidence_parts.append(
                "Security-relevant TLS indicator detected"
            )

        if status_changed:
            evidence_parts.append(
                f"status changed: "
                f"{baseline_status}->{candidate_status}"
            )

        if content_changed:
            evidence_parts.append("response content changed")

        if content_length_changed:
            evidence_parts.append(
                "response content length changed"
            )

        if headers_changed:
            evidence_parts.append(
                "response headers changed"
            )

        evidence = "; ".join(evidence_parts)

        return TLSValidationResult(
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            security_indicator_present=security_indicator_present,
            weak_tls_configuration=weak_tls_configuration,
            potential_tls_security_issue=potential_tls_security_issue,
            status=status,
            evidence=evidence,
        )

    def analyze(
        self,
        analysis: TLSAnalysis,
        **kwargs: Any,
    ) -> TLSValidationResult:
        return self.validate(
            analysis,
            **kwargs,
        )
