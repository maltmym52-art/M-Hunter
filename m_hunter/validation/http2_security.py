from dataclasses import dataclass

from m_hunter.analyzers.http2_security import (
    HTTP2SecurityAnalysis,
    HTTP2SecurityIndicatorType,
)
from m_hunter.core.response import HttpResponse


@dataclass
class HTTP2SecurityValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    potential_http2_security_issue: bool
    status: str
    evidence: list[str]


class HTTP2SecurityValidator:
    _INTERESTING_HEADERS = {
        "content-type",
        "content-length",
        "location",
        "cache-control",
        "set-cookie",
        "upgrade",
        "connection",
        "alt-svc",
        "server",
    }

    _SECURITY_RELEVANT_TYPES = {
        HTTP2SecurityIndicatorType.DUPLICATE_PSEUDO_HEADER,
        HTTP2SecurityIndicatorType.INVALID_PSEUDO_HEADER_ORDER,
        HTTP2SecurityIndicatorType.HTTP2_ERROR,
        HTTP2SecurityIndicatorType.STREAM_ERROR,
        HTTP2SecurityIndicatorType.GOAWAY_ERROR,
        HTTP2SecurityIndicatorType.H2C_UPGRADE,
    }

    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: HTTP2SecurityAnalysis,
    ) -> HTTP2SecurityValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, HTTP2SecurityAnalysis):
            raise TypeError(
                "analysis must be HTTP2SecurityAnalysis"
            )

        status_changed = (
            baseline.status_code != candidate.status_code
        )

        content_changed = (
            baseline.content != candidate.content
        )

        content_length_changed = (
            baseline.content_length != candidate.content_length
        )

        headers_changed = self._headers_changed(
            baseline,
            candidate,
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        security_indicator_present = any(
            analysis.has_type(indicator_type)
            for indicator_type in self._SECURITY_RELEVANT_TYPES
        )

        potential_http2_security_issue = (
            analysis.detected
            and security_indicator_present
            and response_changed
        )

        evidence: list[str] = []

        if security_indicator_present:
            evidence.append(
                "Security-relevant HTTP/2 indicator detected."
            )

        if status_changed:
            evidence.append(
                f"HTTP status changed from {baseline.status_code} "
                f"to {candidate.status_code}."
            )

        if content_changed:
            evidence.append("Response content changed.")

        if content_length_changed:
            evidence.append(
                "Response content length changed."
            )

        if headers_changed:
            evidence.append(
                "Relevant HTTP/2/HTTP response headers changed."
            )

        if potential_http2_security_issue:
            status = "potential"
        elif analysis.detected:
            status = "indicator_only"
        else:
            status = "no_indicator"

        return HTTP2SecurityValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            security_indicator_present=security_indicator_present,
            potential_http2_security_issue=(
                potential_http2_security_issue
            ),
            status=status,
            evidence=evidence,
        )

    def _headers_changed(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
    ) -> bool:
        for header_name in self._INTERESTING_HEADERS:
            if baseline.get_header(header_name) != candidate.get_header(
                header_name
            ):
                return True

        return False
