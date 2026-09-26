from dataclasses import dataclass

from m_hunter.analyzers.websocket_security import (
    WebSocketSecurityAnalysis,
    WebSocketSecurityIndicatorType,
)
from m_hunter.core.response import HttpResponse


@dataclass
class WebSocketSecurityValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    potential_websocket_security_issue: bool
    status: str
    evidence: list[str]


class WebSocketSecurityValidator:
    _INTERESTING_HEADERS = {
        "content-type",
        "content-length",
        "location",
        "cache-control",
        "set-cookie",
        "upgrade",
        "connection",
        "sec-websocket-accept",
        "sec-websocket-protocol",
    }

    _SECURITY_RELEVANT_TYPES = {
        WebSocketSecurityIndicatorType.MISSING_ORIGIN,
        WebSocketSecurityIndicatorType.CORS_LIKE_ORIGIN,
        WebSocketSecurityIndicatorType.WEBSOCKET_ERROR,
        WebSocketSecurityIndicatorType.SENSITIVE_PATH,
    }

    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: WebSocketSecurityAnalysis,
    ) -> WebSocketSecurityValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, WebSocketSecurityAnalysis):
            raise TypeError(
                "analysis must be WebSocketSecurityAnalysis"
            )

        status_changed = baseline.status_code != candidate.status_code
        content_changed = baseline.content != candidate.content
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

        potential_websocket_security_issue = (
            analysis.detected
            and security_indicator_present
            and response_changed
        )

        evidence: list[str] = []

        if security_indicator_present:
            evidence.append(
                "Security-relevant WebSocket indicator detected."
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
                "Relevant WebSocket/HTTP response headers changed."
            )

        if potential_websocket_security_issue:
            status = "potential"
        elif analysis.detected:
            status = "indicator_only"
        else:
            status = "no_indicator"

        return WebSocketSecurityValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            security_indicator_present=security_indicator_present,
            potential_websocket_security_issue=(
                potential_websocket_security_issue
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
