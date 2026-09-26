from dataclasses import dataclass

from m_hunter.analyzers.nosql_injection import (
    NoSQLInjectionAnalysis,
    NoSQLInjectionIndicatorType,
)
from m_hunter.core.response import HttpResponse


@dataclass
class NoSQLInjectionValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    injection_indicator_present: bool
    potential_nosql_injection: bool
    status: str
    evidence: list[str]


class NoSQLInjectionValidator:
    _INTERESTING_HEADERS = {
        "content-type",
        "content-length",
        "location",
        "cache-control",
        "set-cookie",
    }

    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: NoSQLInjectionAnalysis,
    ) -> NoSQLInjectionValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, NoSQLInjectionAnalysis):
            raise TypeError("analysis must be NoSQLInjectionAnalysis")

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

        injection_indicator_present = any(
            analysis.has_type(indicator_type)
            for indicator_type in (
                NoSQLInjectionIndicatorType.MONGODB_OPERATOR,
                NoSQLInjectionIndicatorType.QUERY_OPERATOR,
                NoSQLInjectionIndicatorType.REGEX_OPERATOR,
                NoSQLInjectionIndicatorType.JAVASCRIPT_OPERATOR,
                NoSQLInjectionIndicatorType.DOLLAR_PREFIX,
                NoSQLInjectionIndicatorType.DATABASE_ERROR,
            )
        )

        potential_nosql_injection = (
            analysis.detected
            and injection_indicator_present
            and response_changed
        )

        evidence: list[str] = []

        if injection_indicator_present:
            evidence.append(
                "NoSQL-injection-related input or error indicator detected."
            )

        if status_changed:
            evidence.append(
                f"HTTP status changed from {baseline.status_code} "
                f"to {candidate.status_code}."
            )

        if content_changed:
            evidence.append("Response content changed.")

        if content_length_changed:
            evidence.append("Response content length changed.")

        if headers_changed:
            evidence.append("Relevant response headers changed.")

        if potential_nosql_injection:
            status = "potential"
        elif analysis.detected:
            status = "indicator_only"
        else:
            status = "no_indicator"

        return NoSQLInjectionValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            injection_indicator_present=injection_indicator_present,
            potential_nosql_injection=potential_nosql_injection,
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
