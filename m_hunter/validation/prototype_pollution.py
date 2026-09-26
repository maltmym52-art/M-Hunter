from dataclasses import dataclass

from m_hunter.analyzers.prototype_pollution import (
    PrototypePollutionAnalysis,
    PrototypePollutionIndicatorType,
)
from m_hunter.core.response import HttpResponse


@dataclass
class PrototypePollutionValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    pollution_indicator_present: bool
    potential_prototype_pollution: bool
    status: str
    evidence: list[str]


class PrototypePollutionValidator:
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
        analysis: PrototypePollutionAnalysis,
    ) -> PrototypePollutionValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, PrototypePollutionAnalysis):
            raise TypeError(
                "analysis must be PrototypePollutionAnalysis"
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

        pollution_indicator_present = any(
            analysis.has_type(indicator_type)
            for indicator_type in (
                PrototypePollutionIndicatorType.PROTO_KEY,
                PrototypePollutionIndicatorType.CONSTRUCTOR_KEY,
                PrototypePollutionIndicatorType.PROTOTYPE_KEY,
                PrototypePollutionIndicatorType.POLLUTION_MARKER,
            )
        )

        potential_prototype_pollution = (
            analysis.detected
            and pollution_indicator_present
            and response_changed
        )

        evidence: list[str] = []

        if pollution_indicator_present:
            evidence.append(
                "Prototype-pollution-related input or marker detected."
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
                "Relevant response headers changed."
            )

        if potential_prototype_pollution:
            status = "potential"
        elif analysis.detected:
            status = "indicator_only"
        else:
            status = "no_indicator"

        return PrototypePollutionValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            pollution_indicator_present=pollution_indicator_present,
            potential_prototype_pollution=potential_prototype_pollution,
            status=status,
            evidence=evidence,
        )

    def _headers_changed(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
    ) -> bool:
        for header_name in self._INTERESTING_HEADERS:
            baseline_value = baseline.get_header(header_name)
            candidate_value = candidate.get_header(header_name)

            if baseline_value != candidate_value:
                return True

        return False
