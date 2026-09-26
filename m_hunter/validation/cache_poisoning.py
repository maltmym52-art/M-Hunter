from dataclasses import dataclass

from m_hunter.analyzers.cache_poisoning import CachePoisoningAnalysis
from m_hunter.core.response import HttpResponse


@dataclass
class CachePoisoningValidationResult:
    baseline_status: int | None
    candidate_status: int | None
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    cache_behavior_changed: bool
    potential_cache_poisoning: bool
    status: str
    evidence: str


class CachePoisoningValidator:
    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: CachePoisoningAnalysis,
    ) -> CachePoisoningValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, CachePoisoningAnalysis):
            raise TypeError("analysis must be CachePoisoningAnalysis")

        status_changed = (
            baseline.status_code != candidate.status_code
        )

        content_changed = (
            baseline.content != candidate.content
        )

        content_length_changed = (
            baseline.content_length != candidate.content_length
        )

        headers_changed = (
            baseline.headers != candidate.headers
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        cache_behavior_changed = (
            self._cache_headers_changed(
                baseline,
                candidate,
            )
        )

        potential_cache_poisoning = (
            analysis.detected
            and (
                content_changed
                or content_length_changed
            )
            and (
                cache_behavior_changed
                or response_changed
            )
        )

        if potential_cache_poisoning:
            status = "potential_cache_poisoning"
        elif cache_behavior_changed:
            status = "cache_behavior_changed"
        elif response_changed:
            status = "response_changed"
        elif analysis.detected:
            status = "indicator_detected"
        else:
            status = "no_indicator"

        evidence = (
            f"baseline_status={baseline.status_code}; "
            f"candidate_status={candidate.status_code}; "
            f"status_changed={status_changed}; "
            f"content_changed={content_changed}; "
            f"content_length_changed={content_length_changed}; "
            f"headers_changed={headers_changed}; "
            f"cache_behavior_changed={cache_behavior_changed}; "
            f"potential_cache_poisoning={potential_cache_poisoning}"
        )

        return CachePoisoningValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            cache_behavior_changed=cache_behavior_changed,
            potential_cache_poisoning=potential_cache_poisoning,
            status=status,
            evidence=evidence,
        )

    @staticmethod
    def _cache_headers_changed(
        baseline: HttpResponse,
        candidate: HttpResponse,
    ) -> bool:
        cache_headers = {
            "x-cache",
            "x-cache-hits",
            "x-cache-status",
            "cf-cache-status",
            "x-proxy-cache",
            "x-cache-lookup",
            "cache-control",
            "surrogate-control",
            "cdn-cache-control",
            "age",
            "etag",
            "vary",
        }

        baseline_headers = {
            name.lower(): value
            for name, value in baseline.headers.items()
            if name.lower() in cache_headers
        }

        candidate_headers = {
            name.lower(): value
            for name, value in candidate.headers.items()
            if name.lower() in cache_headers
        }

        return baseline_headers != candidate_headers
