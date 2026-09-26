from dataclasses import dataclass

from m_hunter.analyzers.web_cache_deception import (
    WebCacheDeceptionAnalysis,
)
from m_hunter.core.response import HttpResponse


@dataclass
class WebCacheDeceptionValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    cache_behavior_changed: bool
    response_changed: bool
    sensitive_content_exposed: bool
    potential_web_cache_deception: bool
    status: str
    evidence: str


class WebCacheDeceptionValidator:
    CACHE_HEADERS = {
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
        "vary",
    }

    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: WebCacheDeceptionAnalysis,
    ) -> WebCacheDeceptionValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, WebCacheDeceptionAnalysis):
            raise TypeError(
                "analysis must be WebCacheDeceptionAnalysis"
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

        headers_changed = (
            baseline.headers != candidate.headers
        )

        cache_behavior_changed = (
            self._cache_headers_changed(
                baseline,
                candidate,
            )
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        sensitive_content_exposed = bool(
            analysis.has_type(
                self._sensitive_content_type()
            )
            and content_changed
            and candidate.content
        )

        potential_web_cache_deception = (
            analysis.detected
            and cache_behavior_changed
            and sensitive_content_exposed
        )

        if potential_web_cache_deception:
            status = "potential_web_cache_deception"
        elif cache_behavior_changed and sensitive_content_exposed:
            status = "cache_behavior_changed"
        elif sensitive_content_exposed:
            status = "sensitive_content_exposed"
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
            f"sensitive_content_exposed={sensitive_content_exposed}; "
            f"potential_web_cache_deception="
            f"{potential_web_cache_deception}"
        )

        return WebCacheDeceptionValidationResult(
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            cache_behavior_changed=cache_behavior_changed,
            response_changed=response_changed,
            sensitive_content_exposed=sensitive_content_exposed,
            potential_web_cache_deception=potential_web_cache_deception,
            status=status,
            evidence=evidence,
        )

    @staticmethod
    def _sensitive_content_type():
        from m_hunter.analyzers.web_cache_deception import (
            WebCacheDeceptionIndicatorType,
        )

        return WebCacheDeceptionIndicatorType.SENSITIVE_CONTENT

    @classmethod
    def _cache_headers_changed(
        cls,
        baseline: HttpResponse,
        candidate: HttpResponse,
    ) -> bool:
        baseline_headers = {
            name.lower(): value
            for name, value in baseline.headers.items()
            if name.lower() in cls.CACHE_HEADERS
        }

        candidate_headers = {
            name.lower(): value
            for name, value in candidate.headers.items()
            if name.lower() in cls.CACHE_HEADERS
        }

        return baseline_headers != candidate_headers
