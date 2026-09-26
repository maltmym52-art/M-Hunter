from dataclasses import dataclass

from m_hunter.analyzers.web_cache_deception import (
    WebCacheDeceptionAnalysis,
)
from m_hunter.analyzers.web_cache_deception_finding import (
    WebCacheDeceptionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.web_cache_deception import (
    WebCacheDeceptionValidationResult,
    WebCacheDeceptionValidator,
)


@dataclass
class WebCacheDeceptionPipelineResult:
    validation: WebCacheDeceptionValidationResult
    accepted: bool
    findings: list[Finding]


class WebCacheDeceptionValidationPipeline:
    def __init__(self):
        self.validator = WebCacheDeceptionValidator()
        self.finding_analyzer = WebCacheDeceptionFindingAnalyzer()

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: WebCacheDeceptionAnalysis,
        target: str,
        *,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> WebCacheDeceptionPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, WebCacheDeceptionAnalysis):
            raise TypeError(
                "analysis must be WebCacheDeceptionAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
        )

        accepted = validation.potential_web_cache_deception

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.create_findings(
                analysis,
                target,
                endpoint=endpoint,
                parameter=parameter,
            )

        return WebCacheDeceptionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
