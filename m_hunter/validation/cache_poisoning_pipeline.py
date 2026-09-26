from dataclasses import dataclass

from m_hunter.analyzers.cache_poisoning import CachePoisoningAnalysis
from m_hunter.analyzers.cache_poisoning_finding import (
    CachePoisoningFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.cache_poisoning import (
    CachePoisoningValidationResult,
    CachePoisoningValidator,
)


@dataclass
class CachePoisoningPipelineResult:
    validation: CachePoisoningValidationResult
    accepted: bool
    findings: list[Finding]


class CachePoisoningValidationPipeline:
    def __init__(self):
        self.validator = CachePoisoningValidator()
        self.finding_analyzer = CachePoisoningFindingAnalyzer()

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: CachePoisoningAnalysis,
        target: str,
        *,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> CachePoisoningPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, CachePoisoningAnalysis):
            raise TypeError("analysis must be CachePoisoningAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
        )

        accepted = validation.potential_cache_poisoning

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.create_findings(
                analysis,
                target,
                endpoint=endpoint,
                parameter=parameter,
            )

        return CachePoisoningPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
