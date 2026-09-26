from dataclasses import dataclass

from m_hunter.analyzers.prototype_pollution import (
    PrototypePollutionAnalysis,
)
from m_hunter.analyzers.prototype_pollution_finding import (
    PrototypePollutionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.prototype_pollution import (
    PrototypePollutionValidationResult,
    PrototypePollutionValidator,
)


@dataclass
class PrototypePollutionPipelineResult:
    validation: PrototypePollutionValidationResult
    accepted: bool
    findings: list[Finding]


class PrototypePollutionValidationPipeline:
    name = "prototype_pollution_pipeline"

    def __init__(
        self,
        validator: PrototypePollutionValidator | None = None,
        finding_analyzer: PrototypePollutionFindingAnalyzer | None = None,
    ):
        self.validator = validator or PrototypePollutionValidator()
        self.finding_analyzer = (
            finding_analyzer
            or PrototypePollutionFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: PrototypePollutionAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> PrototypePollutionPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, PrototypePollutionAnalysis):
            raise TypeError(
                "analysis must be PrototypePollutionAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
        )

        accepted = validation.potential_prototype_pollution

        findings = (
            self.finding_analyzer.create_findings(
                analysis,
                target,
                endpoint,
            )
            if accepted
            else []
        )

        return PrototypePollutionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
