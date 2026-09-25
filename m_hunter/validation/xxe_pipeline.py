from dataclasses import dataclass, field

from m_hunter.analyzers.xxe import XXEAnalysis
from m_hunter.analyzers.xxe_finding import XXEFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.xxe import XXEValidationResult, XXEValidator


@dataclass
class XXEPipelineResult:
    validation: XXEValidationResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def potential_xxe(self) -> bool:
        return self.validation.potential_xxe

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class XXEPipeline:
    def __init__(
        self,
        validator: XXEValidator | None = None,
        finding_analyzer: XXEFindingAnalyzer | None = None,
    ):
        self.validator = validator or XXEValidator()
        self.finding_analyzer = (
            finding_analyzer or XXEFindingAnalyzer()
        )

    def run(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: XXEAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        external_entity_behavior: bool = False,
    ) -> XXEPipelineResult:
        if not isinstance(analysis, XXEAnalysis):
            raise TypeError(
                "analysis must be an XXEAnalysis instance"
            )

        validation = self.validator.validate(
            baseline,
            candidate,
            analysis,
            external_entity_behavior=external_entity_behavior,
        )

        findings = self.finding_analyzer.analyze(
            analysis,
            target,
            endpoint,
        )

        return XXEPipelineResult(
            validation=validation,
            findings=findings,
        )
