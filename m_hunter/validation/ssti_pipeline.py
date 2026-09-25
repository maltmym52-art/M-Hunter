from dataclasses import dataclass, field

from m_hunter.analyzers.ssti import SSTIAnalysis
from m_hunter.analyzers.ssti_finding import SSTIFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.ssti import (
    SSTIValidationResult,
    SSTIValidator,
)


@dataclass
class SSTIPipelineResult:
    validation: SSTIValidationResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def potential_ssti(self) -> bool:
        return self.validation.potential_ssti

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class SSTIPipeline:
    """
    Coordinate SSTI validation and finding generation.

    The pipeline does not execute template payloads or perform
    exploitation.
    """

    def __init__(
        self,
        validator: SSTIValidator | None = None,
        finding_analyzer: SSTIFindingAnalyzer | None = None,
    ):
        self.validator = validator or SSTIValidator()
        self.finding_analyzer = (
            finding_analyzer or SSTIFindingAnalyzer()
        )

    def run(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: SSTIAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        evaluation_evidence: bool = False,
    ) -> SSTIPipelineResult:
        if not isinstance(analysis, SSTIAnalysis):
            raise TypeError("analysis must be an SSTIAnalysis instance")

        validation = self.validator.validate(
            baseline,
            candidate,
            analysis,
            evaluation_evidence=evaluation_evidence,
        )

        findings = self.finding_analyzer.analyze(
            analysis,
            target,
            endpoint,
        )

        return SSTIPipelineResult(
            validation=validation,
            findings=findings,
        )
