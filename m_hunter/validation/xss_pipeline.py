from dataclasses import dataclass

from m_hunter.analyzers.xss import XSSAnalysis
from m_hunter.analyzers.xss_finding import XSSFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.xss import XSSValidationResult, XSSValidator


@dataclass(frozen=True)
class XSSPipelineResult:
    validation: XSSValidationResult
    findings: tuple[Finding, ...]

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


class XSSPipeline:
    """
    Coordinates XSS analysis, validation, and finding generation.

    Reflection is not treated as confirmed execution.
    """

    def __init__(
        self,
        validator: XSSValidator | None = None,
        finding_analyzer: XSSFindingAnalyzer | None = None,
    ):
        self.validator = validator or XSSValidator()
        self.finding_analyzer = (
            finding_analyzer or XSSFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: XSSAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
        execution_evidence: bool = False,
    ) -> XSSPipelineResult:
        validation = self.validator.validate(
            baseline,
            candidate,
            analysis,
            execution_evidence=execution_evidence,
        )

        findings = self.finding_analyzer.analyze(
            analysis,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
        )

        return XSSPipelineResult(
            validation=validation,
            findings=tuple(findings),
        )
