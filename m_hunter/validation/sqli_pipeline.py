from dataclasses import dataclass

from m_hunter.analyzers.sqli import SQLiAnalysis
from m_hunter.analyzers.sqli_finding import SQLiFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.sqli import SQLiValidationResult, SQLiValidator


@dataclass(frozen=True)
class SQLiPipelineResult:
    validation: SQLiValidationResult
    findings: tuple[Finding, ...]

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


class SQLiPipeline:
    """
    Coordinates SQLi validation and finding generation.

    Database error indicators are not treated as confirmed
    exploitable SQL injection.
    """

    def __init__(
        self,
        validator: SQLiValidator | None = None,
        finding_analyzer: SQLiFindingAnalyzer | None = None,
    ):
        self.validator = validator or SQLiValidator()
        self.finding_analyzer = (
            finding_analyzer or SQLiFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: SQLiAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> SQLiPipelineResult:
        validation = self.validator.validate(
            baseline,
            candidate,
            analysis,
        )

        findings = self.finding_analyzer.analyze(
            analysis,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
        )

        return SQLiPipelineResult(
            validation=validation,
            findings=tuple(findings),
        )
