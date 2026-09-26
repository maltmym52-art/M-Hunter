from dataclasses import dataclass

from m_hunter.analyzers.nosql_injection import NoSQLInjectionAnalysis
from m_hunter.analyzers.nosql_injection_finding import (
    NoSQLInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.nosql_injection import (
    NoSQLInjectionValidationResult,
    NoSQLInjectionValidator,
)


@dataclass
class NoSQLInjectionPipelineResult:
    validation: NoSQLInjectionValidationResult
    accepted: bool
    findings: list[Finding]


class NoSQLInjectionValidationPipeline:
    name = "nosql_injection_pipeline"

    def __init__(
        self,
        validator: NoSQLInjectionValidator | None = None,
        finding_analyzer: NoSQLInjectionFindingAnalyzer | None = None,
    ):
        self.validator = validator or NoSQLInjectionValidator()
        self.finding_analyzer = (
            finding_analyzer
            or NoSQLInjectionFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: NoSQLInjectionAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> NoSQLInjectionPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, NoSQLInjectionAnalysis):
            raise TypeError(
                "analysis must be NoSQLInjectionAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
        )

        accepted = validation.potential_nosql_injection

        findings = (
            self.finding_analyzer.create_findings(
                analysis,
                target,
                endpoint,
            )
            if accepted
            else []
        )

        return NoSQLInjectionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
