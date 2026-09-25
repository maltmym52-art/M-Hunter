from dataclasses import dataclass, field

from m_hunter.analyzers.csrf import CSRFAnalysis
from m_hunter.analyzers.csrf_finding import CSRFFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.csrf import (
    CSRFValidationResult,
    CSRFValidator,
)


@dataclass
class CSRFPipelineResult:
    validation: CSRFValidationResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def potential_csrf(self) -> bool:
        return self.validation.potential_csrf

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class CSRFPipeline:
    """
    Coordinate CSRF validation and finding generation.

    The pipeline does not send requests or perform exploitation.
    """

    def __init__(
        self,
        validator: CSRFValidator | None = None,
        finding_analyzer: CSRFFindingAnalyzer | None = None,
    ):
        self.validator = validator or CSRFValidator()
        self.finding_analyzer = (
            finding_analyzer or CSRFFindingAnalyzer()
        )

    def run(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: CSRFAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        protection_changed: bool = False,
    ) -> CSRFPipelineResult:
        if not isinstance(analysis, CSRFAnalysis):
            raise TypeError("analysis must be a CSRFAnalysis instance")

        validation = self.validator.validate(
            baseline,
            candidate,
            analysis,
            protection_changed=protection_changed,
        )

        findings = self.finding_analyzer.analyze(
            analysis,
            target,
            endpoint,
        )

        return CSRFPipelineResult(
            validation=validation,
            findings=findings,
        )
