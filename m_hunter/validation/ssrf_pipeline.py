from dataclasses import dataclass, field

from m_hunter.analyzers.ssrf import SSRFAnalysis
from m_hunter.analyzers.ssrf_finding import SSRFFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.ssrf import SSRFValidationResult, SSRFValidator


@dataclass(frozen=True)
class SSRFPipelineResult:
    validation: SSRFValidationResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def potential_ssrf(self) -> bool:
        return self.validation.potential_ssrf

    @property
    def status(self) -> str:
        return self.validation.status

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class SSRFPipeline:
    """
    Coordinates SSRF validation and finding generation.

    The pipeline operates on already-collected baseline/candidate
    responses. It does not perform network requests itself.
    """

    name = "ssrf_pipeline"

    def __init__(
        self,
        validator: SSRFValidator | None = None,
        finding_analyzer: SSRFFindingAnalyzer | None = None,
    ):
        self.validator = validator or SSRFValidator()
        self.finding_analyzer = (
            finding_analyzer or SSRFFindingAnalyzer()
        )

    def run(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: SSRFAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> SSRFPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, SSRFAnalysis):
            raise TypeError("analysis must be an SSRFAnalysis")

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

        return SSRFPipelineResult(
            validation=validation,
            findings=findings,
        )
