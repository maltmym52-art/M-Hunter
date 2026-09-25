from dataclasses import dataclass, field

from m_hunter.analyzers.request_smuggling import (
    RequestSmugglingAnalysis,
)
from m_hunter.analyzers.request_smuggling_finding import (
    RequestSmugglingFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.request_smuggling import (
    RequestSmugglingValidationResult,
    RequestSmugglingValidator,
)


@dataclass
class RequestSmugglingPipelineResult:
    validation: RequestSmugglingValidationResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def potential_smuggling(self) -> bool:
        return self.validation.potential_smuggling

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class RequestSmugglingPipeline:
    def __init__(
        self,
        validator: RequestSmugglingValidator | None = None,
        finding_analyzer: (
            RequestSmugglingFindingAnalyzer | None
        ) = None,
    ):
        self.validator = validator or RequestSmugglingValidator()
        self.finding_analyzer = (
            finding_analyzer
            or RequestSmugglingFindingAnalyzer()
        )

    def run(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: RequestSmugglingAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parser_behavior_changed: bool = False,
    ) -> RequestSmugglingPipelineResult:
        if not isinstance(
            analysis,
            RequestSmugglingAnalysis,
        ):
            raise TypeError(
                "analysis must be a RequestSmugglingAnalysis instance"
            )

        validation = self.validator.validate(
            baseline,
            candidate,
            analysis,
            parser_behavior_changed=parser_behavior_changed,
        )

        findings = self.finding_analyzer.analyze(
            analysis,
            target,
            endpoint,
        )

        return RequestSmugglingPipelineResult(
            validation=validation,
            findings=findings,
        )
