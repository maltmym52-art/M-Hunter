from dataclasses import dataclass

from m_hunter.analyzers.http2_security import (
    HTTP2SecurityAnalysis,
)
from m_hunter.analyzers.http2_security_finding import (
    HTTP2SecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.http2_security import (
    HTTP2SecurityValidationResult,
    HTTP2SecurityValidator,
)


@dataclass
class HTTP2SecurityPipelineResult:
    validation: HTTP2SecurityValidationResult
    accepted: bool
    findings: list[Finding]


class HTTP2SecurityValidationPipeline:
    name = "http2_security_pipeline"

    def __init__(
        self,
        validator: HTTP2SecurityValidator | None = None,
        finding_analyzer: HTTP2SecurityFindingAnalyzer | None = None,
    ):
        self.validator = validator or HTTP2SecurityValidator()
        self.finding_analyzer = (
            finding_analyzer
            or HTTP2SecurityFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: HTTP2SecurityAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> HTTP2SecurityPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, HTTP2SecurityAnalysis):
            raise TypeError(
                "analysis must be HTTP2SecurityAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
        )

        accepted = validation.potential_http2_security_issue

        findings = (
            self.finding_analyzer.create_findings(
                analysis,
                target,
                endpoint,
            )
            if accepted
            else []
        )

        return HTTP2SecurityPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
