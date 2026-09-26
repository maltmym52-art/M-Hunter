from dataclasses import dataclass

from m_hunter.analyzers.websocket_security import (
    WebSocketSecurityAnalysis,
)
from m_hunter.analyzers.websocket_security_finding import (
    WebSocketSecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.websocket_security import (
    WebSocketSecurityValidationResult,
    WebSocketSecurityValidator,
)


@dataclass
class WebSocketSecurityPipelineResult:
    validation: WebSocketSecurityValidationResult
    accepted: bool
    findings: list[Finding]


class WebSocketSecurityValidationPipeline:
    name = "websocket_security_pipeline"

    def __init__(
        self,
        validator: WebSocketSecurityValidator | None = None,
        finding_analyzer: WebSocketSecurityFindingAnalyzer | None = None,
    ):
        self.validator = validator or WebSocketSecurityValidator()
        self.finding_analyzer = (
            finding_analyzer
            or WebSocketSecurityFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: WebSocketSecurityAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> WebSocketSecurityPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be HttpResponse")

        if not isinstance(analysis, WebSocketSecurityAnalysis):
            raise TypeError(
                "analysis must be WebSocketSecurityAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
        )

        accepted = validation.potential_websocket_security_issue

        findings = (
            self.finding_analyzer.create_findings(
                analysis,
                target,
                endpoint,
            )
            if accepted
            else []
        )

        return WebSocketSecurityPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
