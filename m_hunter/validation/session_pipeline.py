from dataclasses import dataclass

from m_hunter.analyzers.session import SessionAnalysis
from m_hunter.analyzers.session_finding import SessionFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.session import (
    SessionValidationResult,
    SessionValidator,
)


@dataclass(frozen=True)
class SessionPipelineResult:
    validation: SessionValidationResult
    accepted: bool
    findings: list[Finding]


class SessionValidationPipeline:
    def __init__(
        self,
        validator: SessionValidator | None = None,
        finding_analyzer: SessionFindingAnalyzer | None = None,
    ):
        self.validator = validator or SessionValidator()
        self.finding_analyzer = (
            finding_analyzer or SessionFindingAnalyzer()
        )

    def process(
        self,
        *,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: SessionAnalysis,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> SessionPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, SessionAnalysis):
            raise TypeError("analysis must be a SessionAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        if not isinstance(behavior_changed, bool):
            raise TypeError("behavior_changed must be a bool")

        validation = self.validator.compare(
            baseline=baseline,
            candidate=candidate,
            analysis=analysis,
            behavior_changed=behavior_changed,
        )

        accepted = (
            analysis.detected
            and (
                validation.potential_session_issue
                or validation.behavior_changed
            )
        )

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis=analysis,
                target=target,
                endpoint=endpoint,
            )

        return SessionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
