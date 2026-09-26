from dataclasses import dataclass

from m_hunter.analyzers.jwt import JWTAnalysis
from m_hunter.analyzers.jwt_finding import JWTFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.jwt import (
    JWTValidationResult,
    JWTValidator,
)


@dataclass(frozen=True)
class JWTPipelineResult:
    validation: JWTValidationResult
    accepted: bool
    findings: list[Finding]


class JWTValidationPipeline:
    def __init__(
        self,
        validator: JWTValidator | None = None,
        finding_analyzer: JWTFindingAnalyzer | None = None,
    ):
        self.validator = validator or JWTValidator()
        self.finding_analyzer = (
            finding_analyzer or JWTFindingAnalyzer()
        )

    def process(
        self,
        *,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: JWTAnalysis,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> JWTPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, JWTAnalysis):
            raise TypeError("analysis must be a JWTAnalysis")

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
                validation.potential_jwt_issue
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

        return JWTPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
