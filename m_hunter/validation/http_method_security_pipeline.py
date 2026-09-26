from dataclasses import dataclass

from m_hunter.analyzers.http_method_security import (
    HTTPMethodSecurityAnalysis,
)
from m_hunter.analyzers.http_method_security_finding import (
    HTTPMethodSecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.http_method_security import (
    HTTPMethodSecurityValidationResult,
    HTTPMethodSecurityValidator,
)


@dataclass(frozen=True)
class HTTPMethodSecurityPipelineResult:
    validation: HTTPMethodSecurityValidationResult
    accepted: bool
    findings: list[Finding]


class HTTPMethodSecurityValidationPipeline:
    def __init__(
        self,
        validator: HTTPMethodSecurityValidator | None = None,
        finding_analyzer: HTTPMethodSecurityFindingAnalyzer | None = None,
    ):
        self.validator = validator or HTTPMethodSecurityValidator()
        self.finding_analyzer = (
            finding_analyzer
            or HTTPMethodSecurityFindingAnalyzer()
        )

    def process(
        self,
        *,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: HTTPMethodSecurityAnalysis,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> HTTPMethodSecurityPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError(
                "baseline must be an HttpResponse"
            )

        if not isinstance(candidate, HttpResponse):
            raise TypeError(
                "candidate must be an HttpResponse"
            )

        if not isinstance(
            analysis,
            HTTPMethodSecurityAnalysis,
        ):
            raise TypeError(
                "analysis must be an HTTPMethodSecurityAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                "target must be a non-empty string"
            )

        if endpoint is not None and not isinstance(
            endpoint,
            str,
        ):
            raise TypeError(
                "endpoint must be a string or None"
            )

        if not isinstance(behavior_changed, bool):
            raise TypeError(
                "behavior_changed must be a bool"
            )

        validation = self.validator.compare(
            baseline=baseline,
            candidate=candidate,
            analysis=analysis,
            behavior_changed=behavior_changed,
        )

        accepted = (
            validation.potential_http_method_security_issue
        )

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis=analysis,
                target=target,
                endpoint=endpoint,
            )

        return HTTPMethodSecurityPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
