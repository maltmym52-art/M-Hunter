from dataclasses import dataclass

from m_hunter.analyzers.host_header_injection import (
    HostHeaderInjectionAnalysis,
)
from m_hunter.analyzers.host_header_injection_finding import (
    HostHeaderInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.host_header_injection import (
    HostHeaderInjectionValidationResult,
    HostHeaderInjectionValidator,
)


@dataclass(frozen=True)
class HostHeaderInjectionPipelineResult:
    validation: HostHeaderInjectionValidationResult
    accepted: bool
    findings: list[Finding]


class HostHeaderInjectionValidationPipeline:
    def __init__(
        self,
        validator: HostHeaderInjectionValidator | None = None,
        finding_analyzer: HostHeaderInjectionFindingAnalyzer | None = None,
    ):
        self.validator = validator or HostHeaderInjectionValidator()
        self.finding_analyzer = (
            finding_analyzer
            or HostHeaderInjectionFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: HostHeaderInjectionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> HostHeaderInjectionPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(
            analysis,
            HostHeaderInjectionAnalysis,
        ):
            raise TypeError(
                "analysis must be a HostHeaderInjectionAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        if not isinstance(behavior_changed, bool):
            raise TypeError(
                "behavior_changed must be a boolean"
            )

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
            behavior_changed=behavior_changed,
        )

        accepted = (
            analysis.detected
            and (
                validation.potential_host_header_injection
                or validation.behavior_changed
            )
        )

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return HostHeaderInjectionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
