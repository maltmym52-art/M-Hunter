from dataclasses import dataclass

from m_hunter.analyzers.crlf_injection import CRLFInjectionAnalysis
from m_hunter.analyzers.crlf_injection_finding import (
    CRLFInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.crlf_injection import (
    CRLFInjectionValidationResult,
    CRLFInjectionValidator,
)


@dataclass(frozen=True)
class CRLFInjectionPipelineResult:
    validation: CRLFInjectionValidationResult
    accepted: bool
    findings: list[Finding]


class CRLFInjectionValidationPipeline:
    def __init__(
        self,
        validator: CRLFInjectionValidator | None = None,
        finding_analyzer: CRLFInjectionFindingAnalyzer | None = None,
    ):
        self.validator = validator or CRLFInjectionValidator()
        self.finding_analyzer = (
            finding_analyzer
            or CRLFInjectionFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: CRLFInjectionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> CRLFInjectionPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, CRLFInjectionAnalysis):
            raise TypeError(
                "analysis must be a CRLFInjectionAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        if not isinstance(behavior_changed, bool):
            raise TypeError("behavior_changed must be a boolean")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
            behavior_changed=behavior_changed,
        )

        accepted = (
            analysis.detected
            and (
                validation.potential_crlf_injection
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

        return CRLFInjectionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
