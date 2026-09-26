from dataclasses import dataclass

from m_hunter.analyzers.hpp import HPPAnalysis
from m_hunter.analyzers.hpp_finding import HPPFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.hpp import HPPValidationResult, HPPValidator


@dataclass
class HPPPipelineResult:
    validation: HPPValidationResult
    accepted: bool
    findings: list[Finding]


class HPPValidationPipeline:
    def __init__(
        self,
        validator: HPPValidator | None = None,
        finding_analyzer: HPPFindingAnalyzer | None = None,
    ):
        self.validator = validator or HPPValidator()
        self.finding_analyzer = (
            finding_analyzer or HPPFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: HPPAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> HPPPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, HPPAnalysis):
            raise TypeError("analysis must be an HPPAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
            behavior_changed=behavior_changed,
        )

        accepted = (
            analysis.detected
            and (
                validation.potential_hpp_issue
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

        return HPPPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
