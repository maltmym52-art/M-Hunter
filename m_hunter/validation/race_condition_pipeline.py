from dataclasses import dataclass

from m_hunter.analyzers.race_condition import RaceConditionAnalysis
from m_hunter.analyzers.race_condition_finding import (
    RaceConditionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.race_condition import (
    RaceConditionValidationResult,
    RaceConditionValidator,
)


@dataclass
class RaceConditionPipelineResult:
    validation: RaceConditionValidationResult
    accepted: bool
    findings: list[Finding]


class RaceConditionValidationPipeline:
    def __init__(
        self,
        validator: RaceConditionValidator | None = None,
        finding_analyzer: RaceConditionFindingAnalyzer | None = None,
    ):
        self.validator = validator or RaceConditionValidator()
        self.finding_analyzer = (
            finding_analyzer or RaceConditionFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: RaceConditionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> RaceConditionPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, RaceConditionAnalysis):
            raise TypeError("analysis must be a RaceConditionAnalysis")

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
                validation.potential_race_condition
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

        return RaceConditionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
