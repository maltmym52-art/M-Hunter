from dataclasses import dataclass

from m_hunter.analyzers.clickjacking import ClickjackingAnalysis
from m_hunter.analyzers.clickjacking_finding import (
    ClickjackingFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.clickjacking import (
    ClickjackingValidationResult,
    ClickjackingValidator,
)


@dataclass(frozen=True)
class ClickjackingPipelineResult:
    validation: ClickjackingValidationResult
    accepted: bool
    findings: list[Finding]


class ClickjackingPipeline:
    name = "clickjacking_pipeline"

    def __init__(
        self,
        validator: ClickjackingValidator | None = None,
        finding_analyzer: ClickjackingFindingAnalyzer | None = None,
    ) -> None:
        self.validator = (
            validator
            if validator is not None
            else ClickjackingValidator()
        )
        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else ClickjackingFindingAnalyzer()
        )

    def run(
        self,
        *,
        analysis: ClickjackingAnalysis,
        baseline_status: int,
        candidate_status: int,
        target: str,
        endpoint: str | None = None,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> ClickjackingPipelineResult:
        validation = self.validator.validate(
            analysis,
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
        )

        accepted = validation.potential_clickjacking

        findings = (
            self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )
            if accepted
            else []
        )

        return ClickjackingPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
