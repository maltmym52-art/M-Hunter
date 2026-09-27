from dataclasses import dataclass

from m_hunter.analyzers.coop import COOPAnalysis
from m_hunter.analyzers.coop_finding import COOPFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.coop import (
    COOPValidationResult,
    COOPValidator,
)


@dataclass(frozen=True)
class COOPPipelineResult:
    validation: COOPValidationResult
    accepted: bool
    findings: list[Finding]


class COOPPipeline:
    name = "coop_pipeline"

    def __init__(
        self,
        validator: COOPValidator | None = None,
        finding_analyzer: COOPFindingAnalyzer | None = None,
    ) -> None:
        self.validator = (
            validator
            if validator is not None
            else COOPValidator()
        )
        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else COOPFindingAnalyzer()
        )

    def process(
        self,
        analysis: COOPAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        target: str,
        endpoint: str | None = None,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> COOPPipelineResult:
        if not isinstance(analysis, COOPAnalysis):
            raise TypeError(
                "analysis must be an instance of COOPAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                "target must be a non-empty string"
            )

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError(
                "endpoint must be a string or None"
            )

        validation = self.validator.validate(
            analysis,
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
        )

        accepted = validation.potential_coop_issue

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return COOPPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
