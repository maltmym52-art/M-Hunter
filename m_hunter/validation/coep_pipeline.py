from dataclasses import dataclass

from m_hunter.analyzers.coep import COEPAnalysis
from m_hunter.analyzers.coep_finding import COEPFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.coep import (
    COEPValidationResult,
    COEPValidator,
)


@dataclass(frozen=True)
class COEPPipelineResult:
    validation: COEPValidationResult
    accepted: bool
    findings: list[Finding]


class COEPPipeline:
    name = "coep_pipeline"

    def __init__(
        self,
        validator: COEPValidator | None = None,
        finding_analyzer: COEPFindingAnalyzer | None = None,
    ) -> None:
        self.validator = (
            validator
            if validator is not None
            else COEPValidator()
        )
        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else COEPFindingAnalyzer()
        )

    def process(
        self,
        analysis: COEPAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        target: str,
        endpoint: str | None = None,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> COEPPipelineResult:
        if not isinstance(analysis, COEPAnalysis):
            raise TypeError(
                "analysis must be an instance of COEPAnalysis"
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

        accepted = validation.potential_coep_issue

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return COEPPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
