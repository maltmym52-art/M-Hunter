from dataclasses import dataclass

from m_hunter.analyzers.corp import CORPAnalysis
from m_hunter.analyzers.corp_finding import CORPFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.corp import (
    CORPValidationResult,
    CORPValidator,
)


@dataclass(frozen=True)
class CORPPipelineResult:
    validation: CORPValidationResult
    accepted: bool
    findings: list[Finding]


class CORPPipeline:
    name = "corp_pipeline"

    def __init__(
        self,
        validator: CORPValidator | None = None,
        finding_analyzer: CORPFindingAnalyzer | None = None,
    ) -> None:
        self.validator = (
            validator if validator is not None else CORPValidator()
        )
        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else CORPFindingAnalyzer()
        )

    def process(
        self,
        analysis: CORPAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        target: str,
        endpoint: str | None = None,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> CORPPipelineResult:
        if not isinstance(analysis, CORPAnalysis):
            raise TypeError(
                "analysis must be an instance of CORPAnalysis"
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

        accepted = validation.potential_corp_issue

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return CORPPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
