from dataclasses import dataclass

from m_hunter.analyzers.cors_advanced import (
    CORSAdvancedAnalysis,
)
from m_hunter.analyzers.cors_advanced_finding import (
    CORSAdvancedFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.cors_advanced import (
    CORSAdvancedValidationResult,
    CORSAdvancedValidator,
)


@dataclass(frozen=True)
class CORSAdvancedPipelineResult:
    validation: CORSAdvancedValidationResult
    accepted: bool
    findings: list[Finding]


class CORSAdvancedPipeline:
    name = "cors_advanced_pipeline"

    def __init__(
        self,
        validator: CORSAdvancedValidator | None = None,
        finding_analyzer: (
            CORSAdvancedFindingAnalyzer | None
        ) = None,
    ) -> None:
        self.validator = (
            validator
            if validator is not None
            else CORSAdvancedValidator()
        )

        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else CORSAdvancedFindingAnalyzer()
        )

    def process(
        self,
        analysis: CORSAdvancedAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        target: str,
        endpoint: str | None = None,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> CORSAdvancedPipelineResult:
        if not isinstance(
            analysis,
            CORSAdvancedAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of "
                "CORSAdvancedAnalysis"
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

        validation = self.validator.validate(
            analysis,
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
        )

        accepted = validation.potential_cors_issue

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return CORSAdvancedPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
