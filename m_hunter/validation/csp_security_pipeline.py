from dataclasses import dataclass

from m_hunter.analyzers.csp_security import CSPAnalysis
from m_hunter.analyzers.csp_security_finding import CSPFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.csp_security import (
    CSPValidationResult,
    CSPValidator,
)


@dataclass(frozen=True)
class CSPPipelineResult:
    validation: CSPValidationResult
    accepted: bool
    findings: list[Finding]


class CSPPipeline:
    name = "csp_security_pipeline"

    def __init__(
        self,
        validator: CSPValidator | None = None,
        finding_analyzer: CSPFindingAnalyzer | None = None,
    ) -> None:
        self.validator = (
            validator
            if validator is not None
            else CSPValidator()
        )
        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else CSPFindingAnalyzer()
        )

    def process(
        self,
        analysis: CSPAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        target: str,
        endpoint: str | None = None,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> CSPPipelineResult:
        if not isinstance(analysis, CSPAnalysis):
            raise TypeError(
                "analysis must be an instance of CSPAnalysis"
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

        accepted = validation.potential_csp_issue

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return CSPPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
