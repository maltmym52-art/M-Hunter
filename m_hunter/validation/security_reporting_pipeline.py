from dataclasses import dataclass

from m_hunter.analyzers.security_reporting import (
    SecurityReportingAnalysis,
)
from m_hunter.analyzers.security_reporting_finding import (
    SecurityReportingFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.security_reporting import (
    SecurityReportingValidationResult,
    SecurityReportingValidator,
)


@dataclass(frozen=True)
class SecurityReportingPipelineResult:
    validation: SecurityReportingValidationResult
    accepted: bool
    findings: list[Finding]


class SecurityReportingPipeline:
    name = "security_reporting_pipeline"

    def __init__(
        self,
        validator: SecurityReportingValidator | None = None,
        finding_analyzer: SecurityReportingFindingAnalyzer | None = None,
    ) -> None:
        self.validator = (
            validator
            if validator is not None
            else SecurityReportingValidator()
        )
        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else SecurityReportingFindingAnalyzer()
        )

    def process(
        self,
        analysis: SecurityReportingAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        target: str,
        endpoint: str | None = None,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> SecurityReportingPipelineResult:
        if not isinstance(
            analysis,
            SecurityReportingAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of "
                "SecurityReportingAnalysis"
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

        accepted = validation.potential_security_reporting_issue

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return SecurityReportingPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
