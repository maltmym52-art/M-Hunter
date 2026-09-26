from dataclasses import dataclass

from m_hunter.analyzers.idor import IDORAnalysis
from m_hunter.analyzers.idor_finding import IDORFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.validation.idor import (
    IDORValidationResult,
    IDORValidator,
)


@dataclass(frozen=True)
class IDORPipelineResult:
    validation: IDORValidationResult
    accepted: bool
    findings: list[Finding]


class IDORPipeline:
    name = "idor_pipeline"

    def __init__(
        self,
        validator: IDORValidator | None = None,
        finding_analyzer: IDORFindingAnalyzer | None = None,
    ) -> None:
        self.validator = (
            validator
            if validator is not None
            else IDORValidator()
        )
        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else IDORFindingAnalyzer()
        )

    def run(
        self,
        *,
        analysis: IDORAnalysis,
        baseline_request: HttpRequest,
        baseline_response: HttpResponse,
        candidate_request: HttpRequest,
        candidate_response: HttpResponse,
        parameter: str,
        original_value: str,
        candidate_value: str,
        target: str,
        endpoint: str | None = None,
        identity_changed: bool = False,
        authorization_context_changed: bool = False,
    ) -> IDORPipelineResult:
        validation = self.validator.validate(
            baseline_request=baseline_request,
            baseline_response=baseline_response,
            candidate_request=candidate_request,
            candidate_response=candidate_response,
            parameter=parameter,
            original_value=original_value,
            candidate_value=candidate_value,
            identity_changed=identity_changed,
            authorization_context_changed=(
                authorization_context_changed
            ),
        )

        accepted = bool(
            analysis.detected
            and validation.potentially_accessible
        )

        findings = (
            self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
                parameter=parameter,
            )
            if accepted
            else []
        )

        return IDORPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
