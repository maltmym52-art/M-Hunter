from dataclasses import dataclass

from m_hunter.analyzers.permissions_policy import (
    PermissionsPolicyAnalysis,
)
from m_hunter.analyzers.permissions_policy_finding import (
    PermissionsPolicyFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.permissions_policy import (
    PermissionsPolicyValidationResult,
    PermissionsPolicyValidator,
)


@dataclass(frozen=True)
class PermissionsPolicyPipelineResult:
    validation: PermissionsPolicyValidationResult
    accepted: bool
    findings: list[Finding]


class PermissionsPolicyPipeline:
    name = "permissions_policy_pipeline"

    def __init__(
        self,
        validator: PermissionsPolicyValidator | None = None,
        finding_analyzer: (
            PermissionsPolicyFindingAnalyzer | None
        ) = None,
    ) -> None:
        self.validator = (
            validator
            if validator is not None
            else PermissionsPolicyValidator()
        )

        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else PermissionsPolicyFindingAnalyzer()
        )

    def process(
        self,
        analysis: PermissionsPolicyAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        target: str,
        endpoint: str | None = None,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> PermissionsPolicyPipelineResult:
        if not isinstance(
            analysis,
            PermissionsPolicyAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of "
                "PermissionsPolicyAnalysis"
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

        accepted = (
            validation.potential_permissions_policy_issue
        )

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return PermissionsPolicyPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
