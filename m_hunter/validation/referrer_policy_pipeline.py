from dataclasses import dataclass

from m_hunter.analyzers.referrer_policy import (
    ReferrerPolicyAnalysis,
)
from m_hunter.analyzers.referrer_policy_finding import (
    ReferrerPolicyFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.referrer_policy import (
    ReferrerPolicyValidationResult,
    ReferrerPolicyValidator,
)


@dataclass(frozen=True)
class ReferrerPolicyPipelineResult:
    validation: ReferrerPolicyValidationResult
    accepted: bool
    findings: list[Finding]


class ReferrerPolicyPipeline:
    name = "referrer_policy_pipeline"

    def __init__(
        self,
        validator: ReferrerPolicyValidator | None = None,
        finding_analyzer: (
            ReferrerPolicyFindingAnalyzer | None
        ) = None,
    ) -> None:
        self.validator = (
            validator
            if validator is not None
            else ReferrerPolicyValidator()
        )
        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else ReferrerPolicyFindingAnalyzer()
        )

    def process(
        self,
        analysis: ReferrerPolicyAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        target: str,
        endpoint: str | None = None,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> ReferrerPolicyPipelineResult:
        if not isinstance(
            analysis,
            ReferrerPolicyAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of "
                "ReferrerPolicyAnalysis"
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
            validation.potential_referrer_policy_issue
        )

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return ReferrerPolicyPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
