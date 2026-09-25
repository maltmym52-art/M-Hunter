from dataclasses import dataclass

from m_hunter.analyzers.oauth import OAuthAnalysis
from m_hunter.analyzers.oauth_finding import OAuthFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.oauth import (
    OAuthValidationResult,
    OAuthValidator,
)


@dataclass(frozen=True)
class OAuthPipelineResult:
    validation: OAuthValidationResult
    accepted: bool
    findings: tuple[Finding, ...]


class OAuthValidationPipeline:
    """Connects OAuth analysis, validation, and finding generation."""

    def __init__(
        self,
        validator: OAuthValidator | None = None,
        finding_analyzer: OAuthFindingAnalyzer | None = None,
    ):
        self.validator = validator or OAuthValidator()
        self.finding_analyzer = (
            finding_analyzer
            or OAuthFindingAnalyzer()
        )

    def process(
        self,
        analysis: OAuthAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        baseline_status: int | None = None,
        candidate_status: int | None = None,
        baseline_content: str | bytes | None = None,
        candidate_content: str | bytes | None = None,
        baseline_headers: dict[str, str] | None = None,
        candidate_headers: dict[str, str] | None = None,
        behavior_changed: bool = False,
    ) -> OAuthPipelineResult:
        if not isinstance(analysis, OAuthAnalysis):
            raise TypeError(
                "analysis must be an OAuthAnalysis"
            )

        validation = self.validator.validate(
            analysis,
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            baseline_content=baseline_content,
            candidate_content=candidate_content,
            baseline_headers=baseline_headers,
            candidate_headers=candidate_headers,
            behavior_changed=behavior_changed,
        )

        accepted = (
            analysis.detected
            and (
                validation.potential_oauth_issue
                or validation.behavior_changed
            )
        )

        findings: tuple[Finding, ...] = ()

        if accepted:
            findings = tuple(
                self.finding_analyzer.analyze(
                    analysis,
                    target=target,
                    endpoint=endpoint,
                )
            )

        return OAuthPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
