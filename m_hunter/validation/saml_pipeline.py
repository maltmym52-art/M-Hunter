from dataclasses import dataclass

from m_hunter.analyzers.saml import SAMLAnalysis
from m_hunter.analyzers.saml_finding import SAMLFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.saml import (
    SAMLValidationResult,
    SAMLValidator,
)


@dataclass(frozen=True)
class SAMLPipelineResult:
    validation: SAMLValidationResult
    accepted: bool
    findings: list[Finding]


class SAMLValidationPipeline:
    """Run SAML validation and convert accepted results into findings."""

    def __init__(
        self,
        validator: SAMLValidator | None = None,
        finding_analyzer: SAMLFindingAnalyzer | None = None,
    ):
        self.validator = validator or SAMLValidator()
        self.finding_analyzer = (
            finding_analyzer or SAMLFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: SAMLAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> SAMLPipelineResult:
        if not isinstance(analysis, SAMLAnalysis):
            raise TypeError("analysis must be a SAMLAnalysis")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
            behavior_changed=behavior_changed,
        )

        accepted = (
            analysis.detected
            and (
                validation.potential_saml_issue
                or validation.behavior_changed
            )
        )

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis,
                target=target,
                endpoint=endpoint,
            )

        return SAMLPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
