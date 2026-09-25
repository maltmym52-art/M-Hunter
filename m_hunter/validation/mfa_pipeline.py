from dataclasses import dataclass, field

from m_hunter.analyzers.mfa import MFAAnalysis
from m_hunter.analyzers.mfa_finding import MFAFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.mfa import MFAValidationResult, MFAValidator


@dataclass(frozen=True)
class MFAPipelineResult:
    validation: MFAValidationResult
    accepted: bool
    findings: list[Finding] = field(default_factory=list)


class MFAValidationPipeline:
    """Combine MFA analysis, validation, and finding generation."""

    def __init__(
        self,
        validator: MFAValidator | None = None,
        finding_analyzer: MFAFindingAnalyzer | None = None,
    ):
        self.validator = validator or MFAValidator()
        self.finding_analyzer = (
            finding_analyzer or MFAFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: MFAAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> MFAPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, MFAAnalysis):
            raise TypeError("analysis must be an MFAAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
            behavior_changed=behavior_changed,
        )

        accepted = (
            analysis.detected
            and (
                validation.potential_mfa_issue
                or validation.behavior_changed
            )
        )

        findings: list[Finding] = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis=analysis,
                target=target,
                endpoint=endpoint,
            )

        return MFAPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
