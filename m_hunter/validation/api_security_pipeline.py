from dataclasses import dataclass, field

from m_hunter.analyzers.api_security import APIAnalysis
from m_hunter.validation.api_security import APIValidationResult


@dataclass
class APIPipelineResult:
    validation: APIValidationResult
    accepted: bool
    findings: list[str] = field(default_factory=list)


class APISecurityValidationPipeline:
    def process(
        self,
        analysis: APIAnalysis,
        validation: APIValidationResult,
    ) -> APIPipelineResult:
        if not isinstance(analysis, APIAnalysis):
            raise TypeError(
                "analysis must be an APIAnalysis instance"
            )

        if not isinstance(
            validation,
            APIValidationResult,
        ):
            raise TypeError(
                "validation must be an APIValidationResult instance"
            )

        accepted = (
            analysis.detected
            and (
                validation.potential_api_issue
                or validation.behavior_changed
            )
        )

        findings: list[str] = []

        if accepted:
            findings.append(
                "API behavior requires further security validation."
            )

        return APIPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
