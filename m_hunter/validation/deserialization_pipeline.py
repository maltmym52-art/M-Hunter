from dataclasses import dataclass, field

from m_hunter.analyzers.deserialization import (
    DeserializationAnalysis,
)
from m_hunter.analyzers.deserialization_finding import (
    DeserializationFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.deserialization import (
    DeserializationValidationResult,
    DeserializationValidator,
)


@dataclass
class DeserializationPipelineResult:
    validation: DeserializationValidationResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def potential_deserialization(self) -> bool:
        return self.validation.potential_deserialization

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class DeserializationPipeline:
    def __init__(
        self,
        validator: DeserializationValidator | None = None,
        finding_analyzer: (
            DeserializationFindingAnalyzer | None
        ) = None,
    ):
        self.validator = validator or DeserializationValidator()
        self.finding_analyzer = (
            finding_analyzer
            or DeserializationFindingAnalyzer()
        )

    def run(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: DeserializationAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> DeserializationPipelineResult:
        if not isinstance(
            analysis,
            DeserializationAnalysis,
        ):
            raise TypeError(
                "analysis must be a DeserializationAnalysis instance"
            )

        validation = self.validator.validate(
            baseline,
            candidate,
            analysis,
            behavior_changed=behavior_changed,
        )

        findings = self.finding_analyzer.analyze(
            analysis,
            target,
            endpoint,
        )

        return DeserializationPipelineResult(
            validation=validation,
            findings=findings,
        )
