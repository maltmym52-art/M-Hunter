from dataclasses import dataclass

from m_hunter.analyzers.file_inclusion import FileInclusionAnalysis
from m_hunter.analyzers.file_inclusion_finding import (
    FileInclusionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.file_inclusion import (
    FileInclusionValidationResult,
    FileInclusionValidator,
)


@dataclass(frozen=True)
class FileInclusionPipelineResult:
    validation: FileInclusionValidationResult
    accepted: bool
    findings: list[Finding]


class FileInclusionPipeline:
    name = "file_inclusion_pipeline"

    def __init__(
        self,
        validator: FileInclusionValidator | None = None,
        finding_analyzer: FileInclusionFindingAnalyzer | None = None,
    ) -> None:
        self.validator = validator or FileInclusionValidator()
        self.finding_analyzer = (
            finding_analyzer or FileInclusionFindingAnalyzer()
        )

    def run(
        self,
        *,
        baseline_status: int,
        candidate_status: int,
        analysis: FileInclusionAnalysis,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
        baseline_content: str = "",
        candidate_content: str = "",
        baseline_headers: dict[str, str] | None = None,
        candidate_headers: dict[str, str] | None = None,
    ) -> FileInclusionPipelineResult:
        validation = self.validator.validate(
            baseline_status,
            candidate_status,
            baseline_content=baseline_content,
            candidate_content=candidate_content,
            baseline_headers=baseline_headers,
            candidate_headers=candidate_headers,
            analysis=analysis,
        )

        accepted = validation.potential_file_inclusion

        if accepted:
            findings = self.finding_analyzer.create_findings(
                analysis,
                target=target,
                endpoint=endpoint,
                parameter=parameter,
            )
        else:
            findings = []

        return FileInclusionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
