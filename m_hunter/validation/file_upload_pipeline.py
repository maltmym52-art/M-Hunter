from dataclasses import dataclass, field

from m_hunter.analyzers.file_upload import FileUploadAnalysis
from m_hunter.analyzers.file_upload_finding import (
    FileUploadFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.file_upload import (
    FileUploadValidationResult,
    FileUploadValidator,
)


@dataclass(frozen=True)
class FileUploadPipelineResult:
    validation: FileUploadValidationResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def potential_upload_issue(self) -> bool:
        return self.validation.potential_upload_issue

    @property
    def status(self) -> str:
        return self.validation.status

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class FileUploadPipeline:
    """
    Coordinates file-upload validation and finding generation.

    The pipeline works with already-collected baseline/candidate
    responses and does not perform uploads or file execution itself.
    """

    name = "file_upload_pipeline"

    def __init__(
        self,
        validator: FileUploadValidator | None = None,
        finding_analyzer: FileUploadFindingAnalyzer | None = None,
    ):
        self.validator = validator or FileUploadValidator()
        self.finding_analyzer = (
            finding_analyzer
            or FileUploadFindingAnalyzer()
        )

    def run(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: FileUploadAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> FileUploadPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError(
                "baseline must be an HttpResponse"
            )

        if not isinstance(candidate, HttpResponse):
            raise TypeError(
                "candidate must be an HttpResponse"
            )

        if not isinstance(analysis, FileUploadAnalysis):
            raise TypeError(
                "analysis must be a FileUploadAnalysis"
            )

        validation = self.validator.validate(
            baseline,
            candidate,
            analysis,
        )

        findings = self.finding_analyzer.analyze(
            analysis,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
        )

        return FileUploadPipelineResult(
            validation=validation,
            findings=findings,
        )
