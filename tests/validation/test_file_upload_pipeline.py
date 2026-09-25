import pytest

from m_hunter.analyzers.file_upload import (
    FileUploadAnalysis,
    FileUploadIndicator,
    FileUploadIndicatorType,
)
from m_hunter.analyzers.file_upload_finding import (
    FileUploadFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.file_upload import (
    FileUploadValidator,
)
from m_hunter.validation.file_upload_pipeline import (
    FileUploadPipeline,
    FileUploadPipelineResult,
)


def response(
    content: bytes,
    *,
    status_code: int = 200,
) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/upload",
        headers={"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def analysis(
    indicator_type: str = FileUploadIndicatorType.DANGEROUS_EXTENSION,
) -> FileUploadAnalysis:
    return FileUploadAnalysis(
        indicators=[
            FileUploadIndicator(
                type=indicator_type,
                evidence="shell.php",
                position=0,
            )
        ]
    )


class TestFileUploadPipeline:
    def test_creation(self):
        assert FileUploadPipeline() is not None

    def test_default_validator(self):
        pipeline = FileUploadPipeline()

        assert isinstance(
            pipeline.validator,
            FileUploadValidator,
        )

    def test_default_finding_analyzer(self):
        pipeline = FileUploadPipeline()

        assert isinstance(
            pipeline.finding_analyzer,
            FileUploadFindingAnalyzer,
        )

    def test_result_type(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://example.com",
        )

        assert isinstance(
            result,
            FileUploadPipelineResult,
        )

    def test_pipeline_detects_potential_issue(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://example.com",
        )

        assert result.potential_upload_issue is True
        assert result.status == "potential_upload_issue"

    def test_pipeline_generates_findings(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://example.com",
        )

        assert result.finding_count == 1
        assert isinstance(
            result.findings[0],
            Finding,
        )

    def test_target_is_preserved(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://target.example",
        )

        assert (
            result.findings[0].target
            == "https://target.example"
        )

    def test_endpoint_is_preserved(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://target.example",
            endpoint="/upload",
        )

        assert result.findings[0].endpoint == "/upload"

    def test_parameter_is_preserved(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://target.example",
            parameter="file",
        )

        assert result.findings[0].parameter == "file"

    def test_empty_analysis(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"different"),
            FileUploadAnalysis(),
            target="https://example.com",
        )

        assert result.status == "no_indicator"
        assert result.potential_upload_issue is False
        assert result.findings == []
        assert result.finding_count == 0

    def test_indicator_without_response_change(self):
        same = response(b"upload response")

        result = FileUploadPipeline().run(
            same,
            same,
            analysis(),
            target="https://example.com",
        )

        assert result.status == "indicator_detected"
        assert result.potential_upload_issue is False
        assert result.finding_count == 1

    def test_response_change_without_indicator(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"different response"),
            FileUploadAnalysis(),
            target="https://example.com",
        )

        assert result.validation.response_changed is True
        assert result.potential_upload_issue is False
        assert result.findings == []

    def test_multiple_indicator_types(self):
        current_analysis = FileUploadAnalysis(
            indicators=[
                FileUploadIndicator(
                    type=(
                        FileUploadIndicatorType
                        .DANGEROUS_EXTENSION
                    ),
                    evidence="shell.php",
                    position=0,
                ),
                FileUploadIndicator(
                    type=(
                        FileUploadIndicatorType
                        .MIME_MISMATCH
                    ),
                    evidence="image.php/image/jpeg",
                    position=10,
                ),
            ]
        )

        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            current_analysis,
            target="https://example.com",
        )

        assert result.potential_upload_issue is True
        assert result.finding_count == 2

    def test_dangerous_mime_pipeline(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.DANGEROUS_MIME
            ),
            target="https://example.com",
        )

        assert result.potential_upload_issue is True
        assert result.finding_count == 1
        assert result.findings[0].severity == "High"

    def test_unsafe_filename_pipeline(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.UNSAFE_FILENAME
            ),
            target="https://example.com",
        )

        assert result.potential_upload_issue is True
        assert result.finding_count == 1

    def test_validation_is_preserved(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://example.com",
        )

        assert result.validation.baseline.status_code == 200
        assert (
            result.validation.candidate.content
            == b"upload accepted"
        )

    def test_findings_are_list(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://example.com",
        )

        assert isinstance(result.findings, list)

    def test_invalid_baseline(self):
        with pytest.raises(TypeError):
            FileUploadPipeline().run(
                "invalid",
                response(b"upload accepted"),
                analysis(),
                target="https://example.com",
            )

    def test_invalid_candidate(self):
        with pytest.raises(TypeError):
            FileUploadPipeline().run(
                response(b"normal"),
                "invalid",
                analysis(),
                target="https://example.com",
            )

    def test_invalid_analysis(self):
        with pytest.raises(TypeError):
            FileUploadPipeline().run(
                response(b"normal"),
                response(b"upload accepted"),
                "invalid",
                target="https://example.com",
            )

    def test_pipeline_does_not_confirm_execution(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://example.com",
        )

        assert result.potential_upload_issue is True
        assert "confirmed" not in result.status
        assert "execution" not in result.status

    def test_finding_metadata_is_preserved(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
            target="https://example.com",
            endpoint="/upload",
            parameter="file",
        )

        finding = result.findings[0]

        assert finding.cwe == "CWE-434"
        assert finding.owasp == "A04:2021"
        assert finding.endpoint == "/upload"
        assert finding.parameter == "file"

    def test_custom_components_are_supported(self):
        validator = FileUploadValidator()
        finding_analyzer = FileUploadFindingAnalyzer()

        pipeline = FileUploadPipeline(
            validator=validator,
            finding_analyzer=finding_analyzer,
        )

        assert pipeline.validator is validator
        assert (
            pipeline.finding_analyzer
            is finding_analyzer
        )

    def test_finding_count_matches_findings(self):
        result = FileUploadPipeline().run(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION,
                FileUploadIndicatorType.MIME_MISMATCH,
            )
            if False
            else FileUploadAnalysis(
                indicators=[
                    FileUploadIndicator(
                        type=(
                            FileUploadIndicatorType
                            .DANGEROUS_EXTENSION
                        ),
                        evidence="shell.php",
                    ),
                    FileUploadIndicator(
                        type=(
                            FileUploadIndicatorType
                            .MIME_MISMATCH
                        ),
                        evidence="php/jpeg",
                    ),
                ]
            ),
            target="https://example.com",
        )

        assert result.finding_count == len(result.findings)
