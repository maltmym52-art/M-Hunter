import pytest

from m_hunter.analyzers.file_upload import (
    FileUploadAnalysis,
    FileUploadIndicator,
    FileUploadIndicatorType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.file_upload import (
    FileUploadValidationResult,
    FileUploadValidator,
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


class TestFileUploadValidator:
    def test_creation(self):
        assert FileUploadValidator() is not None

    def test_invalid_baseline(self):
        with pytest.raises(TypeError):
            FileUploadValidator().validate(
                "invalid",
                response(b"safe"),
                analysis(),
            )

    def test_invalid_candidate(self):
        with pytest.raises(TypeError):
            FileUploadValidator().validate(
                response(b"safe"),
                "invalid",
                analysis(),
            )

    def test_invalid_analysis(self):
        with pytest.raises(TypeError):
            FileUploadValidator().validate(
                response(b"safe"),
                response(b"safe"),
                "invalid",
            )

    def test_no_indicator(self):
        result = FileUploadValidator().validate(
            response(b"safe"),
            response(b"safe"),
            FileUploadAnalysis(),
        )

        assert isinstance(result, FileUploadValidationResult)
        assert result.status == "no_indicator"
        assert result.potential_upload_issue is False

    def test_indicator_without_response_change(self):
        same = response(b"safe")

        result = FileUploadValidator().validate(
            same,
            same,
            analysis(),
        )

        assert result.analysis.detected is True
        assert result.response_changed is False
        assert result.upload_behavior_changed is False
        assert result.potential_upload_issue is False
        assert result.status == "indicator_detected"

    def test_indicator_with_content_change(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
        )

        assert result.content_changed is True
        assert result.response_changed is True
        assert result.upload_behavior_changed is True
        assert result.potential_upload_issue is True
        assert result.status == "potential_upload_issue"

    def test_status_change(self):
        result = FileUploadValidator().validate(
            response(b"normal", status_code=200),
            response(b"upload accepted", status_code=201),
            analysis(),
        )

        assert result.status_changed is True
        assert result.response_changed is True
        assert result.potential_upload_issue is True

    def test_content_length_change(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
        )

        assert result.content_length_changed is True
        assert any(
            "content length changed" in item
            for item in result.evidence
        )

    def test_response_change_without_indicator(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"different response"),
            FileUploadAnalysis(),
        )

        assert result.response_changed is True
        assert result.upload_behavior_changed is True
        assert result.potential_upload_issue is False
        assert result.status == "no_indicator"

    def test_dangerous_extension(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
        )

        assert result.potential_upload_issue is True

    def test_double_extension(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.DOUBLE_EXTENSION
            ),
        )

        assert result.potential_upload_issue is True

    def test_mime_mismatch(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.MIME_MISMATCH
            ),
        )

        assert result.potential_upload_issue is True

    def test_dangerous_mime(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.DANGEROUS_MIME
            ),
        )

        assert result.potential_upload_issue is True

    def test_executable_content_type(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.EXECUTABLE_CONTENT_TYPE
            ),
        )

        assert result.potential_upload_issue is True

    def test_unsafe_filename(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.UNSAFE_FILENAME
            ),
        )

        assert result.potential_upload_issue is True

    def test_evidence_is_tuple(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
        )

        assert isinstance(result.evidence, tuple)

    def test_indicator_count_is_recorded(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
        )

        assert any(
            "file-upload indicators detected: 1" in item
            for item in result.evidence
        )

    def test_indicator_type_is_recorded(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(
                FileUploadIndicatorType.UNSAFE_FILENAME
            ),
        )

        assert any(
            "indicator type: unsafe_filename" in item
            for item in result.evidence
        )

    def test_baseline_is_preserved(self):
        baseline = response(b"normal")

        result = FileUploadValidator().validate(
            baseline,
            response(b"upload accepted"),
            analysis(),
        )

        assert result.baseline is baseline

    def test_candidate_is_preserved(self):
        candidate = response(b"upload accepted")

        result = FileUploadValidator().validate(
            response(b"normal"),
            candidate,
            analysis(),
        )

        assert result.candidate is candidate

    def test_analysis_is_preserved(self):
        current_analysis = analysis()

        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            current_analysis,
        )

        assert result.analysis is current_analysis

    def test_no_execution_confirmation(self):
        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            analysis(),
        )

        assert "confirmed" not in result.status
        assert "execution" not in result.status

    def test_multiple_indicators(self):
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
                    evidence="image.php as image/jpeg",
                    position=10,
                ),
            ]
        )

        result = FileUploadValidator().validate(
            response(b"normal"),
            response(b"upload accepted"),
            current_analysis,
        )

        assert result.potential_upload_issue is True
        assert len(result.analysis.types) == 2
