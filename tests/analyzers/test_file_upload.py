import pytest

from m_hunter.analyzers.file_upload import (
    FileUploadAnalysis,
    FileUploadAnalyzer,
    FileUploadIndicatorType,
)


class TestFileUploadAnalyzer:
    def test_creation(self):
        assert FileUploadAnalyzer() is not None

    def test_empty_filename(self):
        with pytest.raises(ValueError):
            FileUploadAnalyzer().analyze("")

    def test_whitespace_filename(self):
        with pytest.raises(ValueError):
            FileUploadAnalyzer().analyze("   ")

    def test_invalid_filename_type(self):
        with pytest.raises(TypeError):
            FileUploadAnalyzer().analyze(None)

    def test_invalid_mime_type(self):
        with pytest.raises(TypeError):
            FileUploadAnalyzer().analyze(
                "image.jpg",
                mime_type=123,
            )

    def test_invalid_content_type(self):
        with pytest.raises(TypeError):
            FileUploadAnalyzer().analyze(
                "image.jpg",
                content_type=123,
            )

    def test_safe_image(self):
        result = FileUploadAnalyzer().analyze(
            "image.jpg",
            mime_type="image/jpeg",
        )

        assert isinstance(result, FileUploadAnalysis)
        assert result.detected is False
        assert result.indicator_count == 0

    def test_dangerous_php_extension(self):
        result = FileUploadAnalyzer().analyze(
            "shell.php"
        )

        assert result.detected is True
        assert (
            FileUploadIndicatorType.DANGEROUS_EXTENSION
            in result.types
        )

    def test_dangerous_jsp_extension(self):
        result = FileUploadAnalyzer().analyze(
            "shell.jsp"
        )

        assert (
            FileUploadIndicatorType.DANGEROUS_EXTENSION
            in result.types
        )

    def test_dangerous_aspx_extension(self):
        result = FileUploadAnalyzer().analyze(
            "shell.aspx"
        )

        assert (
            FileUploadIndicatorType.DANGEROUS_EXTENSION
            in result.types
        )

    def test_double_extension(self):
        result = FileUploadAnalyzer().analyze(
            "image.php.jpg"
        )

        assert (
            FileUploadIndicatorType.DOUBLE_EXTENSION
            in result.types
        )

    def test_double_extension_case_insensitive(self):
        result = FileUploadAnalyzer().analyze(
            "image.PHP.JPG"
        )

        assert (
            FileUploadIndicatorType.DOUBLE_EXTENSION
            in result.types
        )

    def test_dangerous_mime(self):
        result = FileUploadAnalyzer().analyze(
            "upload.bin",
            mime_type="application/x-php",
        )

        assert (
            FileUploadIndicatorType.DANGEROUS_MIME
            in result.types
        )

    def test_mime_parameters_are_normalized(self):
        result = FileUploadAnalyzer().analyze(
            "upload.php",
            mime_type="application/x-php; charset=binary",
        )

        assert (
            FileUploadIndicatorType.DANGEROUS_MIME
            in result.types
        )

    def test_executable_content_type(self):
        result = FileUploadAnalyzer().analyze(
            "upload.bin",
            content_type="application/x-executable",
        )

        assert (
            FileUploadIndicatorType.EXECUTABLE_CONTENT_TYPE
            in result.types
        )

    def test_mime_mismatch(self):
        result = FileUploadAnalyzer().analyze(
            "image.jpg",
            mime_type="text/plain",
        )

        assert (
            FileUploadIndicatorType.MIME_MISMATCH
            in result.types
        )

    def test_matching_mime_is_not_mismatch(self):
        result = FileUploadAnalyzer().analyze(
            "image.png",
            mime_type="image/png; charset=binary",
        )

        assert (
            FileUploadIndicatorType.MIME_MISMATCH
            not in result.types
        )

    def test_path_traversal_filename(self):
        result = FileUploadAnalyzer().analyze(
            "../shell.php"
        )

        assert (
            FileUploadIndicatorType.UNSAFE_FILENAME
            in result.types
        )

    def test_windows_path_filename(self):
        result = FileUploadAnalyzer().analyze(
            r"..\shell.php"
        )

        assert (
            FileUploadIndicatorType.UNSAFE_FILENAME
            in result.types
        )

    def test_multiple_indicators(self):
        result = FileUploadAnalyzer().analyze(
            "../shell.php.jpg",
            mime_type="application/x-php",
            content_type="application/x-executable",
        )

        assert result.detected is True
        assert result.indicator_count >= 4
        assert (
            FileUploadIndicatorType.DANGEROUS_EXTENSION
            not in result.types
        )
        assert (
            FileUploadIndicatorType.DOUBLE_EXTENSION
            in result.types
        )
        assert (
            FileUploadIndicatorType.UNSAFE_FILENAME
            in result.types
        )
        assert (
            FileUploadIndicatorType.DANGEROUS_MIME
            in result.types
        )
        assert (
            FileUploadIndicatorType.EXECUTABLE_CONTENT_TYPE
            in result.types
        )

    def test_types_are_unique(self):
        result = FileUploadAnalyzer().analyze(
            "shell.php",
            mime_type="application/x-php",
            content_type="application/x-php",
        )

        assert len(result.types) == len(set(result.types))

    def test_names_alias_types(self):
        result = FileUploadAnalyzer().analyze(
            "shell.php"
        )

        assert result.names == result.types

    def test_indicator_positions_are_non_negative(self):
        result = FileUploadAnalyzer().analyze(
            "shell.php"
        )

        assert all(
            indicator.position >= 0
            for indicator in result.indicators
        )

    def test_no_execution_claim(self):
        result = FileUploadAnalyzer().analyze(
            "shell.php"
        )

        evidence = " ".join(
            indicator.evidence
            for indicator in result.indicators
        ).lower()

        assert "executed" not in evidence
        assert "confirmed" not in evidence
