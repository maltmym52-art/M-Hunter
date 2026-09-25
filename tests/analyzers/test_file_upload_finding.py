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


def analysis(*indicator_types: str) -> FileUploadAnalysis:
    return FileUploadAnalysis(
        indicators=[
            FileUploadIndicator(
                type=indicator_type,
                evidence=f"test evidence for {indicator_type}",
                position=index,
            )
            for index, indicator_type in enumerate(
                indicator_types
            )
        ]
    )


class TestFileUploadFindingAnalyzer:
    def test_creation(self):
        assert FileUploadFindingAnalyzer() is not None

    def test_invalid_analysis(self):
        with pytest.raises(TypeError):
            FileUploadFindingAnalyzer().analyze(
                "invalid",
                target="https://example.com",
            )

    def test_empty_analysis(self):
        result = FileUploadFindingAnalyzer().analyze(
            FileUploadAnalysis(),
            target="https://example.com",
        )

        assert result == []

    @pytest.mark.parametrize(
        "indicator_type, severity",
        [
            (
                FileUploadIndicatorType.DANGEROUS_EXTENSION,
                "High",
            ),
            (
                FileUploadIndicatorType.DOUBLE_EXTENSION,
                "Medium",
            ),
            (
                FileUploadIndicatorType.MIME_MISMATCH,
                "Low",
            ),
            (
                FileUploadIndicatorType.DANGEROUS_MIME,
                "High",
            ),
            (
                FileUploadIndicatorType.EXECUTABLE_CONTENT_TYPE,
                "High",
            ),
            (
                FileUploadIndicatorType.UNSAFE_FILENAME,
                "Medium",
            ),
        ],
    )
    def test_severity_mapping(
        self,
        indicator_type,
        severity,
    ):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(indicator_type),
            target="https://example.com",
        )

        assert len(findings) == 1
        assert findings[0].severity == severity

    def test_all_indicator_types_generate_findings(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION,
                FileUploadIndicatorType.DOUBLE_EXTENSION,
                FileUploadIndicatorType.MIME_MISMATCH,
                FileUploadIndicatorType.DANGEROUS_MIME,
                FileUploadIndicatorType.EXECUTABLE_CONTENT_TYPE,
                FileUploadIndicatorType.UNSAFE_FILENAME,
            ),
            target="https://example.com",
        )

        assert len(findings) == 6
        assert all(
            isinstance(finding, Finding)
            for finding in findings
        )

    def test_confidence_is_medium(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://example.com",
        )

        assert findings[0].confidence == "Medium"

    def test_cwe_is_cwe_434(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://example.com",
        )

        assert findings[0].cwe == "CWE-434"

    def test_owasp_is_a04_2021(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://example.com",
        )

        assert findings[0].owasp == "A04:2021"

    def test_target_is_preserved(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://target.example",
        )

        assert findings[0].target == "https://target.example"

    def test_endpoint_is_preserved(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://target.example",
            endpoint="/upload",
        )

        assert findings[0].endpoint == "/upload"

    def test_parameter_is_preserved(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://target.example",
            parameter="file",
        )

        assert findings[0].parameter == "file"

    def test_evidence_contains_indicator_type(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://example.com",
        )

        assert (
            "dangerous_extension"
            in findings[0].evidence
        )

    def test_evidence_contains_indicator_evidence(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://example.com",
        )

        assert (
            "test evidence"
            in findings[0].evidence
        )

    def test_multiple_same_indicators_are_grouped(self):
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
                        .DANGEROUS_EXTENSION
                    ),
                    evidence="shell.jsp",
                    position=1,
                ),
            ]
        )

        findings = FileUploadFindingAnalyzer().analyze(
            current_analysis,
            target="https://example.com",
        )

        assert len(findings) == 1
        assert "shell.php" in findings[0].evidence
        assert "shell.jsp" in findings[0].evidence

    def test_different_types_create_separate_findings(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION,
                FileUploadIndicatorType.MIME_MISMATCH,
            ),
            target="https://example.com",
        )

        assert len(findings) == 2

    def test_remediation_is_present(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://example.com",
        )

        assert findings[0].remediation
        assert "allowlist" in findings[0].remediation.lower()

    def test_no_confirmed_execution_claim(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://example.com",
        )

        text = (
            findings[0].description
            + findings[0].evidence
        ).lower()

        assert "confirmed execution" not in text
        assert "executed" not in text

    def test_status_is_open(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION
            ),
            target="https://example.com",
        )

        assert findings[0].status == "open"

    def test_findings_have_unique_ids(self):
        findings = FileUploadFindingAnalyzer().analyze(
            analysis(
                FileUploadIndicatorType.DANGEROUS_EXTENSION,
                FileUploadIndicatorType.MIME_MISMATCH,
            ),
            target="https://example.com",
        )

        assert len(
            {finding.id for finding in findings}
        ) == 2
