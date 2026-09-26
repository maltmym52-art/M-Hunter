from m_hunter.analyzers.file_inclusion import (
    FileInclusionAnalysis,
    FileInclusionIndicator,
    FileInclusionIndicatorType,
)
from m_hunter.analyzers.file_inclusion_finding import (
    FileInclusionFindingAnalyzer,
)


def indicator(
    indicator_type: FileInclusionIndicatorType,
    value: str = "test",
) -> FileInclusionIndicator:
    return FileInclusionIndicator(
        type=indicator_type,
        name=indicator_type.value,
        value=value,
    )


def analysis(*indicators: FileInclusionIndicator) -> FileInclusionAnalysis:
    return FileInclusionAnalysis(
        detected=bool(indicators),
        indicators=list(indicators),
    )


def test_no_indicators_returns_no_findings():
    findings = FileInclusionFindingAnalyzer().create_findings(
        analysis(),
        target="https://example.com",
    )

    assert findings == []


def test_path_traversal_finding():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(indicator(FileInclusionIndicatorType.PATH_TRAVERSAL, "../")),
        target="https://example.com",
        endpoint="/download",
        parameter="file",
    )[0]

    assert finding.title == "Potential Local File Inclusion / Path Traversal"
    assert finding.severity == "High"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-22"
    assert finding.owasp == "A01:2021"
    assert finding.endpoint == "/download"
    assert finding.parameter == "file"


def test_windows_traversal_metadata():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.WINDOWS_PATH_TRAVERSAL,
                r"..\\",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.cwe == "CWE-22"


def test_file_scheme_metadata():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.FILE_SCHEME,
                "file://",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.cwe == "CWE-98"


def test_php_wrapper_metadata():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.PHP_WRAPPER,
                "php://filter",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.cwe == "CWE-98"


def test_data_wrapper_metadata():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.DATA_WRAPPER,
                "data://",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"


def test_remote_url_is_not_high_confidence():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.REMOTE_URL,
                "https://remote.example/file",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Low"


def test_file_extension_is_informational():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(FileInclusionIndicatorType.FILE_EXTENSION, ".php")
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "High"


def test_sensitive_file_metadata():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.SENSITIVE_FILE,
                "/etc/passwd",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.cwe == "CWE-22"


def test_include_error_metadata():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.FILE_INCLUDE_ERROR,
                "failed to open stream",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-22"


def test_php_error_metadata():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.PHP_INCLUDE_ERROR,
                "warning: include",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-98"


def test_path_not_found_metadata():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.PATH_NOT_FOUND_ERROR,
                "path was not found",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"


def test_evidence_contains_indicator_value():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.PHP_WRAPPER,
                "php://filter",
            )
        ),
        target="https://example.com",
    )[0]

    assert "php://filter" in finding.evidence


def test_description_contains_disclaimer():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.PATH_TRAVERSAL,
                "../",
            )
        ),
        target="https://example.com",
    )[0]

    assert "does not by itself prove" in finding.description


def test_remediation_is_present():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.PATH_TRAVERSAL,
                "../",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.remediation
    assert "allowlist" in finding.remediation


def test_target_is_preserved():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.SENSITIVE_FILE,
                "/etc/passwd",
            )
        ),
        target="https://target.example",
    )[0]

    assert finding.target == "https://target.example"


def test_analyze_alias_matches_create_findings():
    analyzer = FileInclusionFindingAnalyzer()

    result1 = analyzer.create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.PATH_TRAVERSAL,
                "../",
            )
        ),
        target="https://example.com",
    )

    result2 = analyzer.analyze(
        analysis(
            indicator(
                FileInclusionIndicatorType.PATH_TRAVERSAL,
                "../",
            )
        ),
        target="https://example.com",
    )

    assert len(result1) == len(result2)
    assert result1[0].title == result2[0].title


def test_multiple_indicators_create_multiple_findings():
    findings = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.PATH_TRAVERSAL,
                "../",
            ),
            indicator(
                FileInclusionIndicatorType.PHP_WRAPPER,
                "php://filter",
            ),
            indicator(
                FileInclusionIndicatorType.SENSITIVE_FILE,
                "/etc/passwd",
            ),
        ),
        target="https://example.com",
    )

    assert len(findings) == 3


def test_endpoint_and_parameter_are_optional():
    finding = FileInclusionFindingAnalyzer().create_findings(
        analysis(
            indicator(
                FileInclusionIndicatorType.REMOTE_URL,
                "https://remote.example/file",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.endpoint is None
    assert finding.parameter is None


def test_all_indicator_types_have_metadata():
    analyzer = FileInclusionFindingAnalyzer()

    for indicator_type in FileInclusionIndicatorType:
        result = analyzer.create_findings(
            analysis(indicator(indicator_type, indicator_type.value)),
            target="https://example.com",
        )

        assert len(result) == 1
        assert result[0].severity
        assert result[0].confidence
        assert result[0].cwe
        assert result[0].owasp
