from m_hunter.analyzers.file_inclusion import (
    FileInclusionAnalysis,
    FileInclusionIndicator,
    FileInclusionIndicatorType,
)
from m_hunter.validation.file_inclusion_pipeline import FileInclusionPipeline


def analysis(
    *types: FileInclusionIndicatorType,
) -> FileInclusionAnalysis:
    indicators = [
        FileInclusionIndicator(
            type=indicator_type,
            name=indicator_type.value,
            value=indicator_type.value,
        )
        for indicator_type in types
    ]

    return FileInclusionAnalysis(
        detected=bool(indicators),
        indicators=indicators,
    )


def test_clean_pipeline_rejects():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="same",
        candidate_content="same",
        analysis=analysis(),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_indicator_without_behavior_change_rejects():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="same",
        candidate_content="same",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_path_traversal_with_behavior_change_is_accepted():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="root:x:0:0",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
        target="https://example.com",
        endpoint="/download",
        parameter="file",
    )

    assert result.accepted
    assert len(result.findings) == 1
    assert result.findings[0].parameter == "file"


def test_php_wrapper_with_behavior_change():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="included",
        analysis=analysis(
            FileInclusionIndicatorType.PHP_WRAPPER
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 1


def test_file_scheme_with_behavior_change():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=500,
        baseline_content="normal",
        candidate_content="include error",
        analysis=analysis(
            FileInclusionIndicatorType.FILE_SCHEME
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_remote_url_with_behavior_change():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="remote content",
        analysis=analysis(
            FileInclusionIndicatorType.REMOTE_URL
        ),
        target="https://example.com",
    )

    assert result.accepted


def test_sensitive_file_with_behavior_change():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="root:x:0:0",
        analysis=analysis(
            FileInclusionIndicatorType.SENSITIVE_FILE
        ),
        target="https://example.com",
    )

    assert result.accepted


def test_file_extension_only_rejects():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.FILE_EXTENSION
        ),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_path_not_found_only_rejects():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=404,
        baseline_content="normal",
        candidate_content="path was not found",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_NOT_FOUND_ERROR
        ),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_multiple_indicators_create_multiple_findings():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL,
            FileInclusionIndicatorType.SENSITIVE_FILE,
            FileInclusionIndicatorType.PHP_WRAPPER,
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 3


def test_headers_change_accepts_security_indicator():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="same",
        candidate_content="same",
        baseline_headers={"content-type": "text/html"},
        candidate_headers={"content-type": "text/plain"},
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
        target="https://example.com",
    )

    assert result.accepted


def test_status_change_accepts_security_indicator():
    result = FileInclusionPipeline().run(
        baseline_status=404,
        candidate_status=200,
        baseline_content="not found",
        candidate_content="file",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
        target="https://example.com",
    )

    assert result.accepted


def test_windows_traversal():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.WINDOWS_PATH_TRAVERSAL
        ),
        target="https://example.com",
    )

    assert result.accepted


def test_http_wrapper():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="remote",
        analysis=analysis(
            FileInclusionIndicatorType.HTTP_WRAPPER
        ),
        target="https://example.com",
    )

    assert result.accepted


def test_include_error():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=500,
        baseline_content="normal",
        candidate_content="failed to open stream",
        analysis=analysis(
            FileInclusionIndicatorType.FILE_INCLUDE_ERROR
        ),
        target="https://example.com",
    )

    assert result.accepted


def test_php_include_error():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=500,
        baseline_content="normal",
        candidate_content="warning include",
        analysis=analysis(
            FileInclusionIndicatorType.PHP_INCLUDE_ERROR
        ),
        target="https://example.com",
    )

    assert result.accepted


def test_no_analysis_indicators():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=500,
        baseline_content="normal",
        candidate_content="error",
        analysis=analysis(),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_validation_is_exposed():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
        target="https://example.com",
    )

    assert result.validation.potential_file_inclusion


def test_target_is_used_in_findings():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
        target="https://target.example",
    )

    assert result.findings[0].target == "https://target.example"


def test_endpoint_is_used_in_findings():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
        target="https://example.com",
        endpoint="/download",
    )

    assert result.findings[0].endpoint == "/download"


def test_parameter_is_used_in_findings():
    result = FileInclusionPipeline().run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
        target="https://example.com",
        parameter="file",
    )

    assert result.findings[0].parameter == "file"


def test_pipeline_name():
    assert FileInclusionPipeline.name == "file_inclusion_pipeline"


def test_pipeline_can_be_reused():
    pipeline = FileInclusionPipeline()

    result1 = pipeline.run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="a",
        candidate_content="b",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
        target="https://example.com",
    )

    result2 = pipeline.run(
        baseline_status=200,
        candidate_status=200,
        baseline_content="same",
        candidate_content="same",
        analysis=analysis(),
        target="https://example.com",
    )

    assert result1.accepted
    assert result2.accepted is False
