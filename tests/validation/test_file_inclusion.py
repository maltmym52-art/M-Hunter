from m_hunter.analyzers.file_inclusion import (
    FileInclusionAnalysis,
    FileInclusionIndicator,
    FileInclusionIndicatorType,
)
from m_hunter.validation.file_inclusion import FileInclusionValidator


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


def test_clean_response():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="same",
        candidate_content="same",
        analysis=analysis(),
    )

    assert result.status == "clean"
    assert result.potential_file_inclusion is False
    assert result.response_changed is False


def test_indicator_without_behavior_change():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="same",
        candidate_content="same",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
    )

    assert result.security_indicator_present
    assert result.potential_file_inclusion is False
    assert result.status == "indicator"


def test_path_traversal_with_content_change():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="root:x:0:0:root:/root:/bin/bash",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_file_inclusion


def test_path_traversal_with_status_change():
    result = FileInclusionValidator().validate(
        404,
        200,
        baseline_content="not found",
        candidate_content="file content",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
    )

    assert result.status_changed
    assert result.potential_file_inclusion


def test_php_wrapper_with_response_change():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="included content",
        analysis=analysis(
            FileInclusionIndicatorType.PHP_WRAPPER
        ),
    )

    assert result.security_indicator_present
    assert result.potential_file_inclusion


def test_file_scheme_with_response_change():
    result = FileInclusionValidator().validate(
        200,
        500,
        baseline_content="normal",
        candidate_content="include error",
        analysis=analysis(
            FileInclusionIndicatorType.FILE_SCHEME
        ),
    )

    assert result.status_changed
    assert result.potential_file_inclusion


def test_data_wrapper_with_response_change():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.DATA_WRAPPER
        ),
    )

    assert result.potential_file_inclusion


def test_remote_url_with_response_change():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="remote response",
        analysis=analysis(
            FileInclusionIndicatorType.REMOTE_URL
        ),
    )

    assert result.potential_file_inclusion


def test_sensitive_file_with_response_change():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="root:x:0:0",
        analysis=analysis(
            FileInclusionIndicatorType.SENSITIVE_FILE
        ),
    )

    assert result.potential_file_inclusion


def test_include_error_with_response_change():
    result = FileInclusionValidator().validate(
        200,
        500,
        baseline_content="normal",
        candidate_content="failed to open stream",
        analysis=analysis(
            FileInclusionIndicatorType.FILE_INCLUDE_ERROR
        ),
    )

    assert result.potential_file_inclusion


def test_php_include_error_with_response_change():
    result = FileInclusionValidator().validate(
        200,
        500,
        baseline_content="normal",
        candidate_content="warning include",
        analysis=analysis(
            FileInclusionIndicatorType.PHP_INCLUDE_ERROR
        ),
    )

    assert result.potential_file_inclusion


def test_file_extension_alone_is_not_security_relevant():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.FILE_EXTENSION
        ),
    )

    assert result.security_indicator_present is False
    assert result.potential_file_inclusion is False


def test_path_not_found_error_alone_is_not_security_relevant():
    result = FileInclusionValidator().validate(
        200,
        404,
        baseline_content="normal",
        candidate_content="path was not found",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_NOT_FOUND_ERROR
        ),
    )

    assert result.security_indicator_present is False
    assert result.potential_file_inclusion is False


def test_headers_changed():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="same",
        candidate_content="same",
        baseline_headers={"content-type": "text/html"},
        candidate_headers={"content-type": "text/plain"},
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_file_inclusion


def test_content_length_changed():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="a",
        candidate_content="abcdef",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
    )

    assert result.content_length_changed
    assert result.potential_file_inclusion


def test_empty_analysis_is_safe():
    result = FileInclusionValidator().validate(
        200,
        500,
        baseline_content="normal",
        candidate_content="error",
        analysis=None,
    )

    assert result.security_indicator_present is False
    assert result.potential_file_inclusion is False


def test_evidence_contains_status_change():
    result = FileInclusionValidator().validate(
        200,
        500,
        baseline_content="normal",
        candidate_content="error",
        analysis=analysis(
            FileInclusionIndicatorType.PHP_INCLUDE_ERROR
        ),
    )

    assert "status changed 200->500" in result.evidence


def test_evidence_contains_content_change():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.PATH_TRAVERSAL
        ),
    )

    assert "response content changed" in result.evidence


def test_status_indicator_when_no_behavior_change():
    result = FileInclusionValidator().validate(
        200,
        200,
        analysis=analysis(
            FileInclusionIndicatorType.SENSITIVE_FILE
        ),
    )

    assert result.status == "indicator"


def test_potential_status_when_behavior_changes():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="secret",
        analysis=analysis(
            FileInclusionIndicatorType.SENSITIVE_FILE
        ),
    )

    assert result.status == "potential"


def test_windows_traversal_is_security_relevant():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="changed",
        analysis=analysis(
            FileInclusionIndicatorType.WINDOWS_PATH_TRAVERSAL
        ),
    )

    assert result.security_indicator_present
    assert result.potential_file_inclusion


def test_http_wrapper_is_security_relevant():
    result = FileInclusionValidator().validate(
        200,
        200,
        baseline_content="normal",
        candidate_content="remote",
        analysis=analysis(
            FileInclusionIndicatorType.HTTP_WRAPPER
        ),
    )

    assert result.security_indicator_present
    assert result.potential_file_inclusion


def test_response_change_without_indicator_is_not_potential():
    result = FileInclusionValidator().validate(
        200,
        500,
        baseline_content="normal",
        candidate_content="error",
        analysis=analysis(),
    )

    assert result.response_changed
    assert result.security_indicator_present is False
    assert result.potential_file_inclusion is False
