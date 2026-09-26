from m_hunter.analyzers.file_inclusion import (
    FileInclusionAnalyzer,
    FileInclusionIndicatorType,
)
from m_hunter.core.response import HttpResponse


def response(
    text: str = "",
    url: str = "https://example.com/index",
    status: int = 200,
) -> HttpResponse:
    return HttpResponse(
        status_code=status,
        url=url,
        headers={"content-type": "text/html"},
        content=text.encode(),
        cookies={},
        response_time=0.1,
        content_length=len(text.encode()),
    )


def test_clean_response():
    analysis = FileInclusionAnalyzer().analyze(response("normal page"))

    assert analysis.detected is False
    assert analysis.count == 0


def test_path_traversal():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        request_url="https://example.com/?file=../../etc/passwd",
    )

    assert analysis.detected
    assert analysis.has_type(FileInclusionIndicatorType.PATH_TRAVERSAL)


def test_encoded_path_traversal():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["%2e%2e%2fetc%2fpasswd"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.PATH_TRAVERSAL)


def test_windows_path_traversal():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=[r"..\..\windows\win.ini"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.WINDOWS_PATH_TRAVERSAL) is False
    assert analysis.has_type(FileInclusionIndicatorType.PATH_TRAVERSAL)


def test_absolute_unix_path():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["/etc/passwd"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.ABSOLUTE_UNIX_PATH)


def test_absolute_windows_path():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=[r"C:\Windows\win.ini"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.ABSOLUTE_WINDOWS_PATH)


def test_file_scheme():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["file:///etc/passwd"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.FILE_SCHEME)


def test_php_wrapper():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["php://filter/resource=index.php"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.PHP_WRAPPER)


def test_php_input_wrapper():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["php://input"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.PHP_WRAPPER)


def test_data_wrapper():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["data://text/plain,test"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.DATA_WRAPPER)


def test_http_wrapper():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["https://evil.example/payload"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.HTTP_WRAPPER)
    assert analysis.has_type(FileInclusionIndicatorType.REMOTE_URL)


def test_sensitive_file():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["/etc/passwd"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.SENSITIVE_FILE)


def test_windows_sensitive_file():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["C:\\Windows\\win.ini"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.SENSITIVE_FILE)


def test_file_extension():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["config.php"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.FILE_EXTENSION)


def test_file_include_error():
    analysis = FileInclusionAnalyzer().analyze(
        response("Warning: failed to open stream: No such file or directory"),
    )

    assert analysis.has_type(FileInclusionIndicatorType.FILE_INCLUDE_ERROR)
    assert analysis.has_type(FileInclusionIndicatorType.PATH_NOT_FOUND_ERROR)


def test_php_include_error():
    analysis = FileInclusionAnalyzer().analyze(
        response("Warning: include(/etc/passwd): failed to open stream"),
    )

    assert analysis.has_type(FileInclusionIndicatorType.PHP_INCLUDE_ERROR)


def test_path_not_found_error():
    analysis = FileInclusionAnalyzer().analyze(
        response("The requested path was not found"),
    )

    assert analysis.has_type(FileInclusionIndicatorType.PATH_NOT_FOUND_ERROR)


def test_multiple_indicators():
    analysis = FileInclusionAnalyzer().analyze(
        response("Warning: include failed to open stream"),
        request_url="https://example.com/?file=../../etc/passwd",
    )

    assert analysis.detected
    assert analysis.count >= 3


def test_request_url_is_analyzed():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        request_url="https://example.com/?page=php://filter/resource=index.php",
    )

    assert analysis.has_type(FileInclusionIndicatorType.PHP_WRAPPER)
    assert analysis.has_type(FileInclusionIndicatorType.FILE_EXTENSION)


def test_parameter_values_are_analyzed():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["../../config.php", "file:///etc/passwd"],
    )

    assert analysis.has_type(FileInclusionIndicatorType.PATH_TRAVERSAL)
    assert analysis.has_type(FileInclusionIndicatorType.FILE_SCHEME)


def test_response_url_is_analyzed():
    analysis = FileInclusionAnalyzer().analyze(
        response(url="https://example.com/download?file=../../etc/passwd"),
    )

    assert analysis.has_type(FileInclusionIndicatorType.PATH_TRAVERSAL)


def test_case_insensitive_detection():
    analysis = FileInclusionAnalyzer().analyze(
        response("FAILED TO OPEN STREAM"),
    )

    assert analysis.has_type(FileInclusionIndicatorType.FILE_INCLUDE_ERROR)


def test_duplicate_indicators_are_deduplicated():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        request_url="../../etc/passwd",
        parameter_values=["../../etc/passwd"],
    )

    traversal = [
        i
        for i in analysis.indicators
        if i.type == FileInclusionIndicatorType.PATH_TRAVERSAL
    ]

    assert len(traversal) == 1


def test_has_type_for_missing_type():
    analysis = FileInclusionAnalyzer().analyze(response())

    assert analysis.has_type(FileInclusionIndicatorType.REMOTE_URL) is False


def test_indicator_names():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["file:///etc/passwd"],
    )

    assert "File URI scheme" in analysis.names
    assert "Sensitive file path" in analysis.names


def test_indicator_values_are_preserved():
    analysis = FileInclusionAnalyzer().analyze(
        response(),
        parameter_values=["php://filter/resource=index.php"],
    )

    indicator = next(
        i
        for i in analysis.indicators
        if i.type == FileInclusionIndicatorType.PHP_WRAPPER
    )

    assert indicator.value == "php://filter"
