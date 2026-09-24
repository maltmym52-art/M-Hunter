import pytest

from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.metadata import MetadataAnalyzer
from m_hunter.core.response import HttpResponse


def make_response(
    *,
    status_code: int = 200,
    url: str = "https://example.com",
    headers: dict[str, str] | None = None,
    content: bytes = b"hello",
    response_time: float = 0.25,
    cookies: dict[str, str] | None = None,
) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        url=url,
        headers=headers or {},
        content=content,
        cookies=cookies or {},
        response_time=response_time,
        content_length=len(content),
    )


def test_metadata_analyzer_inherits_base_analyzer():
    analyzer = MetadataAnalyzer()

    assert isinstance(analyzer, BaseAnalyzer)


def test_metadata_analyzer_name():
    analyzer = MetadataAnalyzer()

    assert analyzer.name == "metadata"


def test_metadata_analyzer_description():
    analyzer = MetadataAnalyzer()

    assert analyzer.description


def test_metadata_analyzer_returns_dict():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(make_response())

    assert isinstance(result, dict)


def test_metadata_contains_status_information():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(
        make_response(status_code=201)
    )

    assert result["status_code"] == 201
    assert result["status_category"] == "success"
    assert result["is_success"] is True


def test_metadata_contains_url():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(
        make_response(
            url="https://example.com/login",
        )
    )

    assert result["url"] == "https://example.com/login"


def test_metadata_contains_content_information():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Type": "text/html; charset=utf-8",
            },
            content=b"<html></html>",
        )
    )

    assert result["content_type"] == "text/html"
    assert result["content_length"] == len(b"<html></html>")
    assert result["is_html"] is True
    assert result["is_text"] is True


def test_metadata_detects_json():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Type": "application/json",
            },
            content=b'{"status":"ok"}',
        )
    )

    assert result["content_type"] == "application/json"
    assert result["is_json"] is True
    assert result["is_text"] is True


def test_metadata_detects_redirect():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(
        make_response(status_code=302)
    )

    assert result["status_category"] == "redirect"
    assert result["is_redirect"] is True
    assert result["is_success"] is False


def test_metadata_detects_client_error():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(
        make_response(status_code=404)
    )

    assert result["status_category"] == "client_error"
    assert result["is_client_error"] is True


def test_metadata_detects_server_error():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(
        make_response(status_code=500)
    )

    assert result["status_category"] == "server_error"
    assert result["is_server_error"] is True


def test_metadata_contains_response_time():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(
        make_response(response_time=1.234)
    )

    assert result["response_time"] == pytest.approx(1.234)


def test_metadata_contains_headers_copy():
    analyzer = MetadataAnalyzer()

    response = make_response(
        headers={
            "X-Test": "value",
        }
    )

    result = analyzer.analyze(response)

    assert result["headers"] == {
        "X-Test": "value",
    }

    result["headers"]["X-Test"] = "changed"

    assert response.get_header("X-Test") == "value"


def test_metadata_handles_empty_content():
    analyzer = MetadataAnalyzer()

    result = analyzer.analyze(
        make_response(
            content=b"",
        )
    )

    assert result["content_length"] == 0
    assert result["is_html"] is False
    assert result["is_json"] is False
