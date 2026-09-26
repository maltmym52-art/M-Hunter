import pytest

from m_hunter.analyzers.http2_security import (
    HTTP2SecurityAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.http2_security_pipeline import (
    HTTP2SecurityValidationPipeline,
)


def response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com",
        headers=headers or {"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def pipeline():
    return HTTP2SecurityValidationPipeline()


def error_analysis():
    return HTTP2SecurityAnalyzer().analyze(
        "https://example.com",
        response_text="HTTP/2 protocol error",
    )


def duplicate_analysis():
    return HTTP2SecurityAnalyzer().analyze(
        "https://example.com",
        pseudo_headers=[
            ":method",
            ":method",
        ],
    )


def clean_analysis():
    return HTTP2SecurityAnalyzer().analyze(
        "https://example.com",
    )


def test_identical_responses_are_rejected():
    result = pipeline().process(
        response(),
        response(),
        error_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_changed_response_is_accepted():
    result = pipeline().process(
        response(content=b"normal"),
        response(content=b"changed"),
        error_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert len(result.findings) >= 1


def test_findings_only_generated_when_accepted():
    rejected = pipeline().process(
        response(),
        response(),
        error_analysis(),
        "https://example.com",
    )

    accepted = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        error_analysis(),
        "https://example.com",
    )

    assert rejected.findings == []
    assert len(accepted.findings) >= 1


def test_validation_result_is_preserved():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        error_analysis(),
        "https://example.com",
    )

    assert result.validation.content_changed is True
    assert result.validation.response_changed is True


def test_target_is_preserved():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        error_analysis(),
        "https://target.example",
    )

    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_endpoint_is_preserved():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        error_analysis(),
        "https://example.com",
        endpoint="/api",
    )

    assert all(
        finding.endpoint == "/api"
        for finding in result.findings
    )


def test_duplicate_pseudo_header_pipeline():
    result = pipeline().process(
        response(),
        response(content=b"changed"),
        duplicate_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert any(
        "Duplicate HTTP/2" in finding.title
        for finding in result.findings
    )


def test_clean_analysis_is_not_accepted():
    result = pipeline().process(
        response(),
        response(content=b"changed"),
        clean_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_h2c_pipeline():
    analysis = HTTP2SecurityAnalyzer().analyze(
        "https://example.com",
        h2c_upgrade=True,
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True
    assert any(
        "h2c" in finding.title.lower()
        for finding in result.findings
    )


def test_stream_error_pipeline():
    analysis = HTTP2SecurityAnalyzer().analyze(
        "https://example.com",
        response_text="stream error",
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True


def test_goaway_pipeline():
    analysis = HTTP2SecurityAnalyzer().analyze(
        "https://example.com",
        response_text="GOAWAY received",
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True


def test_status_change_can_accept():
    result = pipeline().process(
        response(status_code=200),
        response(status_code=400),
        error_analysis(),
        "https://example.com",
    )

    assert result.accepted is True


def test_header_change_can_accept():
    result = pipeline().process(
        response(
            headers={"content-type": "text/html"},
        ),
        response(
            headers={"content-type": "application/json"},
        ),
        error_analysis(),
        "https://example.com",
    )

    assert result.accepted is True


def test_multiple_response_changes():
    result = pipeline().process(
        response(
            status_code=200,
            content=b"abc",
            headers={"content-type": "text/html"},
        ),
        response(
            status_code=403,
            content=b"abcdef",
            headers={"content-type": "application/json"},
        ),
        error_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert result.validation.status_changed is True
    assert result.validation.content_changed is True
    assert result.validation.content_length_changed is True
    assert result.validation.headers_changed is True


def test_invalid_baseline():
    with pytest.raises(TypeError):
        pipeline().process(
            object(),
            response(),
            error_analysis(),
            "https://example.com",
        )


def test_invalid_candidate():
    with pytest.raises(TypeError):
        pipeline().process(
            response(),
            object(),
            error_analysis(),
            "https://example.com",
        )


def test_invalid_analysis():
    with pytest.raises(TypeError):
        pipeline().process(
            response(),
            response(),
            object(),
            "https://example.com",
        )


def test_empty_target():
    with pytest.raises(ValueError):
        pipeline().process(
            response(),
            response(content=b"changed"),
            error_analysis(),
            "",
        )


def test_whitespace_target():
    with pytest.raises(ValueError):
        pipeline().process(
            response(),
            response(content=b"changed"),
            error_analysis(),
            "   ",
        )


def test_result_contains_findings_list():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        error_analysis(),
        "https://example.com",
    )

    assert isinstance(result.findings, list)


def test_rejected_result_contains_empty_findings():
    result = pipeline().process(
        response(),
        response(),
        error_analysis(),
        "https://example.com",
    )

    assert result.findings == []


def test_pipeline_name():
    assert (
        HTTP2SecurityValidationPipeline.name
        == "http2_security_pipeline"
    )


def test_pipeline_returns_validation_object():
    result = pipeline().process(
        response(),
        response(),
        error_analysis(),
        "https://example.com",
    )

    assert result.validation is not None


def test_http2_protocol_alone_is_not_accepted():
    analysis = HTTP2SecurityAnalyzer().analyze(
        "https://example.com",
        protocol="h2",
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_settings_alone_is_not_accepted():
    analysis = HTTP2SecurityAnalyzer().analyze(
        "https://example.com",
        settings={"max_frame_size": 16384},
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
