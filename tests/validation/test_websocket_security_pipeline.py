import pytest

from m_hunter.analyzers.websocket_security import (
    WebSocketSecurityAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.websocket_security_pipeline import (
    WebSocketSecurityValidationPipeline,
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


def missing_origin_analysis():
    return WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/socket",
    )


def broad_origin_analysis():
    return WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "*"},
    )


def clean_analysis():
    return WebSocketSecurityAnalyzer().analyze(
        "https://example.com",
        headers={"accept": "text/html"},
    )


def pipeline():
    return WebSocketSecurityValidationPipeline()


def test_identical_responses_are_rejected():
    result = pipeline().process(
        response(),
        response(),
        missing_origin_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_changed_response_is_accepted():
    result = pipeline().process(
        response(content=b"normal"),
        response(content=b"changed"),
        missing_origin_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert len(result.findings) >= 1


def test_findings_only_generated_when_accepted():
    rejected = pipeline().process(
        response(),
        response(),
        missing_origin_analysis(),
        "https://example.com",
    )

    accepted = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        missing_origin_analysis(),
        "https://example.com",
    )

    assert rejected.findings == []
    assert len(accepted.findings) >= 1


def test_validation_result_is_preserved():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        missing_origin_analysis(),
        "https://example.com",
    )

    assert result.validation.content_changed is True
    assert result.validation.response_changed is True


def test_target_is_preserved():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        missing_origin_analysis(),
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
        missing_origin_analysis(),
        "https://example.com",
        endpoint="/socket",
    )

    assert all(
        finding.endpoint == "/socket"
        for finding in result.findings
    )


def test_broad_origin_pipeline():
    result = pipeline().process(
        response(),
        response(content=b"changed"),
        broad_origin_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert any(
        "Broad WebSocket Origin" in finding.title
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


def test_websocket_error_pipeline():
    analysis = WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/socket",
        response_text="WebSocket handshake failed",
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True


def test_sensitive_path_pipeline():
    analysis = WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/admin/socket",
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True


def test_normal_origin_is_not_accepted():
    analysis = WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "https://trusted.example"},
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_status_change_can_accept():
    result = pipeline().process(
        response(status_code=200),
        response(status_code=403),
        missing_origin_analysis(),
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
        missing_origin_analysis(),
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
        missing_origin_analysis(),
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
            missing_origin_analysis(),
            "https://example.com",
        )


def test_invalid_candidate():
    with pytest.raises(TypeError):
        pipeline().process(
            response(),
            object(),
            missing_origin_analysis(),
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
            missing_origin_analysis(),
            "",
        )


def test_whitespace_target():
    with pytest.raises(ValueError):
        pipeline().process(
            response(),
            response(content=b"changed"),
            missing_origin_analysis(),
            "   ",
        )


def test_result_contains_findings_list():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        missing_origin_analysis(),
        "https://example.com",
    )

    assert isinstance(result.findings, list)


def test_rejected_result_contains_empty_findings():
    result = pipeline().process(
        response(),
        response(),
        missing_origin_analysis(),
        "https://example.com",
    )

    assert result.findings == []


def test_pipeline_name():
    assert (
        WebSocketSecurityValidationPipeline.name
        == "websocket_security_pipeline"
    )


def test_pipeline_returns_validation_object():
    result = pipeline().process(
        response(),
        response(),
        missing_origin_analysis(),
        "https://example.com",
    )

    assert result.validation is not None


def test_authentication_context_alone_is_not_accepted():
    analysis = WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "https://trusted.example"},
        authenticated=True,
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_session_context_alone_is_not_accepted():
    analysis = WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "https://trusted.example"},
        session_present=True,
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
