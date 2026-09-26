import pytest

from m_hunter.analyzers.websocket_security import (
    WebSocketSecurityAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.websocket_security import (
    WebSocketSecurityValidator,
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


def test_identical_responses_do_not_confirm_issue():
    result = WebSocketSecurityValidator().compare(
        response(),
        response(),
        missing_origin_analysis(),
    )

    assert result.response_changed is False
    assert result.potential_websocket_security_issue is False
    assert result.status == "indicator_only"


def test_content_change_is_detected():
    result = WebSocketSecurityValidator().compare(
        response(content=b"normal"),
        response(content=b"changed"),
        missing_origin_analysis(),
    )

    assert result.content_changed is True
    assert result.response_changed is True


def test_content_length_change_is_detected():
    result = WebSocketSecurityValidator().compare(
        response(content=b"abc"),
        response(content=b"abcdef"),
        missing_origin_analysis(),
    )

    assert result.content_length_changed is True


def test_status_change_is_detected():
    result = WebSocketSecurityValidator().compare(
        response(status_code=200),
        response(status_code=403),
        missing_origin_analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True


def test_header_change_is_detected():
    result = WebSocketSecurityValidator().compare(
        response(
            headers={"content-type": "text/html"},
        ),
        response(
            headers={"content-type": "application/json"},
        ),
        missing_origin_analysis(),
    )

    assert result.headers_changed is True


def test_missing_origin_is_security_relevant():
    result = WebSocketSecurityValidator().compare(
        response(),
        response(content=b"changed"),
        missing_origin_analysis(),
    )

    assert result.security_indicator_present is True


def test_broad_origin_is_security_relevant():
    result = WebSocketSecurityValidator().compare(
        response(),
        response(content=b"changed"),
        broad_origin_analysis(),
    )

    assert result.security_indicator_present is True
    assert result.potential_websocket_security_issue is True


def test_clean_analysis_cannot_confirm_issue():
    result = WebSocketSecurityValidator().compare(
        response(),
        response(content=b"changed"),
        clean_analysis(),
    )

    assert result.security_indicator_present is False
    assert result.potential_websocket_security_issue is False


def test_indicator_plus_response_change_is_potential():
    result = WebSocketSecurityValidator().compare(
        response(content=b"normal"),
        response(content=b"changed"),
        missing_origin_analysis(),
    )

    assert result.potential_websocket_security_issue is True
    assert result.status == "potential"


def test_baseline_status_is_preserved():
    result = WebSocketSecurityValidator().compare(
        response(status_code=201),
        response(status_code=200),
        missing_origin_analysis(),
    )

    assert result.baseline_status == 201


def test_candidate_status_is_preserved():
    result = WebSocketSecurityValidator().compare(
        response(status_code=200),
        response(status_code=201),
        missing_origin_analysis(),
    )

    assert result.candidate_status == 201


def test_content_evidence_is_reported():
    result = WebSocketSecurityValidator().compare(
        response(content=b"a"),
        response(content=b"b"),
        missing_origin_analysis(),
    )

    assert "Response content changed." in result.evidence


def test_status_evidence_is_reported():
    result = WebSocketSecurityValidator().compare(
        response(status_code=200),
        response(status_code=403),
        missing_origin_analysis(),
    )

    assert any(
        "HTTP status changed" in item
        for item in result.evidence
    )


def test_header_evidence_is_reported():
    result = WebSocketSecurityValidator().compare(
        response(
            headers={"content-type": "text/html"},
        ),
        response(
            headers={"content-type": "application/json"},
        ),
        missing_origin_analysis(),
    )

    assert any(
        "Relevant WebSocket/HTTP response headers changed"
        in item
        for item in result.evidence
    )


def test_no_indicator_status():
    result = WebSocketSecurityValidator().compare(
        response(),
        response(),
        clean_analysis(),
    )

    assert result.status == "no_indicator"


def test_invalid_baseline_type():
    with pytest.raises(TypeError):
        WebSocketSecurityValidator().compare(
            object(),
            response(),
            missing_origin_analysis(),
        )


def test_invalid_candidate_type():
    with pytest.raises(TypeError):
        WebSocketSecurityValidator().compare(
            response(),
            object(),
            missing_origin_analysis(),
        )


def test_invalid_analysis_type():
    with pytest.raises(TypeError):
        WebSocketSecurityValidator().compare(
            response(),
            response(),
            object(),
        )


def test_websocket_error_is_security_relevant():
    analysis = WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/socket",
        response_text="WebSocket handshake failed",
    )

    result = WebSocketSecurityValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.security_indicator_present is True
    assert result.potential_websocket_security_issue is True


def test_sensitive_path_is_security_relevant():
    analysis = WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/admin/socket",
    )

    result = WebSocketSecurityValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.security_indicator_present is True
    assert result.potential_websocket_security_issue is True


def test_normal_origin_alone_is_not_security_issue():
    analysis = WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "https://trusted.example"},
    )

    result = WebSocketSecurityValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.security_indicator_present is False
    assert result.potential_websocket_security_issue is False


def test_websocket_scheme_alone_is_not_security_issue():
    analysis = WebSocketSecurityAnalyzer().analyze(
        "wss://example.com/socket",
    )

    result = WebSocketSecurityValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.security_indicator_present is True
    assert result.potential_websocket_security_issue is True


def test_multiple_changes_are_reported():
    result = WebSocketSecurityValidator().compare(
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
    )

    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is True
    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_websocket_security_issue is True
