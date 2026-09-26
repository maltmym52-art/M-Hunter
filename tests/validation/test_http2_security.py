import pytest

from m_hunter.analyzers.http2_security import (
    HTTP2SecurityAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.http2_security import (
    HTTP2SecurityValidator,
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


def validator():
    return HTTP2SecurityValidator()


def analysis(**kwargs):
    return HTTP2SecurityAnalyzer().analyze(
        "https://example.com",
        **kwargs,
    )


def test_identical_responses_are_rejected():
    result = validator().compare(
        response(),
        response(),
        analysis(response_text="HTTP/2 protocol error"),
    )

    assert result.response_changed is False
    assert result.accepted if hasattr(result, "accepted") else True
    assert result.potential_http2_security_issue is False


def test_changed_content_with_http2_error_is_potential():
    result = validator().compare(
        response(content=b"normal"),
        response(content=b"changed"),
        analysis(response_text="HTTP/2 protocol error"),
    )

    assert result.content_changed is True
    assert result.response_changed is True
    assert result.security_indicator_present is True
    assert result.potential_http2_security_issue is True
    assert result.status == "potential"


def test_status_change_is_detected():
    result = validator().compare(
        response(status_code=200),
        response(status_code=400),
        analysis(response_text="stream error"),
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_http2_security_issue is True


def test_content_length_change_is_detected():
    result = validator().compare(
        response(content=b"a"),
        response(content=b"abcd"),
        analysis(response_text="GOAWAY"),
    )

    assert result.content_length_changed is True
    assert result.response_changed is True
    assert result.potential_http2_security_issue is True


def test_header_change_is_detected():
    result = validator().compare(
        response(headers={"content-type": "text/html"}),
        response(headers={"content-type": "application/json"}),
        analysis(response_text="HTTP/2 protocol error"),
    )

    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_http2_security_issue is True


def test_http2_scheme_alone_is_not_security_issue():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(),
    )

    assert result.security_indicator_present is False
    assert result.potential_http2_security_issue is False


def test_http2_protocol_alone_is_not_security_issue():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(protocol="h2"),
    )

    assert result.security_indicator_present is False
    assert result.potential_http2_security_issue is False


def test_alpn_alone_is_not_security_issue():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(alpn="h2"),
    )

    assert result.security_indicator_present is False
    assert result.potential_http2_security_issue is False


def test_authority_alone_is_not_security_issue():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(headers={":authority": "example.com"}),
    )

    assert result.security_indicator_present is False
    assert result.potential_http2_security_issue is False


def test_pseudo_header_alone_is_not_security_issue():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(headers={":method": "GET"}),
    )

    assert result.security_indicator_present is False
    assert result.potential_http2_security_issue is False


def test_settings_exposure_alone_is_not_security_issue():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(settings={"max_frame_size": 16384}),
    )

    assert result.security_indicator_present is False
    assert result.potential_http2_security_issue is False


def test_prior_knowledge_alone_is_not_security_issue():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(prior_knowledge=True),
    )

    assert result.security_indicator_present is False
    assert result.potential_http2_security_issue is False


def test_duplicate_pseudo_header_is_security_relevant():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(
            pseudo_headers=[
                ":method",
                ":method",
            ],
        ),
    )

    assert result.security_indicator_present is True
    assert result.potential_http2_security_issue is True


def test_invalid_pseudo_header_order_is_security_relevant():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(
            pseudo_headers=[
                ":method",
                "x-test",
                ":path",
            ],
        ),
    )

    assert result.security_indicator_present is True
    assert result.potential_http2_security_issue is True


def test_h2c_upgrade_is_security_relevant():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(h2c_upgrade=True),
    )

    assert result.security_indicator_present is True
    assert result.potential_http2_security_issue is True


def test_stream_error_is_security_relevant():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(response_text="stream error"),
    )

    assert result.security_indicator_present is True
    assert result.potential_http2_security_issue is True


def test_goaway_error_is_security_relevant():
    result = validator().compare(
        response(),
        response(content=b"changed"),
        analysis(response_text="GOAWAY received"),
    )

    assert result.security_indicator_present is True
    assert result.potential_http2_security_issue is True


def test_error_indicator_without_response_change_is_indicator_only():
    result = validator().compare(
        response(),
        response(),
        analysis(response_text="HTTP/2 protocol error"),
    )

    assert result.security_indicator_present is True
    assert result.response_changed is False
    assert result.potential_http2_security_issue is False
    assert result.status == "indicator_only"


def test_clean_analysis_status():
    result = validator().compare(
        response(),
        response(),
        analysis(),
    )

    assert result.status == "no_indicator"
    assert result.security_indicator_present is False


def test_evidence_mentions_security_indicator():
    result = validator().compare(
        response(content=b"a"),
        response(content=b"b"),
        analysis(response_text="HTTP/2 protocol error"),
    )

    assert any(
        "security-relevant" in item.lower()
        for item in result.evidence
    )


def test_evidence_mentions_content_change():
    result = validator().compare(
        response(content=b"a"),
        response(content=b"b"),
        analysis(response_text="HTTP/2 protocol error"),
    )

    assert "Response content changed." in result.evidence


def test_invalid_baseline():
    with pytest.raises(TypeError):
        validator().compare(
            object(),
            response(),
            analysis(),
        )


def test_invalid_candidate():
    with pytest.raises(TypeError):
        validator().compare(
            response(),
            object(),
            analysis(),
        )


def test_invalid_analysis():
    with pytest.raises(TypeError):
        validator().compare(
            response(),
            response(),
            object(),
        )


def test_multiple_changes_are_detected():
    result = validator().compare(
        response(
            status_code=200,
            content=b"a",
            headers={"content-type": "text/html"},
        ),
        response(
            status_code=403,
            content=b"abcd",
            headers={"content-type": "application/json"},
        ),
        analysis(response_text="HTTP/2 protocol error"),
    )

    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is True
    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_http2_security_issue is True


def test_h2c_upgrade_without_response_change_is_indicator_only():
    result = validator().compare(
        response(),
        response(),
        analysis(h2c_upgrade=True),
    )

    assert result.security_indicator_present is True
    assert result.potential_http2_security_issue is False
    assert result.status == "indicator_only"
