import pytest

from m_hunter.analyzers.prototype_pollution import (
    PrototypePollutionAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.prototype_pollution_pipeline import (
    PrototypePollutionValidationPipeline,
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


def proto_analysis():
    return PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )


def clean_analysis():
    return PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        query={"name": "test"},
    )


def pipeline():
    return PrototypePollutionValidationPipeline()


def test_identical_responses_are_not_accepted():
    result = pipeline().process(
        response(),
        response(),
        proto_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_changed_response_is_accepted():
    result = pipeline().process(
        response(content=b"normal"),
        response(content=b"changed"),
        proto_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert len(result.findings) == 1


def test_findings_are_generated_only_when_accepted():
    rejected = pipeline().process(
        response(),
        response(),
        proto_analysis(),
        "https://example.com",
    )

    accepted = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        proto_analysis(),
        "https://example.com",
    )

    assert rejected.findings == []
    assert len(accepted.findings) == 1


def test_validation_result_is_preserved():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        proto_analysis(),
        "https://example.com",
    )

    assert result.validation.content_changed is True
    assert result.validation.response_changed is True


def test_target_is_preserved_in_finding():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        proto_analysis(),
        "https://target.example",
    )

    assert result.findings[0].target == "https://target.example"


def test_endpoint_is_preserved():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        proto_analysis(),
        "https://example.com",
        endpoint="/api/profile",
    )

    assert result.findings[0].endpoint == "/api/profile"


def test_constructor_indicator_pipeline():
    analysis = PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        query={"constructor": "prototype"},
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True
    assert len(result.findings) == 1


def test_prototype_indicator_pipeline():
    analysis = PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        query={"prototype": "polluted"},
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True


def test_clean_analysis_is_not_accepted():
    result = pipeline().process(
        response(),
        response(content=b"changed"),
        clean_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_status_change_can_accept():
    result = pipeline().process(
        response(status_code=200),
        response(status_code=500),
        proto_analysis(),
        "https://example.com",
    )

    assert result.accepted is True


def test_header_change_can_accept():
    result = pipeline().process(
        response(headers={"content-type": "text/html"}),
        response(headers={"content-type": "application/json"}),
        proto_analysis(),
        "https://example.com",
    )

    assert result.accepted is True


def test_multiple_response_changes():
    result = pipeline().process(
        response(
            status_code=200,
            content=b"a",
            headers={"content-type": "text/html"},
        ),
        response(
            status_code=500,
            content=b"abcdef",
            headers={"content-type": "application/json"},
        ),
        proto_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert result.validation.status_changed is True
    assert result.validation.content_changed is True
    assert result.validation.headers_changed is True


def test_invalid_baseline():
    with pytest.raises(TypeError):
        pipeline().process(
            object(),
            response(),
            proto_analysis(),
            "https://example.com",
        )


def test_invalid_candidate():
    with pytest.raises(TypeError):
        pipeline().process(
            response(),
            object(),
            proto_analysis(),
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
            proto_analysis(),
            "",
        )


def test_whitespace_target():
    with pytest.raises(ValueError):
        pipeline().process(
            response(),
            response(content=b"changed"),
            proto_analysis(),
            "   ",
        )


def test_result_contains_findings_list():
    result = pipeline().process(
        response(content=b"a"),
        response(content=b"b"),
        proto_analysis(),
        "https://example.com",
    )

    assert isinstance(result.findings, list)


def test_rejected_result_contains_empty_findings():
    result = pipeline().process(
        response(),
        response(),
        proto_analysis(),
        "https://example.com",
    )

    assert result.findings == []


def test_pollution_marker_pipeline():
    analysis = PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        response_text="polluted",
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True


def test_nested_object_alone_is_not_enough():
    analysis = PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        body={"user": {"name": "test"}},
    )

    result = pipeline().process(
        response(),
        response(content=b"changed"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is False


def test_pipeline_name():
    assert (
        PrototypePollutionValidationPipeline.name
        == "prototype_pollution_pipeline"
    )
