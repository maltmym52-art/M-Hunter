import pytest

from m_hunter.analyzers.cache_poisoning import (
    CachePoisoningAnalysis,
    CachePoisoningAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.cache_poisoning_pipeline import (
    CachePoisoningValidationPipeline,
)


def response(*, body=b"same", headers=None, status=200):
    return HttpResponse(
        status_code=status,
        url="https://example.com/",
        headers=headers or {},
        content=body,
        cookies={},
        response_time=0.1,
        content_length=len(body),
    )


def detected_analysis():
    return CachePoisoningAnalyzer().analyze(
        headers={"X-Cache": "HIT"},
    )


def empty_analysis():
    return CachePoisoningAnalysis(
        detected=False,
        count=0,
        types=[],
        names=[],
        indicators=[],
    )


def pipeline():
    return CachePoisoningValidationPipeline()


def test_identical_responses_not_accepted():
    result = pipeline().process(
        response(),
        response(),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_content_change_is_accepted():
    result = pipeline().process(
        response(body=b"normal"),
        response(body=b"changed"),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert result.validation.potential_cache_poisoning is True
    assert result.findings


def test_cache_change_without_content_change_not_accepted():
    result = pipeline().process(
        response(
            headers={"X-Cache": "MISS"},
        ),
        response(
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_no_analysis_not_accepted():
    result = pipeline().process(
        response(body=b"normal"),
        response(body=b"changed"),
        empty_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_status_change_without_content_change_not_accepted():
    result = pipeline().process(
        response(status=200),
        response(status=403),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is False


def test_endpoint_is_preserved():
    result = pipeline().process(
        response(body=b"old"),
        response(body=b"new"),
        detected_analysis(),
        "https://example.com",
        endpoint="/account",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        finding.endpoint == "/account"
        for finding in result.findings
    )


def test_parameter_is_preserved():
    result = pipeline().process(
        response(body=b"old"),
        response(body=b"new"),
        detected_analysis(),
        "https://example.com",
        parameter="id",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        finding.parameter == "id"
        for finding in result.findings
    )


def test_target_is_preserved():
    result = pipeline().process(
        response(body=b"old"),
        response(body=b"new"),
        detected_analysis(),
        "https://target.example",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_invalid_baseline():
    with pytest.raises(TypeError):
        pipeline().process(
            "invalid",
            response(),
            detected_analysis(),
            "https://example.com",
        )


def test_invalid_candidate():
    with pytest.raises(TypeError):
        pipeline().process(
            response(),
            "invalid",
            detected_analysis(),
            "https://example.com",
        )


def test_invalid_analysis():
    with pytest.raises(TypeError):
        pipeline().process(
            response(),
            response(),
            "invalid",
            "https://example.com",
        )


def test_empty_target():
    with pytest.raises(ValueError):
        pipeline().process(
            response(),
            response(body=b"changed"),
            detected_analysis(),
            "",
        )


def test_validation_result_is_exposed():
    result = pipeline().process(
        response(body=b"old"),
        response(body=b"new"),
        detected_analysis(),
        "https://example.com",
    )

    assert result.validation is not None
    assert result.validation.content_changed is True


def test_findings_only_when_accepted():
    rejected = pipeline().process(
        response(),
        response(),
        detected_analysis(),
        "https://example.com",
    )

    accepted = pipeline().process(
        response(body=b"old"),
        response(body=b"new"),
        detected_analysis(),
        "https://example.com",
    )

    assert rejected.findings == []
    assert accepted.findings


def test_multiple_findings_are_returned():
    analysis = CachePoisoningAnalyzer().analyze(
        headers={
            "X-Cache": "HIT",
            "Cache-Control": "public",
            "Age": "120",
        },
    )

    result = pipeline().process(
        response(body=b"old"),
        response(body=b"new"),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True
    assert len(result.findings) == analysis.count


def test_result_has_expected_fields():
    result = pipeline().process(
        response(),
        response(),
        detected_analysis(),
        "https://example.com",
    )

    assert hasattr(result, "validation")
    assert hasattr(result, "accepted")
    assert hasattr(result, "findings")


def test_findings_are_finding_objects():
    result = pipeline().process(
        response(body=b"old"),
        response(body=b"new"),
        detected_analysis(),
        "https://example.com",
    )

    assert all(
        hasattr(finding, "title")
        and hasattr(finding, "severity")
        for finding in result.findings
    )


def test_header_variation_with_content_change_is_accepted():
    result = pipeline().process(
        response(
            body=b"old",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"new",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert result.validation.cache_behavior_changed is True
    assert result.validation.content_changed is True


def test_pipeline_does_not_accept_header_change_alone():
    result = pipeline().process(
        response(
            headers={"Cache-Control": "no-store"},
        ),
        response(
            headers={"Cache-Control": "public"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
