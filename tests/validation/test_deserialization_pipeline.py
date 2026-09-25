import pytest

from m_hunter.analyzers.deserialization import (
    DeserializationAnalysis,
    DeserializationIndicator,
    DeserializationIndicatorType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.deserialization_pipeline import (
    DeserializationPipeline,
    DeserializationPipelineResult,
)


def make_response(
    *,
    status_code: int = 200,
    content: bytes = b"same",
    content_length: int | None = None,
) -> HttpResponse:
    if content_length is None:
        content_length = len(content)

    return HttpResponse(
        status_code=status_code,
        url="https://example.com/",
        headers={"Content-Type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=content_length,
    )


def make_analysis(
    *,
    detected: bool = True,
) -> DeserializationAnalysis:
    if not detected:
        return DeserializationAnalysis()

    indicator = DeserializationIndicator(
        type=DeserializationIndicatorType.SERIALIZED_PARAMETER,
        evidence="Serialized parameter detected",
        name="serialized",
    )

    return DeserializationAnalysis(
        detected=True,
        indicator_count=1,
        types=[
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ],
        names=["serialized"],
        indicators=[indicator],
    )


def test_pipeline_returns_result():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert isinstance(result, DeserializationPipelineResult)


def test_pipeline_returns_validation():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation is not None
    assert result.validation.potential_deserialization is True


def test_pipeline_creates_findings():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.finding_count == 1
    assert result.findings[0].cwe == "CWE-502"


def test_pipeline_preserves_endpoint():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
        endpoint="/api/object",
    )

    assert result.findings[0].endpoint == "/api/object"


def test_pipeline_preserves_target():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://target.example",
    )

    assert result.findings[0].target == "https://target.example"


def test_pipeline_exposes_potential_deserialization():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.potential_deserialization is True


def test_pipeline_without_response_change_is_indicator_only():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(),
        make_analysis(),
        target="https://example.com",
    )

    assert result.potential_deserialization is False
    assert result.validation.status == "indicator_detected"
    assert result.finding_count == 1


def test_pipeline_detects_behavior_change():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(),
        make_analysis(),
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.potential_deserialization is True
    assert result.validation.status == "behavior_changed"


def test_pipeline_no_indicator_has_no_findings():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(detected=False),
        target="https://example.com",
    )

    assert result.potential_deserialization is False
    assert result.finding_count == 0
    assert result.findings == []


def test_pipeline_no_indicator_with_behavior_change_has_no_findings():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(),
        make_analysis(detected=False),
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.potential_deserialization is False
    assert result.finding_count == 0


def test_pipeline_detects_status_change():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(status_code=200),
        make_response(status_code=500),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.status_changed is True
    assert result.potential_deserialization is True


def test_pipeline_detects_content_change():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(content=b"one"),
        make_response(content=b"two"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.content_changed is True
    assert result.potential_deserialization is True


def test_pipeline_detects_content_length_change():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(content=b"one"),
        make_response(
            content=b"one",
            content_length=100,
        ),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.content_length_changed is True
    assert result.potential_deserialization is True


def test_pipeline_finding_contains_evidence():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert "Serialized parameter detected" in result.findings[0].evidence


def test_pipeline_finding_has_correct_owasp():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.findings[0].owasp == "A08:2021"


def test_pipeline_finding_is_open():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.findings[0].status == "open"


def test_pipeline_finding_count_matches_findings():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.finding_count == len(result.findings)


def test_pipeline_rejects_invalid_analysis():
    pipeline = DeserializationPipeline()

    with pytest.raises(TypeError):
        pipeline.run(
            make_response(),
            make_response(),
            object(),
            target="https://example.com",
        )


def test_pipeline_returns_validation_evidence():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.evidence
    assert any(
        "Baseline status" in item
        for item in result.validation.evidence
    )


def test_pipeline_handles_endpoint_none():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.findings[0].endpoint is None


def test_pipeline_handles_multiple_indicator_types():
    indicators = [
        DeserializationIndicator(
            type=DeserializationIndicatorType.SERIALIZED_PARAMETER,
            evidence="Parameter detected",
            name="pickle",
        ),
        DeserializationIndicator(
            type=DeserializationIndicatorType.SERIALIZED_COOKIE,
            evidence="Cookie detected",
            name="serialized",
        ),
    ]

    analysis = DeserializationAnalysis(
        detected=True,
        indicator_count=2,
        types=[
            DeserializationIndicatorType.SERIALIZED_PARAMETER,
            DeserializationIndicatorType.SERIALIZED_COOKIE,
        ],
        names=["pickle", "serialized"],
        indicators=indicators,
    )

    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == 2


def test_pipeline_behavior_change_takes_priority():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.validation.status == "behavior_changed"
    assert result.potential_deserialization is True


def test_pipeline_clean_analysis_returns_no_indicator():
    pipeline = DeserializationPipeline()

    result = pipeline.run(
        make_response(),
        make_response(),
        DeserializationAnalysis(),
        target="https://example.com",
    )

    assert result.validation.status == "no_indicator"
    assert result.potential_deserialization is False
    assert result.findings == []
