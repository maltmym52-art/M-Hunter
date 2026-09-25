import pytest

from m_hunter.analyzers.xxe import (
    XXEAnalysis,
    XXEAnalyzer,
    XXEIndicatorType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.xxe_pipeline import (
    XXEPipeline,
    XXEPipelineResult,
)


def response(
    *,
    status_code=200,
    content=b"same",
    url="https://example.com",
):
    return HttpResponse(
        status_code=status_code,
        url=url,
        headers={"content-type": "application/xml"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def pipeline():
    return XXEPipeline()


@pytest.fixture
def analysis():
    return XXEAnalysis(
        detected=True,
        indicator_count=1,
        types=[XXEIndicatorType.EXTERNAL_ENTITY],
        names=[XXEIndicatorType.EXTERNAL_ENTITY.value],
    )


def test_pipeline_returns_result(pipeline, analysis):
    result = pipeline.run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert isinstance(result, XXEPipelineResult)


def test_pipeline_returns_validation(pipeline, analysis):
    result = pipeline.run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.validation.response_changed is True
    assert result.validation.potential_xxe is True


def test_pipeline_returns_findings(pipeline, analysis):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == 1
    assert result.findings[0].cwe == "CWE-611"


def test_pipeline_potential_xxe_property(pipeline, analysis):
    result = pipeline.run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_xxe is True


def test_pipeline_no_potential_without_change(pipeline, analysis):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.potential_xxe is False


def test_pipeline_finding_count_property(pipeline, analysis):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == len(result.findings)


def test_pipeline_preserves_target_and_endpoint(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
        endpoint="/api/xml",
    )

    assert result.findings[0].target == "https://example.com"
    assert result.findings[0].endpoint == "/api/xml"


def test_pipeline_passes_external_behavior(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
        external_entity_behavior=True,
    )

    assert result.validation.external_entity_behavior is True
    assert result.validation.status == "external_entity_behavior"


def test_pipeline_accepts_empty_analysis(pipeline):
    analysis = XXEAnalysis()

    result = pipeline.run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_xxe is False
    assert result.findings == []
    assert result.validation.status == "no_indicator"


def test_pipeline_rejects_invalid_analysis(pipeline):
    with pytest.raises(
        TypeError,
        match="analysis must be an XXEAnalysis instance",
    ):
        pipeline.run(
            response(),
            response(),
            object(),
            target="https://example.com",
        )


def test_pipeline_detects_multiple_findings(pipeline):
    analyzer = XXEAnalyzer()

    analysis = analyzer.analyze(
        '<!DOCTYPE root>'
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
        "<root>&test;</root>"
    )

    result = pipeline.run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == len(analysis.types)
    assert result.potential_xxe is True


def test_pipeline_does_not_infer_external_behavior(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.validation.external_entity_behavior is False
    assert result.validation.status == "potential_xxe"


def test_pipeline_explicit_external_behavior(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
        external_entity_behavior=True,
    )

    assert result.validation.external_entity_behavior is True
    assert result.validation.status == "external_entity_behavior"


def test_pipeline_findings_are_independent_of_validation(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count > 0
    assert result.potential_xxe is False


def test_pipeline_uses_default_endpoint_none(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.findings[0].endpoint is None


def test_pipeline_result_exposes_same_validation_object(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.validation is not None
    assert result.validation.baseline_status == 200


def test_pipeline_finding_metadata_is_preserved(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    finding = result.findings[0]

    assert finding.severity == "High"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-611"
    assert finding.owasp == "A05:2021"


def test_pipeline_response_change_detected_by_status(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(status_code=200),
        response(status_code=500),
        analysis,
        target="https://example.com",
    )

    assert result.potential_xxe is True
    assert result.validation.status_changed is True


def test_pipeline_response_change_detected_by_content(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_xxe is True
    assert result.validation.content_changed is True


def test_pipeline_same_response_is_not_potential(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_xxe is False
    assert result.validation.status == "indicator_detected"


def test_pipeline_result_finding_count_matches_findings(
    pipeline,
    analysis,
):
    result = pipeline.run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == len(result.findings)


def test_pipeline_requires_keyword_target(
    pipeline,
    analysis,
):
    with pytest.raises(TypeError):
        pipeline.run(
            response(),
            response(),
            analysis,
        )
