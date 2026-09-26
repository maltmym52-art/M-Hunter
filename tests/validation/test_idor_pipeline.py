import pytest

from m_hunter.analyzers.idor import (
    IDORAnalysis,
    IDORIndicator,
    IDORIndicatorType,
)
from m_hunter.validation.idor_pipeline import (
    IDORPipeline,
    IDORPipelineResult,
)
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


def make_request(
    *,
    url="https://example.com/api",
    params=None,
):
    return HttpRequest(
        method="GET",
        url=url,
        params=params or {},
    )


def make_response(
    *,
    status_code=200,
    content=b"same",
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/api",
        headers={},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def make_analysis(
    *types,
):
    indicators = [
        IDORIndicator(
            type=indicator_type,
            name=indicator_type.value,
            value="123",
        )
        for indicator_type in types
    ]

    return IDORAnalysis(
        detected=bool(indicators),
        indicators=indicators,
    )


def make_requests():
    baseline = make_request(
        params={"id": "1"},
    )

    candidate = make_request(
        params={"id": "2"},
    )

    return baseline, candidate


@pytest.fixture
def pipeline():
    return IDORPipeline()


def test_pipeline_can_be_created(pipeline):
    assert isinstance(pipeline, IDORPipeline)


def test_clean_analysis_is_rejected(pipeline):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(),
        baseline_request=baseline,
        baseline_response=make_response(content=b"same"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"different"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    assert isinstance(result, IDORPipelineResult)
    assert result.accepted is False
    assert result.findings == []


def test_analysis_without_behavior_change_is_rejected(
    pipeline,
):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"same"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"same"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_resource_change_with_behavior_change_is_accepted(
    pipeline,
):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"user-1"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"user-2"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_identity_change_with_behavior_change_is_accepted(
    pipeline,
):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.USER_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"private"),
        candidate_request=candidate,
        candidate_response=make_response(status_code=403),
        parameter="user_id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
        identity_changed=True,
    )

    assert result.accepted is True
    assert result.findings


def test_authorization_context_change_with_behavior_change(
    pipeline,
):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"private"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"changed"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
        authorization_context_changed=True,
    )

    assert result.accepted is True


def test_findings_preserve_target(pipeline):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"a"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"b"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://target.example",
    )

    assert result.findings[0].target == "https://target.example"


def test_findings_preserve_endpoint(pipeline):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"a"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"b"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
        endpoint="/api/resource",
    )

    assert result.findings[0].endpoint == "/api/resource"


def test_findings_preserve_parameter(pipeline):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"a"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"b"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    assert result.findings[0].parameter == "id"


def test_multiple_indicators_produce_findings(pipeline):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
            IDORIndicatorType.NUMERIC_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"a"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"b"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 2


def test_validation_is_exposed(pipeline):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"a"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"b"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    assert result.validation.behavior_changed
    assert result.validation.potentially_accessible


def test_pipeline_name():
    assert IDORPipeline.name == "idor_pipeline"


def test_pipeline_is_reusable(pipeline):
    baseline, candidate = make_requests()

    first = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(content=b"a"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"b"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    second = pipeline.run(
        analysis=make_analysis(),
        baseline_request=baseline,
        baseline_response=make_response(content=b"a"),
        candidate_request=candidate,
        candidate_response=make_response(content=b"b"),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    assert first.accepted is True
    assert second.accepted is False


def test_candidate_request_must_differ(pipeline):
    baseline = make_request(
        params={"id": "1"},
    )

    with pytest.raises(ValueError):
        pipeline.run(
            analysis=make_analysis(
                IDORIndicatorType.OBJECT_IDENTIFIER,
            ),
            baseline_request=baseline,
            baseline_response=make_response(content=b"a"),
            candidate_request=baseline,
            candidate_response=make_response(content=b"b"),
            parameter="id",
            original_value="1",
            candidate_value="2",
            target="https://example.com",
        )


def test_status_change_counts_as_behavior_change(pipeline):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.OBJECT_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(status_code=200),
        candidate_request=candidate,
        candidate_response=make_response(status_code=403),
        parameter="id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    assert result.validation.behavior_changed
    assert result.accepted


def test_same_response_is_not_accepted(pipeline):
    baseline, candidate = make_requests()

    result = pipeline.run(
        analysis=make_analysis(
            IDORIndicatorType.USER_IDENTIFIER,
        ),
        baseline_request=baseline,
        baseline_response=make_response(
            status_code=200,
            content=b"same",
        ),
        candidate_request=candidate,
        candidate_response=make_response(
            status_code=200,
            content=b"same",
        ),
        parameter="user_id",
        original_value="1",
        candidate_value="2",
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
