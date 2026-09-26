import pytest

from m_hunter.analyzers.clickjacking import (
    ClickjackingAnalysis,
    ClickjackingIndicator,
    ClickjackingIndicatorType,
)
from m_hunter.validation.clickjacking_pipeline import (
    ClickjackingPipeline,
    ClickjackingPipelineResult,
)


def make_analysis(*types):
    indicators = [
        ClickjackingIndicator(
            type=indicator_type,
            name=indicator_type.value,
            value=indicator_type.value,
        )
        for indicator_type in types
    ]

    return ClickjackingAnalysis(
        detected=bool(indicators),
        indicators=indicators,
    )


@pytest.fixture
def pipeline():
    return ClickjackingPipeline()


def test_pipeline_can_be_created(pipeline):
    assert isinstance(
        pipeline,
        ClickjackingPipeline,
    )


def test_clean_analysis_is_rejected(pipeline):
    result = pipeline.run(
        analysis=make_analysis(),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert isinstance(
        result,
        ClickjackingPipelineResult,
    )
    assert result.accepted is False
    assert result.findings == []


def test_weak_policy_without_response_change_is_rejected(
    pipeline,
):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_weak_policy_with_status_change_is_accepted(
    pipeline,
):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_weak_policy_with_content_change_is_accepted(
    pipeline,
):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD,
        ),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_weak_policy_with_content_length_change_is_accepted(
    pipeline,
):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
        target="https://example.com",
    )

    assert result.accepted is True


def test_weak_policy_with_header_change_is_accepted(
    pipeline,
):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS,
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
        target="https://example.com",
    )

    assert result.accepted is True


def test_safe_deny_is_rejected(pipeline):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.X_FRAME_OPTIONS_DENY,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_safe_sameorigin_is_rejected(pipeline):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.X_FRAME_OPTIONS_SAMEORIGIN,
        ),
        baseline_status=200,
        candidate_status=403,
        content_changed=True,
        target="https://example.com",
    )

    assert result.accepted is False


def test_safe_frame_ancestors_none_is_rejected(
    pipeline,
):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.FRAME_ANCESTORS_NONE,
        ),
        baseline_status=200,
        candidate_status=403,
        content_changed=True,
        target="https://example.com",
    )

    assert result.accepted is False


def test_csp_present_alone_is_rejected(pipeline):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.CSP_PRESENT,
        ),
        baseline_status=200,
        candidate_status=403,
        content_changed=True,
        target="https://example.com",
    )

    assert result.accepted is False


def test_findings_preserve_target(pipeline):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://target.example",
    )

    assert result.findings[0].target == "https://target.example"


def test_findings_preserve_endpoint(pipeline):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
        endpoint="/account",
    )

    assert result.findings[0].endpoint == "/account"


def test_validation_is_exposed(pipeline):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.validation.potential_clickjacking
    assert result.validation.status == "potential"


def test_multiple_indicators_create_findings(pipeline):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
            ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 2


def test_pipeline_name():
    assert ClickjackingPipeline.name == "clickjacking_pipeline"


def test_pipeline_is_reusable(pipeline):
    first = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    second = pipeline.run(
        analysis=make_analysis(),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert first.accepted is True
    assert second.accepted is False


def test_invalid_analysis_is_rejected(pipeline):
    with pytest.raises(TypeError):
        pipeline.run(
            analysis=object(),
            baseline_status=200,
            candidate_status=403,
            target="https://example.com",
        )


def test_header_change_without_weak_policy_is_rejected(
    pipeline,
):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.CSP_PRESENT,
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
        target="https://example.com",
    )

    assert result.accepted is False


def test_status_change_and_weak_policy_produce_finding(
    pipeline,
):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD,
        ),
        baseline_status=200,
        candidate_status=500,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 1


def test_findings_are_empty_when_not_accepted(pipeline):
    result = pipeline.run(
        analysis=make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert result.findings == []
