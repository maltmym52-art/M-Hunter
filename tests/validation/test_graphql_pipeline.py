import pytest

from m_hunter.analyzers.graphql import (
    GraphQLAnalysis,
    GraphQLIndicatorType,
)
from m_hunter.validation.graphql import (
    GraphQLValidationResult,
)
from m_hunter.validation.graphql_pipeline import (
    GraphQLPipelineResult,
    GraphQLValidationPipeline,
)


def make_analysis(detected=True):
    return GraphQLAnalysis(
        detected=detected,
        indicator_count=1 if detected else 0,
        types=(
            [GraphQLIndicatorType.QUERY_OPERATION]
            if detected
            else []
        ),
        names=["query"] if detected else [],
        indicators=[],
    )


def make_validation(
    *,
    potential=False,
    behavior=False,
    status="indicator_detected",
):
    return GraphQLValidationResult(
        baseline_status=200,
        candidate_status=200,
        status_changed=False,
        content_changed=False,
        content_length_changed=False,
        response_changed=False,
        behavior_changed=behavior,
        potential_graphql_issue=potential,
        status=status,
        evidence=[
            "Baseline status: 200",
            "Candidate status: 200",
        ],
    )


@pytest.fixture
def pipeline():
    return GraphQLValidationPipeline()


def test_pipeline_result_type(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(),
    )

    assert isinstance(result, GraphQLPipelineResult)


def test_indicator_without_issue_is_not_accepted(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(),
    )

    assert result.accepted is False
    assert result.findings == []


def test_potential_issue_is_accepted(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(potential=True),
    )

    assert result.accepted is True


def test_behavior_change_is_accepted(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(behavior=True),
    )

    assert result.accepted is True


def test_potential_issue_creates_finding_message(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(potential=True),
    )

    assert len(result.findings) == 1
    assert "GraphQL" in result.findings[0]


def test_behavior_change_creates_finding_message(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(behavior=True),
    )

    assert len(result.findings) == 1


def test_detected_graphql_with_both_flags_is_accepted(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(
            potential=True,
            behavior=True,
            status="behavior_changed",
        ),
    )

    assert result.accepted is True
    assert len(result.findings) == 1


def test_undetected_analysis_is_not_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(detected=False),
        make_validation(
            potential=True,
            behavior=True,
            status="behavior_changed",
        ),
    )

    assert result.accepted is False
    assert result.findings == []


def test_undetected_analysis_never_creates_finding(
    pipeline,
):
    result = pipeline.process(
        make_analysis(detected=False),
        make_validation(potential=True),
    )

    assert result.findings == []


def test_validation_object_is_preserved(pipeline):
    validation = make_validation(potential=True)

    result = pipeline.process(
        make_analysis(),
        validation,
    )

    assert result.validation is validation


def test_analysis_type_validation(pipeline):
    with pytest.raises(TypeError):
        pipeline.process(
            object(),
            make_validation(),
        )


def test_validation_type_validation(pipeline):
    with pytest.raises(TypeError):
        pipeline.process(
            make_analysis(),
            object(),
        )


def test_empty_analysis_and_clean_validation(
    pipeline,
):
    result = pipeline.process(
        make_analysis(detected=False),
        make_validation(),
    )

    assert result.accepted is False
    assert result.findings == []


def test_query_analysis_can_be_processed(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(potential=True),
    )

    assert result.accepted is True


def test_pipeline_requires_detected_analysis_for_acceptance(
    pipeline,
):
    analysis = GraphQLAnalysis(
        detected=False,
        indicator_count=0,
        types=[],
        names=[],
        indicators=[],
    )

    validation = make_validation(
        potential=True,
        behavior=True,
        status="behavior_changed",
    )

    result = pipeline.process(
        analysis,
        validation,
    )

    assert result.accepted is False


def test_pipeline_result_has_empty_findings_when_rejected(
    pipeline,
):
    result = pipeline.process(
        make_analysis(),
        make_validation(
            potential=False,
            behavior=False,
        ),
    )

    assert result.findings == []


def test_pipeline_result_findings_are_strings(
    pipeline,
):
    result = pipeline.process(
        make_analysis(),
        make_validation(potential=True),
    )

    assert all(
        isinstance(item, str)
        for item in result.findings
    )


def test_behavior_status_can_be_processed(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(
            behavior=True,
            status="behavior_changed",
        ),
    )

    assert result.accepted is True
    assert result.validation.status == "behavior_changed"


def test_potential_issue_status_can_be_processed(
    pipeline,
):
    result = pipeline.process(
        make_analysis(),
        make_validation(
            potential=True,
            status="potential_graphql_issue",
        ),
    )

    assert result.accepted is True
    assert result.validation.status == (
        "potential_graphql_issue"
    )


def test_indicator_detected_status_without_change_is_rejected(
    pipeline,
):
    result = pipeline.process(
        make_analysis(),
        make_validation(
            potential=False,
            behavior=False,
            status="indicator_detected",
        ),
    )

    assert result.accepted is False


def test_no_indicator_status_is_rejected(pipeline):
    result = pipeline.process(
        make_analysis(detected=False),
        make_validation(
            potential=False,
            behavior=False,
            status="no_indicator",
        ),
    )

    assert result.accepted is False


def test_finding_message_is_security_focused(
    pipeline,
):
    result = pipeline.process(
        make_analysis(),
        make_validation(potential=True),
    )

    assert "security validation" in (
        result.findings[0].lower()
    )


def test_multiple_calls_are_independent(pipeline):
    accepted = pipeline.process(
        make_analysis(),
        make_validation(potential=True),
    )

    rejected = pipeline.process(
        make_analysis(),
        make_validation(),
    )

    assert accepted.accepted is True
    assert rejected.accepted is False
    assert len(accepted.findings) == 1
    assert rejected.findings == []


def test_pipeline_does_not_modify_analysis(pipeline):
    analysis = make_analysis()
    original_detected = analysis.detected
    original_types = analysis.types.copy()

    pipeline.process(
        analysis,
        make_validation(potential=True),
    )

    assert analysis.detected == original_detected
    assert analysis.types == original_types


def test_pipeline_does_not_modify_validation(
    pipeline,
):
    validation = make_validation(potential=True)
    original_status = validation.status
    original_accepted = validation.potential_graphql_issue

    pipeline.process(
        make_analysis(),
        validation,
    )

    assert validation.status == original_status
    assert (
        validation.potential_graphql_issue
        == original_accepted
    )
