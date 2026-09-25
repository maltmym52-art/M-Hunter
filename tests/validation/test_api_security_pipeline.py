import pytest

from m_hunter.analyzers.api_security import (
    APIAnalysis,
    APIIndicatorType,
)
from m_hunter.validation.api_security import (
    APIValidationResult,
)
from m_hunter.validation.api_security_pipeline import (
    APIPipelineResult,
    APISecurityValidationPipeline,
)


def make_analysis(detected=True):
    return APIAnalysis(
        detected=detected,
        indicator_count=1 if detected else 0,
        types=(
            [APIIndicatorType.EXCESSIVE_DATA_EXPOSURE]
            if detected
            else []
        ),
        names=["password"] if detected else [],
        indicators=[],
    )


def make_validation(
    *,
    potential=False,
    behavior=False,
    status="indicator_detected",
):
    return APIValidationResult(
        baseline_status=200,
        candidate_status=200,
        status_changed=False,
        content_changed=False,
        content_length_changed=False,
        headers_changed=False,
        response_changed=False,
        behavior_changed=behavior,
        potential_api_issue=potential,
        status=status,
        evidence=[
            "Baseline status: 200",
            "Candidate status: 200",
        ],
    )


@pytest.fixture
def pipeline():
    return APISecurityValidationPipeline()


def test_pipeline_result_type(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(),
    )

    assert isinstance(result, APIPipelineResult)


def test_indicator_without_issue_is_rejected(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(),
    )

    assert result.accepted is False
    assert result.findings == []


def test_potential_api_issue_is_accepted(pipeline):
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


def test_potential_issue_creates_finding_message(
    pipeline,
):
    result = pipeline.process(
        make_analysis(),
        make_validation(potential=True),
    )

    assert len(result.findings) == 1
    assert "API" in result.findings[0]


def test_behavior_change_creates_finding_message(
    pipeline,
):
    result = pipeline.process(
        make_analysis(),
        make_validation(behavior=True),
    )

    assert len(result.findings) == 1


def test_both_flags_are_accepted(pipeline):
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


def test_undetected_analysis_is_rejected(pipeline):
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


def test_empty_analysis_is_rejected(pipeline):
    result = pipeline.process(
        make_analysis(detected=False),
        make_validation(),
    )

    assert result.accepted is False
    assert result.findings == []


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
    original_names = analysis.names.copy()

    pipeline.process(
        analysis,
        make_validation(potential=True),
    )

    assert analysis.detected == original_detected
    assert analysis.types == original_types
    assert analysis.names == original_names


def test_pipeline_does_not_modify_validation(pipeline):
    validation = make_validation(
        potential=True,
        behavior=True,
        status="behavior_changed",
    )

    original_status = validation.status
    original_potential = validation.potential_api_issue
    original_behavior = validation.behavior_changed

    pipeline.process(
        make_analysis(),
        validation,
    )

    assert validation.status == original_status
    assert (
        validation.potential_api_issue
        == original_potential
    )
    assert validation.behavior_changed == original_behavior


def test_finding_message_is_security_focused(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(potential=True),
    )

    assert "security validation" in (
        result.findings[0].lower()
    )


def test_behavior_status_is_accepted(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(
            behavior=True,
            status="behavior_changed",
        ),
    )

    assert result.accepted is True
    assert result.validation.status == "behavior_changed"


def test_potential_issue_status_is_accepted(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(
            potential=True,
            status="potential_api_issue",
        ),
    )

    assert result.accepted is True
    assert result.validation.status == (
        "potential_api_issue"
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


def test_finding_messages_are_strings(pipeline):
    result = pipeline.process(
        make_analysis(),
        make_validation(potential=True),
    )

    assert all(
        isinstance(item, str)
        for item in result.findings
    )


def test_clean_validation_produces_no_findings(
    pipeline,
):
    result = pipeline.process(
        make_analysis(),
        make_validation(
            potential=False,
            behavior=False,
        ),
    )

    assert result.accepted is False
    assert result.findings == []


def test_detected_analysis_with_behavior_change_is_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(detected=True),
        make_validation(
            behavior=True,
            status="behavior_changed",
        ),
    )

    assert result.accepted is True


def test_undetected_analysis_with_behavior_change_is_rejected(
    pipeline,
):
    result = pipeline.process(
        make_analysis(detected=False),
        make_validation(
            behavior=True,
            status="behavior_changed",
        ),
    )

    assert result.accepted is False
    assert result.findings == []
