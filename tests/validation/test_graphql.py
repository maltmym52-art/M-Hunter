import pytest

from m_hunter.analyzers.graphql import (
    GraphQLAnalysis,
    GraphQLIndicatorType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.graphql import (
    GraphQLValidationResult,
    GraphQLValidator,
)


def make_response(
    status_code=200,
    content=b"same",
    url="https://example.com/graphql",
):
    return HttpResponse(
        status_code=status_code,
        url=url,
        headers={"content-type": "application/json"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
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


@pytest.fixture
def validator():
    return GraphQLValidator()


def test_identical_responses_are_not_changed(validator):
    baseline = make_response()
    candidate = make_response()

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert result.status_changed is False
    assert result.content_changed is False
    assert result.content_length_changed is False
    assert result.response_changed is False


def test_status_change_is_detected(validator):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=403)

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True


def test_content_change_is_detected(validator):
    baseline = make_response(content=b"first")
    candidate = make_response(content=b"second")

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert result.content_changed is True
    assert result.response_changed is True


def test_content_length_change_is_detected(validator):
    baseline = make_response(content=b"short")
    candidate = make_response(content=b"a much longer response")

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert result.content_length_changed is True
    assert result.response_changed is True


def test_behavior_change_is_detected(validator):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
        behavior_changed=True,
    )

    assert result.behavior_changed is True
    assert result.potential_graphql_issue is True
    assert result.status == "behavior_changed"


def test_detected_graphql_with_response_change_is_potential_issue(
    validator,
):
    result = validator.validate(
        make_response(content=b"baseline"),
        make_response(content=b"candidate"),
        make_analysis(),
    )

    assert result.potential_graphql_issue is True
    assert result.status == "potential_graphql_issue"


def test_detected_graphql_without_change_is_indicator_only(
    validator,
):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert result.potential_graphql_issue is False
    assert result.status == "indicator_detected"


def test_no_graphql_indicator_returns_no_indicator(validator):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(detected=False),
    )

    assert result.potential_graphql_issue is False
    assert result.status == "no_indicator"


def test_behavior_change_without_graphql_indicator_does_not_create_issue(
    validator,
):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(detected=False),
        behavior_changed=True,
    )

    assert result.potential_graphql_issue is False
    assert result.status == "no_indicator"


def test_baseline_status_is_preserved(validator):
    result = validator.validate(
        make_response(status_code=201),
        make_response(status_code=200),
        make_analysis(),
    )

    assert result.baseline_status == 201


def test_candidate_status_is_preserved(validator):
    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=201),
        make_analysis(),
    )

    assert result.candidate_status == 201


def test_result_is_correct_type(validator):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert isinstance(result, GraphQLValidationResult)


def test_result_contains_evidence(validator):
    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=403),
        make_analysis(),
    )

    assert result.evidence
    assert "Baseline status: 200" in result.evidence
    assert "Candidate status: 403" in result.evidence


def test_evidence_contains_status_change(validator):
    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=403),
        make_analysis(),
    )

    assert "Status changed: True" in result.evidence


def test_evidence_contains_content_change(validator):
    result = validator.validate(
        make_response(content=b"a"),
        make_response(content=b"b"),
        make_analysis(),
    )

    assert "Content changed: True" in result.evidence


def test_evidence_contains_behavior_change(validator):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
        behavior_changed=True,
    )

    assert "Behavior changed: True" in result.evidence


def test_invalid_baseline_type(validator):
    with pytest.raises(TypeError):
        validator.validate(
            object(),
            make_response(),
            make_analysis(),
        )


def test_invalid_candidate_type(validator):
    with pytest.raises(TypeError):
        validator.validate(
            make_response(),
            object(),
            make_analysis(),
        )


def test_invalid_analysis_type(validator):
    with pytest.raises(TypeError):
        validator.validate(
            make_response(),
            make_response(),
            object(),
        )


def test_default_behavior_changed_is_false(validator):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert result.behavior_changed is False


def test_status_change_from_success_to_error(validator):
    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=500),
        make_analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_graphql_issue is True


def test_status_change_from_error_to_success(validator):
    result = validator.validate(
        make_response(status_code=500),
        make_response(status_code=200),
        make_analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_graphql_issue is True


def test_only_content_length_difference_counts_as_change(validator):
    baseline = make_response(content=b"same")
    candidate = make_response(content=b"same")

    candidate.content_length = 999

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert result.content_changed is False
    assert result.content_length_changed is True
    assert result.response_changed is True


def test_all_response_change_flags_can_be_true(validator):
    result = validator.validate(
        make_response(
            status_code=200,
            content=b"baseline",
        ),
        make_response(
            status_code=500,
            content=b"candidate",
        ),
        make_analysis(),
        behavior_changed=True,
    )

    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is True
    assert result.response_changed is True
    assert result.behavior_changed is True
    assert result.potential_graphql_issue is True


def test_introspection_analysis_is_accepted(validator):
    analysis = GraphQLAnalysis(
        detected=True,
        indicator_count=1,
        types=[GraphQLIndicatorType.INTROSPECTION_ENABLED],
        names=["introspection"],
        indicators=[],
    )

    result = validator.validate(
        make_response(),
        make_response(),
        analysis,
    )

    assert result.status == "indicator_detected"


def test_batching_analysis_is_accepted(validator):
    analysis = GraphQLAnalysis(
        detected=True,
        indicator_count=1,
        types=[GraphQLIndicatorType.BATCHING],
        names=["batching"],
        indicators=[],
    )

    result = validator.validate(
        make_response(),
        make_response(content=b"changed"),
        analysis,
    )

    assert result.potential_graphql_issue is True


def test_deep_query_analysis_is_accepted(validator):
    analysis = GraphQLAnalysis(
        detected=True,
        indicator_count=1,
        types=[GraphQLIndicatorType.DEEP_QUERY],
        names=["deep"],
        indicators=[],
    )

    result = validator.validate(
        make_response(),
        make_response(),
        analysis,
    )

    assert result.status == "indicator_detected"


def test_sensitive_field_analysis_is_accepted(validator):
    analysis = GraphQLAnalysis(
        detected=True,
        indicator_count=1,
        types=[GraphQLIndicatorType.SENSITIVE_FIELD],
        names=["password"],
        indicators=[],
    )

    result = validator.validate(
        make_response(),
        make_response(content=b"changed"),
        analysis,
    )

    assert result.potential_graphql_issue is True


def test_no_change_with_behavior_false_has_no_issue(validator):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
        behavior_changed=False,
    )

    assert result.response_changed is False
    assert result.behavior_changed is False
    assert result.potential_graphql_issue is False


def test_result_fields_are_consistent(validator):
    result = validator.validate(
        make_response(status_code=200, content=b"a"),
        make_response(status_code=403, content=b"b"),
        make_analysis(),
        behavior_changed=True,
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 403
    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is False
    assert result.response_changed is True
    assert result.behavior_changed is True
    assert result.potential_graphql_issue is True


def test_evidence_has_all_core_flags(validator):
    result = validator.validate(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        behavior_changed=True,
    )

    evidence = "\n".join(result.evidence)

    assert "Baseline status:" in evidence
    assert "Candidate status:" in evidence
    assert "Status changed:" in evidence
    assert "Content changed:" in evidence
    assert "Content length changed:" in evidence
    assert "Response changed:" in evidence
    assert "Behavior changed:" in evidence
