import pytest

from m_hunter.analyzers.xxe import XXEAnalysis, XXEIndicatorType
from m_hunter.core.response import HttpResponse
from m_hunter.validation.xxe import (
    XXEValidationResult,
    XXEValidator,
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
def validator():
    return XXEValidator()


@pytest.fixture
def analysis():
    return XXEAnalysis(
        detected=True,
        indicator_count=1,
        types=[XXEIndicatorType.EXTERNAL_ENTITY],
        names=[XXEIndicatorType.EXTERNAL_ENTITY.value],
    )


def test_identical_responses_have_no_change(validator, analysis):
    result = validator.validate(
        response(),
        response(),
        analysis,
    )

    assert isinstance(result, XXEValidationResult)
    assert result.response_changed is False
    assert result.potential_xxe is False
    assert result.status == "indicator_detected"


def test_status_change_is_detected(validator, analysis):
    result = validator.validate(
        response(status_code=200),
        response(status_code=500),
        analysis,
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_xxe is True
    assert result.status == "potential_xxe"


def test_content_change_is_detected(validator, analysis):
    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.content_changed is True
    assert result.response_changed is True
    assert result.potential_xxe is True


def test_content_length_change_is_detected(validator, analysis):
    result = validator.validate(
        response(content=b"short"),
        response(content=b"much longer response"),
        analysis,
    )

    assert result.content_length_changed is True
    assert result.response_changed is True
    assert result.potential_xxe is True


def test_explicit_external_entity_behavior_gets_distinct_status(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        external_entity_behavior=True,
    )

    assert result.external_entity_behavior is True
    assert result.potential_xxe is True
    assert result.status == "external_entity_behavior"


def test_no_indicator_status(validator):
    analysis = XXEAnalysis()

    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.response_changed is True
    assert result.potential_xxe is False
    assert result.status == "no_indicator"


def test_indicator_without_response_change(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert result.potential_xxe is False
    assert result.status == "indicator_detected"


def test_external_behavior_without_response_change(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(),
        analysis,
        external_entity_behavior=True,
    )

    assert result.external_entity_behavior is True
    assert result.status == "external_entity_behavior"


def test_status_change_flag_is_false_when_same(
    validator,
    analysis,
):
    result = validator.validate(
        response(status_code=200),
        response(status_code=200),
        analysis,
    )

    assert result.status_changed is False


def test_content_change_flag_is_false_when_same(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert result.content_changed is False


def test_content_length_change_flag_is_false_when_same(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert result.content_length_changed is False


def test_response_changed_is_or_of_response_differences(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(status_code=201),
        analysis,
    )

    assert result.response_changed == (
        result.status_changed
        or result.content_changed
        or result.content_length_changed
    )


def test_baseline_status_is_preserved(
    validator,
    analysis,
):
    result = validator.validate(
        response(status_code=201),
        response(status_code=500),
        analysis,
    )

    assert result.baseline_status == 201


def test_candidate_status_is_preserved(
    validator,
    analysis,
):
    result = validator.validate(
        response(status_code=201),
        response(status_code=500),
        analysis,
    )

    assert result.candidate_status == 500


def test_evidence_contains_statuses(
    validator,
    analysis,
):
    result = validator.validate(
        response(status_code=200),
        response(status_code=500),
        analysis,
    )

    assert "Baseline status: 200" in result.evidence
    assert "Candidate status: 500" in result.evidence


def test_evidence_contains_change_flags(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    evidence = "\n".join(result.evidence)

    assert "Status changed:" in evidence
    assert "Content changed:" in evidence
    assert "Content length changed:" in evidence
    assert "Response changed:" in evidence


def test_evidence_contains_external_behavior(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(),
        analysis,
        external_entity_behavior=True,
    )

    assert "External entity behavior: True" in result.evidence


def test_invalid_baseline_type(validator, analysis):
    with pytest.raises(
        TypeError,
        match="baseline must be an HttpResponse instance",
    ):
        validator.validate(
            object(),
            response(),
            analysis,
        )


def test_invalid_candidate_type(validator, analysis):
    with pytest.raises(
        TypeError,
        match="candidate must be an HttpResponse instance",
    ):
        validator.validate(
            response(),
            object(),
            analysis,
        )


def test_invalid_analysis_type(validator):
    with pytest.raises(
        TypeError,
        match="analysis must be an XXEAnalysis instance",
    ):
        validator.validate(
            response(),
            response(),
            object(),
        )


def test_invalid_external_behavior_type(
    validator,
    analysis,
):
    with pytest.raises(
        TypeError,
        match="external_entity_behavior must be a bool",
    ):
        validator.validate(
            response(),
            response(),
            analysis,
            external_entity_behavior="yes",
        )


def test_result_preserves_external_behavior_false(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(),
        analysis,
        external_entity_behavior=False,
    )

    assert result.external_entity_behavior is False


def test_result_evidence_is_a_list(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(),
        analysis,
    )

    assert isinstance(result.evidence, list)
    assert result.evidence


def test_indicator_does_not_alone_confirm_xxe(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert result.status == "indicator_detected"
    assert result.potential_xxe is False
    assert result.external_entity_behavior is False


def test_response_change_requires_indicator_for_potential_xxe(
    validator,
):
    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        XXEAnalysis(),
    )

    assert result.response_changed is True
    assert result.potential_xxe is False
    assert result.status == "no_indicator"
