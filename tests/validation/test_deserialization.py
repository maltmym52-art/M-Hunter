import pytest

from m_hunter.analyzers.deserialization import (
    DeserializationAnalysis,
    DeserializationIndicator,
    DeserializationIndicatorType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.deserialization import (
    DeserializationValidationResult,
    DeserializationValidator,
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


def test_identical_responses_are_not_potential_deserialization():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert isinstance(result, DeserializationValidationResult)
    assert result.status_changed is False
    assert result.content_changed is False
    assert result.content_length_changed is False
    assert result.response_changed is False
    assert result.potential_deserialization is False
    assert result.status == "indicator_detected"


def test_status_change_is_detected():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=500),
        make_analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_deserialization is True
    assert result.status == "potential_deserialization"


def test_content_change_is_detected():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(content=b"normal"),
        make_response(content=b"changed"),
        make_analysis(),
    )

    assert result.content_changed is True
    assert result.response_changed is True
    assert result.potential_deserialization is True


def test_content_length_change_is_detected():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(content=b"abc"),
        make_response(
            content=b"abc",
            content_length=100,
        ),
        make_analysis(),
    )

    assert result.content_length_changed is True
    assert result.response_changed is True
    assert result.potential_deserialization is True


def test_behavior_change_is_detected():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
        behavior_changed=True,
    )

    assert result.behavior_changed is True
    assert result.potential_deserialization is True
    assert result.status == "behavior_changed"


def test_behavior_change_has_priority_in_status():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        behavior_changed=True,
    )

    assert result.status == "behavior_changed"
    assert result.potential_deserialization is True


def test_no_indicator_returns_no_indicator_status():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(detected=False),
    )

    assert result.status == "no_indicator"
    assert result.potential_deserialization is False


def test_no_indicator_with_behavior_change_is_not_potential():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(detected=False),
        behavior_changed=True,
    )

    assert result.status == "no_indicator"
    assert result.potential_deserialization is False


def test_response_change_without_indicator_is_not_potential():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(status_code=500),
        make_analysis(detected=False),
    )

    assert result.response_changed is True
    assert result.potential_deserialization is False


def test_baseline_status_is_preserved():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(status_code=201),
        make_response(status_code=201),
        make_analysis(),
    )

    assert result.baseline_status == 201


def test_candidate_status_is_preserved():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=418),
        make_analysis(),
    )

    assert result.candidate_status == 418


def test_evidence_is_generated():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
    )

    assert result.evidence
    assert any(
        "Baseline status" in item
        for item in result.evidence
    )
    assert any(
        "Candidate status" in item
        for item in result.evidence
    )


def test_evidence_contains_status_change():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=500),
        make_analysis(),
    )

    assert any(
        "Status changed: True" in item
        for item in result.evidence
    )


def test_evidence_contains_content_change():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(content=b"a"),
        make_response(content=b"b"),
        make_analysis(),
    )

    assert any(
        "Content changed: True" in item
        for item in result.evidence
    )


def test_evidence_contains_content_length_change():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(content=b"a"),
        make_response(
            content=b"a",
            content_length=20,
        ),
        make_analysis(),
    )

    assert any(
        "Content length changed: True" in item
        for item in result.evidence
    )


def test_evidence_contains_behavior_change():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
        behavior_changed=True,
    )

    assert any(
        "Behavior changed: True" in item
        for item in result.evidence
    )


def test_response_change_is_false_for_identical_responses():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert result.response_changed is False


def test_response_change_is_true_for_status_change():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=404),
        make_analysis(),
    )

    assert result.response_changed is True


def test_response_change_is_true_for_content_change():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(content=b"one"),
        make_response(content=b"two"),
        make_analysis(),
    )

    assert result.response_changed is True


def test_response_change_is_true_for_length_change():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(content=b"one"),
        make_response(
            content=b"one",
            content_length=99,
        ),
        make_analysis(),
    )

    assert result.response_changed is True


def test_validator_rejects_invalid_baseline():
    validator = DeserializationValidator()

    with pytest.raises(TypeError):
        validator.validate(
            object(),
            make_response(),
            make_analysis(),
        )


def test_validator_rejects_invalid_candidate():
    validator = DeserializationValidator()

    with pytest.raises(TypeError):
        validator.validate(
            make_response(),
            object(),
            make_analysis(),
        )


def test_validator_rejects_invalid_analysis():
    validator = DeserializationValidator()

    with pytest.raises(TypeError):
        validator.validate(
            make_response(),
            make_response(),
            object(),
        )


def test_result_fields_are_consistent():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(status_code=200, content=b"a"),
        make_response(status_code=500, content=b"b"),
        make_analysis(),
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 500
    assert result.status_changed is True
    assert result.content_changed is True
    assert result.response_changed is True
    assert result.potential_deserialization is True


def test_indicator_without_changes_remains_indicator_detected():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert result.status == "indicator_detected"
    assert result.potential_deserialization is False


def test_behavior_change_without_response_change_is_potential():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
        behavior_changed=True,
    )

    assert result.response_changed is False
    assert result.behavior_changed is True
    assert result.potential_deserialization is True


def test_result_evidence_has_expected_number_of_entries():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert len(result.evidence) == 7


def test_clean_analysis_has_no_indicator_status():
    validator = DeserializationValidator()

    result = validator.validate(
        make_response(),
        make_response(),
        DeserializationAnalysis(),
    )

    assert result.status == "no_indicator"
    assert result.potential_deserialization is False
