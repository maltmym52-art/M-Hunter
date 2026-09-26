import pytest

from m_hunter.analyzers.race_condition import RaceConditionAnalyzer
from m_hunter.core.response import HttpResponse
from m_hunter.validation.race_condition import (
    RaceConditionValidationResult,
    RaceConditionValidator,
)


def make_response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/api/test",
        headers=headers or {"content-type": "application/json"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def validator():
    return RaceConditionValidator()


@pytest.fixture
def analyzer():
    return RaceConditionAnalyzer()


def test_no_indicator(validator, analyzer):
    baseline = make_response()
    candidate = make_response()

    analysis = analyzer.analyze()

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert isinstance(result, RaceConditionValidationResult)
    assert result.status == "no_indicator"
    assert not result.potential_race_condition
    assert result.evidence == []


def test_indicator_detected_without_response_change(
    validator,
    analyzer,
):
    baseline = make_response()
    candidate = make_response()

    analysis = analyzer.analyze(
        concurrent_requests=5,
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.status == "indicator_detected"
    assert not result.potential_race_condition


def test_status_change(
    validator,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=409)

    analysis = analyzer.analyze(
        concurrent_requests=5,
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.status_changed
    assert result.response_changed
    assert result.potential_race_condition
    assert result.status == "potential_race_condition"
    assert any("Status changed" in item for item in result.evidence)


def test_content_change(
    validator,
    analyzer,
):
    baseline = make_response(content=b"baseline")
    candidate = make_response(content=b"candidate")

    analysis = analyzer.analyze(
        repeated_requests=3,
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_race_condition


def test_content_length_change(
    validator,
    analyzer,
):
    baseline = make_response(content=b"one")
    candidate = make_response(content=b"three")

    analysis = analyzer.analyze(
        duplicate_operation=True,
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.content_length_changed
    assert result.response_changed
    assert result.potential_race_condition


def test_header_change(
    validator,
    analyzer,
):
    baseline = make_response(
        headers={"content-type": "application/json"}
    )
    candidate = make_response(
        headers={
            "content-type": "application/json",
            "x-request-id": "123",
        }
    )

    analysis = analyzer.analyze(
        state_changed=True,
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_race_condition


def test_behavior_change(
    validator,
    analyzer,
):
    baseline = make_response()
    candidate = make_response()

    analysis = analyzer.analyze(
        concurrent_requests=4,
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed
    assert result.potential_race_condition
    assert result.status == "potential_race_condition"
    assert "Application behavior changed." in result.evidence


def test_response_changed_without_indicator(
    validator,
    analyzer,
):
    baseline = make_response(content=b"one")
    candidate = make_response(content=b"two")

    analysis = analyzer.analyze()

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.response_changed
    assert not result.potential_race_condition
    assert result.status == "response_changed"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"baseline": object()},
        {"candidate": object()},
        {"analysis": object()},
    ],
)
def test_invalid_arguments_rejected(
    validator,
    analyzer,
    kwargs,
):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze()

    values = {
        "baseline": baseline,
        "candidate": candidate,
        "analysis": analysis,
    }
    values.update(kwargs)

    with pytest.raises(TypeError):
        validator.compare(**values)


def test_invalid_behavior_flag(
    validator,
    analyzer,
):
    with pytest.raises(TypeError):
        validator.compare(
            make_response(),
            make_response(),
            analyzer.analyze(),
            behavior_changed="yes",
        )


@pytest.mark.parametrize(
    "analysis_kwargs",
    [
        {"balance_changed": True},
        {"coupon_redeemed": True},
        {"password_changed": True},
        {"mfa_operation": True},
        {"token_rotated": True},
        {"resource_created": True},
        {"resource_deleted": True},
        {"response_variation": True},
    ],
)
def test_sensitive_indicators_can_be_validated(
    validator,
    analyzer,
    analysis_kwargs,
):
    baseline = make_response(content=b"before")
    candidate = make_response(content=b"after")

    analysis = analyzer.analyze(**analysis_kwargs)

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.potential_race_condition
    assert result.status == "potential_race_condition"


def test_multiple_response_differences(
    validator,
    analyzer,
):
    baseline = make_response(
        status_code=200,
        content=b"before",
        headers={"content-type": "application/json"},
    )
    candidate = make_response(
        status_code=500,
        content=b"after-response",
        headers={"content-type": "text/plain"},
    )

    analysis = analyzer.analyze(
        concurrent_requests=10,
        duplicate_operation=True,
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.status_changed
    assert result.content_changed
    assert result.content_length_changed
    assert result.headers_changed
    assert result.response_changed
    assert result.potential_race_condition
    assert len(result.evidence) == 4
