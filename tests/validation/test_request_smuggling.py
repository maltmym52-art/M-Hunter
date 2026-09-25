import pytest

from m_hunter.analyzers.request_smuggling import (
    RequestSmugglingAnalysis,
    SmugglingIndicatorType,
    SmugglingType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.request_smuggling import (
    RequestSmugglingValidationResult,
    RequestSmugglingValidator,
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
        headers={"content-type": "text/plain"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def validator():
    return RequestSmugglingValidator()


@pytest.fixture
def analysis():
    return RequestSmugglingAnalysis(
        detected=True,
        indicator_count=1,
        smuggling_types=[SmugglingType.CL_TE],
        types=[
            SmugglingIndicatorType.CONFLICTING_FRAMING
        ],
        names=[
            SmugglingIndicatorType.CONFLICTING_FRAMING.value
        ],
    )


def test_identical_responses_have_no_change(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(),
        analysis,
    )

    assert isinstance(
        result,
        RequestSmugglingValidationResult,
    )
    assert result.response_changed is False
    assert result.potential_smuggling is False
    assert result.status == "indicator_detected"


def test_status_change_is_detected(
    validator,
    analysis,
):
    result = validator.validate(
        response(status_code=200),
        response(status_code=500),
        analysis,
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_smuggling is True
    assert result.status == "potential_smuggling"


def test_content_change_is_detected(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.content_changed is True
    assert result.response_changed is True
    assert result.potential_smuggling is True


def test_content_length_change_is_detected(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"short"),
        response(content=b"much longer"),
        analysis,
    )

    assert result.content_length_changed is True
    assert result.response_changed is True
    assert result.potential_smuggling is True


def test_parser_behavior_change_gets_distinct_status(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(),
        analysis,
        parser_behavior_changed=True,
    )

    assert result.parser_behavior_changed is True
    assert result.potential_smuggling is True
    assert result.status == "parser_behavior_changed"


def test_parser_behavior_change_with_response_change(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        parser_behavior_changed=True,
    )

    assert result.response_changed is True
    assert result.parser_behavior_changed is True
    assert result.potential_smuggling is True
    assert result.status == "parser_behavior_changed"


def test_no_indicator_status(validator):
    analysis = RequestSmugglingAnalysis()

    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.response_changed is True
    assert result.potential_smuggling is False
    assert result.status == "no_indicator"


def test_indicator_without_response_change(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(),
        analysis,
    )

    assert result.potential_smuggling is False
    assert result.status == "indicator_detected"


def test_parser_behavior_without_indicator(
    validator,
):
    result = validator.validate(
        response(),
        response(),
        RequestSmugglingAnalysis(),
        parser_behavior_changed=True,
    )

    assert result.parser_behavior_changed is True
    assert result.potential_smuggling is False
    assert result.status == "no_indicator"


def test_status_changed_false_when_same(
    validator,
    analysis,
):
    result = validator.validate(
        response(status_code=200),
        response(status_code=200),
        analysis,
    )

    assert result.status_changed is False


def test_content_changed_false_when_same(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert result.content_changed is False


def test_content_length_changed_false_when_same(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert result.content_length_changed is False


def test_response_changed_matches_component_flags(
    validator,
    analysis,
):
    result = validator.validate(
        response(status_code=200),
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


def test_evidence_contains_parser_behavior(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(),
        analysis,
        parser_behavior_changed=True,
    )

    assert "Parser behavior changed: True" in result.evidence


def test_parser_behavior_defaults_to_false(
    validator,
    analysis,
):
    result = validator.validate(
        response(),
        response(),
        analysis,
    )

    assert result.parser_behavior_changed is False


def test_invalid_baseline_type(
    validator,
    analysis,
):
    with pytest.raises(
        TypeError,
        match="baseline must be an HttpResponse instance",
    ):
        validator.validate(
            object(),
            response(),
            analysis,
        )


def test_invalid_candidate_type(
    validator,
    analysis,
):
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
        match=(
            "analysis must be a "
            "RequestSmugglingAnalysis instance"
        ),
    ):
        validator.validate(
            response(),
            response(),
            object(),
        )


def test_invalid_parser_behavior_type(
    validator,
    analysis,
):
    with pytest.raises(
        TypeError,
        match="parser_behavior_changed must be a bool",
    ):
        validator.validate(
            response(),
            response(),
            analysis,
            parser_behavior_changed="yes",
        )


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


def test_indicator_alone_does_not_confirm_smuggling(
    validator,
    analysis,
):
    result = validator.validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert result.status == "indicator_detected"
    assert result.potential_smuggling is False
    assert result.parser_behavior_changed is False


def test_response_change_requires_indicator_for_potential(
    validator,
):
    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        RequestSmugglingAnalysis(),
    )

    assert result.response_changed is True
    assert result.potential_smuggling is False
    assert result.status == "no_indicator"


def test_cl_te_analysis_is_accepted(
    validator,
):
    analysis = RequestSmugglingAnalysis(
        detected=True,
        indicator_count=1,
        smuggling_types=[SmugglingType.CL_TE],
        types=[
            SmugglingIndicatorType.CONFLICTING_FRAMING
        ],
        names=[
            SmugglingIndicatorType.CONFLICTING_FRAMING.value
        ],
    )

    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.potential_smuggling is True


def test_duplicate_content_length_analysis_is_accepted(
    validator,
):
    analysis = RequestSmugglingAnalysis(
        detected=True,
        indicator_count=1,
        smuggling_types=[
            SmugglingType.DUPLICATE_CONTENT_LENGTH
        ],
        types=[
            SmugglingIndicatorType.DUPLICATE_CONTENT_LENGTH
        ],
        names=[
            SmugglingIndicatorType
            .DUPLICATE_CONTENT_LENGTH.value
        ],
    )

    result = validator.validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.potential_smuggling is True
