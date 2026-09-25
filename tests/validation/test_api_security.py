import pytest

from m_hunter.analyzers.api_security import (
    APIAnalysis,
    APIIndicatorType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.api_security import (
    APIValidationResult,
    APISecurityValidator,
)


def make_response(
    status_code=200,
    content=b"same",
    headers=None,
    url="https://example.com/api",
):
    return HttpResponse(
        status_code=status_code,
        url=url,
        headers=headers or {
            "content-type": "application/json",
        },
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
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


@pytest.fixture
def validator():
    return APISecurityValidator()


def test_identical_responses_are_not_changed(validator):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert result.status_changed is False
    assert result.content_changed is False
    assert result.content_length_changed is False
    assert result.headers_changed is False
    assert result.response_changed is False


def test_status_change_is_detected(validator):
    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=403),
        make_analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True


def test_content_change_is_detected(validator):
    result = validator.validate(
        make_response(content=b"first"),
        make_response(content=b"second"),
        make_analysis(),
    )

    assert result.content_changed is True
    assert result.response_changed is True


def test_content_length_change_is_detected(validator):
    baseline = make_response(content=b"short")
    candidate = make_response(content=b"much longer")

    candidate.content_length = 999

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert result.content_length_changed is True
    assert result.response_changed is True


def test_header_change_is_detected(validator):
    baseline = make_response(
        headers={
            "content-type": "application/json",
        }
    )
    candidate = make_response(
        headers={
            "content-type": "application/json",
            "x-test": "changed",
        }
    )

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert result.headers_changed is True
    assert result.response_changed is True


def test_behavior_change_is_detected(validator):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
        behavior_changed=True,
    )

    assert result.behavior_changed is True
    assert result.potential_api_issue is True
    assert result.status == "behavior_changed"


def test_response_change_creates_potential_issue(
    validator,
):
    result = validator.validate(
        make_response(content=b"baseline"),
        make_response(content=b"candidate"),
        make_analysis(),
    )

    assert result.potential_api_issue is True
    assert result.status == "potential_api_issue"


def test_detected_indicator_without_change_is_indicator_only(
    validator,
):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert result.potential_api_issue is False
    assert result.status == "indicator_detected"


def test_no_indicator_returns_no_indicator(
    validator,
):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(detected=False),
    )

    assert result.potential_api_issue is False
    assert result.status == "no_indicator"


def test_behavior_change_without_indicator_is_not_issue(
    validator,
):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(detected=False),
        behavior_changed=True,
    )

    assert result.potential_api_issue is False
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


def test_result_type(validator):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
    )

    assert isinstance(result, APIValidationResult)


def test_evidence_is_present(validator):
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
        make_response(),
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


def test_evidence_contains_content_length_change(
    validator,
):
    baseline = make_response(content=b"same")
    candidate = make_response(content=b"same")
    candidate.content_length = 100

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert (
        "Content length changed: True"
        in result.evidence
    )


def test_evidence_contains_header_change(validator):
    baseline = make_response()
    candidate = make_response(
        headers={
            "content-type": "application/json",
            "x-new-header": "value",
        }
    )

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert "Headers changed: True" in result.evidence


def test_evidence_contains_behavior_change(
    validator,
):
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


def test_success_to_error_is_detected(validator):
    result = validator.validate(
        make_response(status_code=200),
        make_response(status_code=500),
        make_analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_api_issue is True


def test_error_to_success_is_detected(validator):
    result = validator.validate(
        make_response(status_code=500),
        make_response(status_code=200),
        make_analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_api_issue is True


def test_only_header_difference_counts_as_response_change(
    validator,
):
    baseline = make_response(
        headers={
            "content-type": "application/json",
        }
    )
    candidate = make_response(
        headers={
            "content-type": "application/json",
            "x-security": "enabled",
        }
    )

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert result.status_changed is False
    assert result.content_changed is False
    assert result.content_length_changed is False
    assert result.headers_changed is True
    assert result.response_changed is True


def test_all_change_flags_can_be_true(validator):
    baseline = make_response(
        status_code=200,
        content=b"baseline",
        headers={
            "content-type": "application/json",
        },
    )

    candidate = make_response(
        status_code=500,
        content=b"candidate",
        headers={
            "content-type": "text/plain",
            "x-test": "changed",
        },
    )

    candidate.content_length = 999

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
        behavior_changed=True,
    )

    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is True
    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.behavior_changed is True
    assert result.potential_api_issue is True


@pytest.mark.parametrize(
    "indicator_type",
    list(APIIndicatorType),
)
def test_all_api_indicator_types_are_accepted(
    validator,
    indicator_type,
):
    analysis = APIAnalysis(
        detected=True,
        indicator_count=1,
        types=[indicator_type],
        names=[indicator_type.value],
        indicators=[],
    )

    result = validator.validate(
        make_response(),
        make_response(content=b"changed"),
        analysis,
    )

    assert result.potential_api_issue is True


def test_no_change_with_behavior_false_has_no_issue(
    validator,
):
    result = validator.validate(
        make_response(),
        make_response(),
        make_analysis(),
        behavior_changed=False,
    )

    assert result.response_changed is False
    assert result.behavior_changed is False
    assert result.potential_api_issue is False


def test_result_fields_are_consistent(validator):
    baseline = make_response(
        status_code=200,
        content=b"a",
    )
    candidate = make_response(
        status_code=403,
        content=b"b",
    )

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
        behavior_changed=True,
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 403
    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is False
    assert result.headers_changed is False
    assert result.response_changed is True
    assert result.behavior_changed is True
    assert result.potential_api_issue is True


def test_headers_are_compared_by_mapping_equality(
    validator,
):
    baseline = make_response(
        headers={
            "content-type": "application/json",
            "x-test": "one",
        }
    )
    candidate = make_response(
        headers={
            "content-type": "application/json",
            "x-test": "two",
        }
    )

    result = validator.validate(
        baseline,
        candidate,
        make_analysis(),
    )

    assert result.headers_changed is True


def test_identical_headers_do_not_trigger_change(
    validator,
):
    headers = {
        "content-type": "application/json",
        "x-test": "same",
    }

    result = validator.validate(
        make_response(headers=headers.copy()),
        make_response(headers=headers.copy()),
        make_analysis(),
    )

    assert result.headers_changed is False


def test_potential_issue_requires_detected_analysis(
    validator,
):
    result = validator.validate(
        make_response(content=b"a"),
        make_response(content=b"b"),
        make_analysis(detected=False),
    )

    assert result.response_changed is True
    assert result.potential_api_issue is False
    assert result.status == "no_indicator"
