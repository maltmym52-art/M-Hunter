import pytest

from m_hunter.analyzers.jwt import (
    JWTAnalysis,
    JWTAnalyzer,
    JWTIndicator,
    JWTIndicatorType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.jwt import JWTValidator


def make_response(
    *,
    status_code=200,
    content=b"OK",
    headers=None,
    cookies=None,
    response_time=0.1,
    content_length=None,
    repeated_headers=None,
):
    if content_length is None:
        content_length = len(content)

    return HttpResponse(
        status_code=status_code,
        url="https://example.com/api",
        headers=headers or {},
        content=content,
        cookies=cookies or {},
        response_time=response_time,
        content_length=content_length,
        repeated_headers=repeated_headers or {},
    )


@pytest.fixture
def validator():
    return JWTValidator()


@pytest.fixture
def clean_analysis():
    return JWTAnalysis(indicators=())


@pytest.fixture
def jwt_analysis():
    return JWTAnalyzer().analyze(
        algorithm="none",
    )


def test_identical_responses_have_no_changes(
    validator,
    clean_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=clean_analysis,
    )

    assert result.status_changed is False
    assert result.content_changed is False
    assert result.content_length_changed is False
    assert result.headers_changed is False
    assert result.response_changed is False
    assert result.behavior_changed is False
    assert result.potential_jwt_issue is False
    assert result.status == "no_indicator"


def test_status_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=401)

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.status_changed
    assert result.response_changed
    assert result.status == "no_indicator"


def test_content_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(content=b"before")
    candidate = make_response(content=b"after")

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.status == "no_indicator"


def test_content_length_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(
        content=b"abc",
        content_length=3,
    )
    candidate = make_response(
        content=b"abc",
        content_length=20,
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.content_length_changed
    assert result.response_changed


def test_header_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(
        headers={"X-Test": "one"},
    )
    candidate = make_response(
        headers={"X-Test": "two"},
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.headers_changed
    assert result.response_changed


def test_repeated_header_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(
        repeated_headers={
            "Set-Cookie": ["jwt=one"],
        },
    )
    candidate = make_response(
        repeated_headers={
            "Set-Cookie": ["jwt=two"],
        },
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.headers_changed
    assert result.response_changed


def test_behavior_change_is_detected(
    validator,
    clean_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=clean_analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed
    assert result.status == "behavior_changed"


def test_indicator_without_change_is_not_potential_issue(
    validator,
    jwt_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=jwt_analysis,
    )

    assert jwt_analysis.detected
    assert result.potential_jwt_issue is False
    assert result.status == "indicator_detected"


def test_indicator_with_response_change_is_potential_issue(
    validator,
    jwt_analysis,
):
    baseline = make_response(
        headers={"X-JWT": "one"},
    )
    candidate = make_response(
        headers={"X-JWT": "two"},
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=jwt_analysis,
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_jwt_issue
    assert result.status == "potential_jwt_issue"


def test_indicator_with_behavior_change_is_potential_issue(
    validator,
    jwt_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=jwt_analysis,
        behavior_changed=True,
    )

    assert result.potential_jwt_issue
    assert result.status == "potential_jwt_issue"


@pytest.mark.parametrize(
    "indicator_type",
    list(JWTIndicatorType),
)
def test_any_jwt_indicator_can_trigger_validation(
    validator,
    indicator_type,
):
    analysis = JWTAnalysis(
        indicators=(
            JWTIndicator(
                type=indicator_type,
                evidence="test evidence",
            ),
        )
    )

    baseline = make_response()
    candidate = make_response(
        content=b"changed-response",
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=analysis,
    )

    assert result.potential_jwt_issue
    assert result.status == "potential_jwt_issue"


def test_evidence_mentions_status_change(
    validator,
    clean_analysis,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=403)

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert any(
        "status changed" in item.lower()
        for item in result.evidence
    )


def test_evidence_mentions_content_change(
    validator,
    clean_analysis,
):
    baseline = make_response(content=b"one")
    candidate = make_response(content=b"two")

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert any(
        "content changed" in item.lower()
        for item in result.evidence
    )


def test_evidence_mentions_header_change(
    validator,
    clean_analysis,
):
    baseline = make_response(
        headers={"X-Test": "one"},
    )
    candidate = make_response(
        headers={"X-Test": "two"},
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert any(
        "headers changed" in item.lower()
        for item in result.evidence
    )


def test_evidence_mentions_behavior_change(
    validator,
    clean_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=clean_analysis,
        behavior_changed=True,
    )

    assert any(
        "behavior changed" in item.lower()
        for item in result.evidence
    )


def test_evidence_mentions_jwt_indicator(
    validator,
    jwt_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=jwt_analysis,
    )

    assert any(
        "jwt security indicators" in item.lower()
        for item in result.evidence
    )


def test_requires_baseline_response(
    validator,
    clean_analysis,
):
    with pytest.raises(TypeError):
        validator.compare(
            baseline="invalid",
            candidate=make_response(),
            analysis=clean_analysis,
        )


def test_requires_candidate_response(
    validator,
    clean_analysis,
):
    with pytest.raises(TypeError):
        validator.compare(
            baseline=make_response(),
            candidate="invalid",
            analysis=clean_analysis,
        )


def test_requires_jwt_analysis(validator):
    with pytest.raises(TypeError):
        validator.compare(
            baseline=make_response(),
            candidate=make_response(),
            analysis="invalid",
        )


def test_behavior_changed_must_be_boolean(
    validator,
    clean_analysis,
):
    with pytest.raises(TypeError):
        validator.compare(
            baseline=make_response(),
            candidate=make_response(),
            analysis=clean_analysis,
            behavior_changed="yes",
        )


def test_result_preserves_status_codes(
    validator,
    clean_analysis,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=403)

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 403


def test_multiple_changes_are_recorded(
    validator,
    jwt_analysis,
):
    baseline = make_response(
        status_code=200,
        content=b"one",
        headers={"X-Test": "one"},
    )

    candidate = make_response(
        status_code=401,
        content=b"two-two",
        headers={"X-Test": "two"},
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=jwt_analysis,
        behavior_changed=True,
    )

    assert result.status_changed
    assert result.content_changed
    assert result.content_length_changed
    assert result.headers_changed
    assert result.response_changed
    assert result.behavior_changed
    assert result.potential_jwt_issue
    assert result.status == "potential_jwt_issue"


def test_clean_analysis_with_response_change_has_no_jwt_issue(
    validator,
    clean_analysis,
):
    baseline = make_response(content=b"one")
    candidate = make_response(content=b"two")

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.response_changed
    assert result.potential_jwt_issue is False
    assert result.status == "no_indicator"
