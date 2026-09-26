import pytest

from m_hunter.analyzers.clickjacking import (
    ClickjackingAnalysis,
    ClickjackingIndicator,
    ClickjackingIndicatorType,
)
from m_hunter.validation.clickjacking import (
    ClickjackingValidationResult,
    ClickjackingValidator,
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
def validator():
    return ClickjackingValidator()


def test_validator_can_be_created(validator):
    assert isinstance(
        validator,
        ClickjackingValidator,
    )


def test_clean_analysis_is_clean(validator):
    result = validator.validate(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
    )

    assert isinstance(
        result,
        ClickjackingValidationResult,
    )
    assert result.status == "clean"
    assert result.potential_clickjacking is False


def test_missing_xfo_is_security_indicator(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present
    assert result.framing_policy_weak


def test_missing_frame_ancestors_is_weak(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.framing_policy_weak


def test_invalid_xfo_is_weak(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.framing_policy_weak


def test_allow_from_is_weak(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.X_FRAME_OPTIONS_ALLOW_FROM,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.framing_policy_weak


def test_wildcard_frame_ancestors_is_weak(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.framing_policy_weak


def test_safe_deny_is_not_weak(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.X_FRAME_OPTIONS_DENY,
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.framing_policy_weak is False
    assert result.potential_clickjacking is False


def test_safe_sameorigin_is_not_weak(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.X_FRAME_OPTIONS_SAMEORIGIN,
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.framing_policy_weak is False
    assert result.potential_clickjacking is False


def test_csp_present_alone_is_not_weak(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.CSP_PRESENT,
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.framing_policy_weak is False
    assert result.potential_clickjacking is False


def test_status_change_is_detected(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed
    assert result.response_changed


def test_content_change_is_detected(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.content_changed
    assert result.response_changed


def test_content_length_change_is_detected(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
    )

    assert result.content_length_changed
    assert result.response_changed


def test_header_change_is_detected(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.headers_changed
    assert result.response_changed


def test_weak_policy_without_response_change_is_indicator(
    validator,
):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "indicator"
    assert result.potential_clickjacking is False


def test_weak_policy_with_status_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status == "potential"
    assert result.potential_clickjacking


def test_weak_policy_with_content_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD,
        ),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.status == "potential"
    assert result.potential_clickjacking


def test_weak_policy_with_header_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.status == "potential"
    assert result.potential_clickjacking


def test_safe_policy_with_response_change_not_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.FRAME_ANCESTORS_NONE,
        ),
        baseline_status=200,
        candidate_status=403,
        content_changed=True,
    )

    assert result.potential_clickjacking is False


def test_analysis_detected_but_unrelated_indicator_is_not_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.CSP_PRESENT,
        ),
        baseline_status=200,
        candidate_status=403,
        content_changed=True,
    )

    assert result.potential_clickjacking is False


def test_evidence_contains_statuses(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert "Baseline status: 200." in result.evidence
    assert "Candidate status: 403." in result.evidence


def test_evidence_contains_policy_state(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert "Framing policy weak: True." in result.evidence


def test_invalid_analysis_is_rejected(validator):
    with pytest.raises(TypeError):
        validator.validate(
            object(),
            baseline_status=200,
            candidate_status=200,
        )


def test_potential_requires_analysis_detected(validator):
    analysis = ClickjackingAnalysis(
        detected=False,
        indicators=[
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                name="missing_x_frame_options",
            )
        ],
    )

    result = validator.validate(
        analysis,
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_clickjacking is False


def test_potential_requires_security_indicator(validator):
    result = validator.validate(
        make_analysis(
            ClickjackingIndicatorType.CSP_PRESENT,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is False
    assert result.potential_clickjacking is False
