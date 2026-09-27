import pytest

from m_hunter.analyzers.referrer_policy import (
    ReferrerPolicyAnalysis,
    ReferrerPolicyIndicator,
    ReferrerPolicyIndicatorType,
)
from m_hunter.validation.referrer_policy import (
    ReferrerPolicyValidationResult,
    ReferrerPolicyValidator,
)


def make_analysis(*types):
    indicators = tuple(
        ReferrerPolicyIndicator(
            type=indicator_type,
            evidence=f"evidence: {indicator_type.value}",
            value=indicator_type.value,
        )
        for indicator_type in types
    )

    unique_types = tuple(dict.fromkeys(types))

    return ReferrerPolicyAnalysis(
        detected=bool(indicators),
        indicators=indicators,
        count=len(indicators),
        types=unique_types,
        names=tuple(
            item.value for item in unique_types
        ),
    )


@pytest.fixture
def validator():
    return ReferrerPolicyValidator()


def test_result_is_frozen():
    result = ReferrerPolicyValidationResult(
        baseline_status=200,
        candidate_status=200,
        status_changed=False,
        content_changed=False,
        content_length_changed=False,
        headers_changed=False,
        response_changed=False,
        security_indicator_present=False,
        weak_policy_present=False,
        potential_referrer_policy_issue=False,
        status="clean",
        evidence="clean",
    )

    with pytest.raises(AttributeError):
        result.status = "potential"


def test_requires_analysis(validator):
    with pytest.raises(TypeError):
        validator.validate(
            object(),
            baseline_status=200,
            candidate_status=200,
        )


@pytest.mark.parametrize(
    "value",
    ["200", 200.0, None],
)
def test_requires_integer_statuses(
    validator,
    value,
):
    with pytest.raises(TypeError):
        validator.validate(
            make_analysis(
                ReferrerPolicyIndicatorType.UNSAFE_URL
            ),
            baseline_status=value,
            candidate_status=200,
        )


@pytest.mark.parametrize(
    "field",
    [
        "content_changed",
        "content_length_changed",
        "headers_changed",
    ],
)
def test_requires_boolean_response_flags(
    validator,
    field,
):
    kwargs = {
        "baseline_status": 200,
        "candidate_status": 200,
        "content_changed": False,
        "content_length_changed": False,
        "headers_changed": False,
    }

    kwargs[field] = "true"

    with pytest.raises(TypeError):
        validator.validate(
            make_analysis(
                ReferrerPolicyIndicatorType.UNSAFE_URL
            ),
            **kwargs,
        )


def test_clean_analysis(validator):
    result = validator.validate(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "clean"
    assert result.potential_referrer_policy_issue is False
    assert result.response_changed is False


def test_policy_present_is_detected_not_weak(validator):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.POLICY_PRESENT
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status == "detected"
    assert result.security_indicator_present is False
    assert result.weak_policy_present is False
    assert result.potential_referrer_policy_issue is False


@pytest.mark.parametrize(
    "indicator_type",
    [
        ReferrerPolicyIndicatorType.UNSAFE_URL,
        ReferrerPolicyIndicatorType.NO_REFERRER_WHEN_DOWNGRADE,
        ReferrerPolicyIndicatorType.INVALID_POLICY,
    ],
)
def test_security_indicators_are_detected(
    validator,
    indicator_type,
):
    result = validator.validate(
        make_analysis(indicator_type),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present is True
    assert result.weak_policy_present is True
    assert result.status == "indicator"
    assert result.potential_referrer_policy_issue is False


def test_status_change_creates_potential_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_referrer_policy_issue is True
    assert result.status == "potential"


def test_content_change_creates_potential_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.INVALID_POLICY
        ),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.response_changed is True
    assert result.potential_referrer_policy_issue is True


def test_content_length_change_creates_potential_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
    )

    assert result.response_changed is True
    assert result.potential_referrer_policy_issue is True


def test_header_change_creates_potential_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.NO_REFERRER_WHEN_DOWNGRADE
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.response_changed is True
    assert result.potential_referrer_policy_issue is True


def test_weak_policy_without_change_is_not_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "indicator"
    assert result.potential_referrer_policy_issue is False


def test_secure_policy_is_not_security_indicator(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType
            .STRICT_ORIGIN_WHEN_CROSS_ORIGIN
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is False
    assert result.potential_referrer_policy_issue is False


def test_same_origin_is_not_security_indicator(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.SAME_ORIGIN
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is False


def test_no_referrer_is_not_security_indicator(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.NO_REFERRER
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is False


def test_multiple_weak_indicators(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL,
            ReferrerPolicyIndicatorType.INVALID_POLICY,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is True
    assert result.potential_referrer_policy_issue is True


def test_evidence_contains_state(validator):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert "detected=True" in result.evidence
    assert "status_changed=True" in result.evidence
    assert "response_changed=True" in result.evidence


def test_status_values_are_preserved(validator):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        baseline_status=200,
        candidate_status=500,
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 500


def test_all_response_change_flags_combine(
    validator,
):
    result = validator.validate(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        baseline_status=200,
        candidate_status=201,
        content_changed=True,
        content_length_changed=True,
        headers_changed=True,
    )

    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is True
    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_referrer_policy_issue is True
