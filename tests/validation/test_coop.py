from m_hunter.analyzers.coop import (
    COOPAnalysis,
    COOPIndicator,
    COOPIndicatorType,
)
from m_hunter.validation.coop import (
    COOPValidationResult,
    COOPValidator,
)


def analysis(*types):
    return COOPAnalysis(
        detected=True,
        indicators=tuple(
            COOPIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_result_type():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
    )

    assert isinstance(result, COOPValidationResult)


def test_clean_policy():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "detected"
    assert not result.potential_coop_issue


def test_unsafe_none_without_change():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present
    assert result.weak_policy_present
    assert not result.response_changed
    assert not result.potential_coop_issue


def test_unsafe_none_with_status_change():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed
    assert result.response_changed
    assert result.potential_coop_issue
    assert result.status == "potential"


def test_invalid_policy_with_change():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.INVALID_POLICY),
        baseline_status=200,
        candidate_status=500,
    )

    assert result.security_indicator_present
    assert result.potential_coop_issue


def test_multiple_policies_with_change():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.MULTIPLE_POLICIES),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present
    assert result.potential_coop_issue


def test_content_change():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_coop_issue


def test_content_length_change():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
    )

    assert result.content_length_changed
    assert result.response_changed
    assert result.potential_coop_issue


def test_headers_change():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_coop_issue


def test_missing_policy_not_security_indicator():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.POLICY_MISSING),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_coop_issue


def test_same_origin_not_security_indicator():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_coop_issue


def test_same_origin_allow_popups_not_security_indicator():
    result = COOPValidator().validate(
        analysis(
            COOPIndicatorType.SAME_ORIGIN_ALLOW_POPUPS
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_coop_issue


def test_status_change():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=404,
    )

    assert result.status_changed
    assert result.response_changed


def test_no_status_change():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
    )

    assert not result.status_changed


def test_evidence_contains_statuses():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
    )

    assert "baseline_status=200" in result.evidence
    assert "candidate_status=403" in result.evidence


def test_evidence_contains_indicator():
    result = COOPValidator().validate(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
    )

    assert "unsafe_none=unsafe_none" in result.evidence


def test_all_security_indicators():
    for kind in COOPValidator.SECURITY_INDICATORS:
        result = COOPValidator().validate(
            analysis(kind),
            baseline_status=200,
            candidate_status=500,
        )

        assert result.security_indicator_present
        assert result.potential_coop_issue


def test_analysis_type_validation():
    try:
        COOPValidator().validate(
            object(),
            baseline_status=200,
            candidate_status=200,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_baseline_status_validation():
    try:
        COOPValidator().validate(
            analysis(COOPIndicatorType.SAME_ORIGIN),
            baseline_status="200",
            candidate_status=200,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_candidate_status_validation():
    try:
        COOPValidator().validate(
            analysis(COOPIndicatorType.SAME_ORIGIN),
            baseline_status=200,
            candidate_status="200",
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_boolean_validation():
    try:
        COOPValidator().validate(
            analysis(COOPIndicatorType.SAME_ORIGIN),
            baseline_status=200,
            candidate_status=200,
            content_changed=1,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_reusable_validator():
    validator = COOPValidator()

    first = validator.validate(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
    )

    second = validator.validate(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
    )

    assert first.potential_coop_issue
    assert not second.potential_coop_issue
