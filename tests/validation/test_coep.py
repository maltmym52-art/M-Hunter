from m_hunter.analyzers.coep import (
    COEPAnalysis,
    COEPIndicator,
    COEPIndicatorType,
)
from m_hunter.validation.coep import (
    COEPValidationResult,
    COEPValidator,
)


def analysis(*types):
    return COEPAnalysis(
        detected=True,
        indicators=tuple(
            COEPIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_result_type():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=200,
    )

    assert isinstance(result, COEPValidationResult)


def test_clean_policy():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "detected"
    assert not result.potential_coep_issue


def test_unsafe_none_without_change():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present
    assert result.weak_policy_present
    assert not result.response_changed
    assert not result.potential_coep_issue


def test_unsafe_none_with_status_change():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed
    assert result.response_changed
    assert result.potential_coep_issue
    assert result.status == "potential"


def test_invalid_policy_with_change():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.INVALID_POLICY),
        baseline_status=200,
        candidate_status=500,
    )

    assert result.security_indicator_present
    assert result.potential_coep_issue


def test_multiple_policies_with_change():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.MULTIPLE_POLICIES),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present
    assert result.potential_coep_issue


def test_content_change():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_coep_issue


def test_content_length_change():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
    )

    assert result.content_length_changed
    assert result.response_changed
    assert result.potential_coep_issue


def test_headers_change():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_coep_issue


def test_missing_policy_not_security_indicator():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.POLICY_MISSING),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_coep_issue


def test_require_corp_not_security_indicator():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_coep_issue


def test_credentialless_not_security_indicator():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.CREDENTIALLESS),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_coep_issue


def test_status_change():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=404,
    )

    assert result.status_changed
    assert result.response_changed


def test_no_status_change():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=200,
    )

    assert not result.status_changed


def test_evidence_contains_statuses():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
    )

    assert "baseline_status=200" in result.evidence
    assert "candidate_status=403" in result.evidence


def test_evidence_contains_indicator():
    result = COEPValidator().validate(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
    )

    assert "unsafe_none=unsafe_none" in result.evidence


def test_all_security_indicators():
    for kind in COEPValidator.SECURITY_INDICATORS:
        result = COEPValidator().validate(
            analysis(kind),
            baseline_status=200,
            candidate_status=500,
        )

        assert result.security_indicator_present
        assert result.potential_coep_issue


def test_analysis_type_validation():
    try:
        COEPValidator().validate(
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
        COEPValidator().validate(
            analysis(COEPIndicatorType.REQUIRE_CORP),
            baseline_status="200",
            candidate_status=200,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_candidate_status_validation():
    try:
        COEPValidator().validate(
            analysis(COEPIndicatorType.REQUIRE_CORP),
            baseline_status=200,
            candidate_status="200",
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_boolean_validation():
    try:
        COEPValidator().validate(
            analysis(COEPIndicatorType.REQUIRE_CORP),
            baseline_status=200,
            candidate_status=200,
            content_changed=1,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_reusable_validator():
    validator = COEPValidator()

    first = validator.validate(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
    )

    second = validator.validate(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=200,
    )

    assert first.potential_coep_issue
    assert not second.potential_coep_issue
