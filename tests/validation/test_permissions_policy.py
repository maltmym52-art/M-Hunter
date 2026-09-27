from m_hunter.analyzers.permissions_policy import (
    PermissionsPolicyAnalysis,
    PermissionsPolicyIndicator,
    PermissionsPolicyIndicatorType,
)
from m_hunter.validation.permissions_policy import (
    PermissionsPolicyValidationResult,
    PermissionsPolicyValidator,
)


def analysis(*types):
    return PermissionsPolicyAnalysis(
        detected=True,
        indicators=tuple(
            PermissionsPolicyIndicator(
                type=kind,
                name=kind.value,
                value="camera *"
                if kind
                == PermissionsPolicyIndicatorType.WILDCARD_SOURCE
                else None,
            )
            for kind in types
        ),
    )


def test_result_type():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.POLICY_PRESENT),
        baseline_status=200,
        candidate_status=200,
    )

    assert isinstance(result, PermissionsPolicyValidationResult)


def test_clean_policy():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.POLICY_PRESENT),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "detected"
    assert not result.potential_permissions_policy_issue


def test_wildcard_without_change():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present
    assert result.weak_policy_present
    assert not result.response_changed
    assert not result.potential_permissions_policy_issue


def test_wildcard_with_status_change():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed
    assert result.response_changed
    assert result.potential_permissions_policy_issue
    assert result.status == "potential"


def test_content_change():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_permissions_policy_issue


def test_content_length_change():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
    )

    assert result.content_length_changed
    assert result.response_changed
    assert result.potential_permissions_policy_issue


def test_headers_change():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_permissions_policy_issue


def test_invalid_directive():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.INVALID_DIRECTIVE),
        baseline_status=200,
        candidate_status=500,
    )

    assert result.security_indicator_present
    assert result.potential_permissions_policy_issue


def test_invalid_source():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.INVALID_SOURCE),
        baseline_status=200,
        candidate_status=500,
    )

    assert result.security_indicator_present
    assert result.potential_permissions_policy_issue


def test_missing_policy_is_not_security_indicator():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.POLICY_MISSING),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_permissions_policy_issue


def test_self_source_is_not_security_indicator():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.SELF_SOURCE),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_permissions_policy_issue


def test_origin_source_is_not_security_indicator():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.ORIGIN_SOURCE),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_permissions_policy_issue


def test_feature_context_is_not_security_indicator():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.CAMERA),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_permissions_policy_issue


def test_status_change():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.POLICY_PRESENT),
        baseline_status=200,
        candidate_status=404,
    )

    assert result.status_changed
    assert result.response_changed


def test_no_status_change():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.POLICY_PRESENT),
        baseline_status=200,
        candidate_status=200,
    )

    assert not result.status_changed


def test_evidence_contains_statuses():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
    )

    assert "baseline_status=200" in result.evidence
    assert "candidate_status=403" in result.evidence


def test_evidence_contains_indicator():
    result = PermissionsPolicyValidator().validate(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
    )

    assert "wildcard_source=camera *" in result.evidence


def test_all_security_indicators():
    for kind in PermissionsPolicyValidator.SECURITY_INDICATORS:
        result = PermissionsPolicyValidator().validate(
            analysis(kind),
            baseline_status=200,
            candidate_status=500,
        )

        assert result.security_indicator_present
        assert result.potential_permissions_policy_issue


def test_analysis_type_validation():
    try:
        PermissionsPolicyValidator().validate(
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
        PermissionsPolicyValidator().validate(
            analysis(PermissionsPolicyIndicatorType.CAMERA),
            baseline_status="200",
            candidate_status=200,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_candidate_status_validation():
    try:
        PermissionsPolicyValidator().validate(
            analysis(PermissionsPolicyIndicatorType.CAMERA),
            baseline_status=200,
            candidate_status="200",
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_boolean_validation():
    try:
        PermissionsPolicyValidator().validate(
            analysis(PermissionsPolicyIndicatorType.CAMERA),
            baseline_status=200,
            candidate_status=200,
            content_changed=1,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_reusable_validator():
    validator = PermissionsPolicyValidator()

    first = validator.validate(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
    )

    second = validator.validate(
        analysis(PermissionsPolicyIndicatorType.POLICY_PRESENT),
        baseline_status=200,
        candidate_status=200,
    )

    assert first.potential_permissions_policy_issue
    assert not second.potential_permissions_policy_issue
