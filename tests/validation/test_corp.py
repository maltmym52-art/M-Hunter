import pytest

from m_hunter.analyzers.corp import (
    CORPAnalysis,
    CORPIndicator,
    CORPIndicatorType,
)
from m_hunter.validation.corp import (
    CORPValidationResult,
    CORPValidator,
)


def analysis(*types):
    return CORPAnalysis(
        detected=True,
        indicators=tuple(
            CORPIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_result_type():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
    )

    assert isinstance(result, CORPValidationResult)


def test_clean_policy():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "detected"
    assert not result.potential_corp_issue


def test_cross_origin_without_change():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present
    assert result.weak_policy_present
    assert not result.response_changed
    assert not result.potential_corp_issue


def test_cross_origin_with_status_change():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed
    assert result.response_changed
    assert result.potential_corp_issue
    assert result.status == "potential"


def test_invalid_policy_with_change():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.INVALID_POLICY),
        baseline_status=200,
        candidate_status=500,
    )

    assert result.security_indicator_present
    assert result.potential_corp_issue


def test_multiple_policies_with_change():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.MULTIPLE_POLICIES),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present
    assert result.potential_corp_issue


def test_content_change():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_corp_issue


def test_content_length_change():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
    )

    assert result.content_length_changed
    assert result.response_changed
    assert result.potential_corp_issue


def test_headers_change():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_corp_issue


def test_missing_policy_not_security_indicator():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.POLICY_MISSING),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_corp_issue


def test_same_site_not_security_indicator():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.SAME_SITE),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_corp_issue


def test_same_origin_not_security_indicator():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_corp_issue


def test_status_change():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=404,
    )

    assert result.status_changed
    assert result.response_changed


def test_no_status_change():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
    )

    assert not result.status_changed


def test_evidence_contains_statuses():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
    )

    assert "baseline_status=200" in result.evidence
    assert "candidate_status=403" in result.evidence


def test_evidence_contains_indicator():
    result = CORPValidator().validate(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
    )

    assert "cross_origin=cross_origin" in result.evidence


def test_all_security_indicators():
    for kind in CORPValidator.SECURITY_INDICATORS:
        result = CORPValidator().validate(
            analysis(kind),
            baseline_status=200,
            candidate_status=500,
        )

        assert result.security_indicator_present
        assert result.potential_corp_issue


def test_analysis_type_validation():
    with pytest.raises(TypeError):
        CORPValidator().validate(
            object(),
            baseline_status=200,
            candidate_status=200,
        )


def test_baseline_status_validation():
    with pytest.raises(TypeError):
        CORPValidator().validate(
            analysis(CORPIndicatorType.SAME_ORIGIN),
            baseline_status="200",
            candidate_status=200,
        )


def test_candidate_status_validation():
    with pytest.raises(TypeError):
        CORPValidator().validate(
            analysis(CORPIndicatorType.SAME_ORIGIN),
            baseline_status=200,
            candidate_status="200",
        )


def test_boolean_validation():
    with pytest.raises(TypeError):
        CORPValidator().validate(
            analysis(CORPIndicatorType.SAME_ORIGIN),
            baseline_status=200,
            candidate_status=200,
            content_changed=1,
        )


def test_reusable_validator():
    validator = CORPValidator()

    first = validator.validate(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
    )

    second = validator.validate(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
    )

    assert first.potential_corp_issue
    assert not second.potential_corp_issue
