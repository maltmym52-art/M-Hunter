import pytest

from m_hunter.analyzers.cors_advanced import (
    CORSAdvancedAnalysis,
    CORSAdvancedIndicator,
    CORSAdvancedIndicatorType,
)
from m_hunter.validation.cors_advanced import (
    CORSAdvancedValidationResult,
    CORSAdvancedValidator,
)


def make_analysis(*types):
    indicators = tuple(
        CORSAdvancedIndicator(
            type=indicator_type,
            evidence=f"evidence for {indicator_type.value}",
            value=indicator_type.value,
        )
        for indicator_type in types
    )

    return CORSAdvancedAnalysis(
        detected=bool(indicators),
        indicators=indicators,
        count=len(indicators),
        types=tuple(dict.fromkeys(types)),
        names=tuple(
            indicator_type.value
            for indicator_type in dict.fromkeys(types)
        ),
    )


@pytest.fixture
def validator():
    return CORSAdvancedValidator()


def test_validator_can_be_created(validator):
    assert isinstance(
        validator,
        CORSAdvancedValidator,
    )


def test_clean_analysis_is_clean(validator):
    result = validator.validate(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
    )

    assert isinstance(
        result,
        CORSAdvancedValidationResult,
    )
    assert result.status == "clean"
    assert result.potential_cors_issue is False
    assert result.security_indicator_present is False


def test_requires_correct_analysis_type(validator):
    with pytest.raises(TypeError):
        validator.validate(
            object(),
            baseline_status=200,
            candidate_status=200,
        )


def test_baseline_status_must_be_integer(validator):
    with pytest.raises(TypeError):
        validator.validate(
            make_analysis(),
            baseline_status="200",
            candidate_status=200,
        )


def test_candidate_status_must_be_integer(validator):
    with pytest.raises(TypeError):
        validator.validate(
            make_analysis(),
            baseline_status=200,
            candidate_status="200",
        )


def test_content_changed_must_be_boolean(validator):
    with pytest.raises(TypeError):
        validator.validate(
            make_analysis(),
            baseline_status=200,
            candidate_status=200,
            content_changed=1,
        )


def test_content_length_changed_must_be_boolean(
    validator,
):
    with pytest.raises(TypeError):
        validator.validate(
            make_analysis(),
            baseline_status=200,
            candidate_status=200,
            content_length_changed=1,
        )


def test_headers_changed_must_be_boolean(validator):
    with pytest.raises(TypeError):
        validator.validate(
            make_analysis(),
            baseline_status=200,
            candidate_status=200,
            headers_changed=1,
        )


def test_status_change_is_detected(validator):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed is True
    assert result.response_changed is True


def test_content_change_is_detected(validator):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
        ),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.content_changed is True
    assert result.response_changed is True


def test_content_length_change_is_detected(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
        ),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
    )

    assert result.content_length_changed is True
    assert result.response_changed is True


def test_header_change_is_detected(validator):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.headers_changed is True
    assert result.response_changed is True


@pytest.mark.parametrize(
    "indicator_type",
    [
        CORSAdvancedIndicatorType.REFLECTED_ARBITRARY_ORIGIN,
        CORSAdvancedIndicatorType.CREDENTIALED_ORIGIN_REFLECTION,
        CORSAdvancedIndicatorType.NULL_ORIGIN_REFLECTION,
        CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
        CORSAdvancedIndicatorType.PREFIX_TRUST,
        CORSAdvancedIndicatorType.SUFFIX_TRUST,
        CORSAdvancedIndicatorType.WILDCARD_CREDENTIALS,
    ],
)
def test_security_indicators_are_recognized(
    validator,
    indicator_type,
):
    result = validator.validate(
        make_analysis(indicator_type),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is True


def test_origin_reflection_is_recognized(validator):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.origin_reflection_present is True


@pytest.mark.parametrize(
    "indicator_type",
    [
        CORSAdvancedIndicatorType.CREDENTIALS_ENABLED,
        CORSAdvancedIndicatorType
        .CREDENTIALED_ORIGIN_REFLECTION,
        CORSAdvancedIndicatorType.WILDCARD_CREDENTIALS,
        CORSAdvancedIndicatorType.PREFLIGHT_CREDENTIALS,
    ],
)
def test_credential_indicators_are_recognized(
    validator,
    indicator_type,
):
    result = validator.validate(
        make_analysis(indicator_type),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.credentials_present is True


def test_arbitrary_origin_with_response_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_cors_issue is True
    assert result.status == "potential"


def test_credentialed_reflection_with_response_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType
            .CREDENTIALED_ORIGIN_REFLECTION,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_cors_issue is True


def test_null_origin_reflection_with_response_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType
            .NULL_ORIGIN_REFLECTION,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_cors_issue is True


def test_subdomain_trust_with_response_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_cors_issue is True


def test_prefix_trust_with_response_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.PREFIX_TRUST,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_cors_issue is True


def test_suffix_trust_with_response_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.SUFFIX_TRUST,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_cors_issue is True


def test_wildcard_credentials_with_response_change_is_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.WILDCARD_CREDENTIALS,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_cors_issue is True


def test_origin_reflection_can_be_potential_without_response_change(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.origin_reflection_present is True
    assert result.potential_cors_issue is False


def test_security_indicator_without_response_change_is_indicator(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present is True
    assert result.potential_cors_issue is False
    assert result.status == "indicator"


def test_credentials_alone_is_not_a_security_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.CREDENTIALS_ENABLED,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.credentials_present is True
    assert result.security_indicator_present is False
    assert result.potential_cors_issue is False
    assert result.status == "indicator"


def test_allow_origin_presence_is_not_a_security_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType
            .ACCESS_CONTROL_ALLOW_ORIGIN_PRESENT,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present is False
    assert result.potential_cors_issue is False


def test_preflight_methods_are_not_security_indicators(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.PREFLIGHT_METHODS,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is False
    assert result.potential_cors_issue is False


def test_multiple_security_indicators_are_supported(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
            CORSAdvancedIndicatorType
            .CREDENTIALED_ORIGIN_REFLECTION,
            CORSAdvancedIndicatorType
            .VARY_ORIGIN_MISSING,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is True
    assert result.origin_reflection_present is True
    assert result.credentials_present is True
    assert result.potential_cors_issue is True


def test_evidence_contains_all_response_flags(validator):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
        ),
        baseline_status=200,
        candidate_status=403,
        content_changed=True,
        content_length_changed=True,
        headers_changed=True,
    )

    assert "baseline_status=200" in result.evidence
    assert "candidate_status=403" in result.evidence
    assert "status_changed=True" in result.evidence
    assert "content_changed=True" in result.evidence
    assert "content_length_changed=True" in result.evidence
    assert "headers_changed=True" in result.evidence
    assert "response_changed=True" in result.evidence
    assert "security_indicator_present=True" in result.evidence


def test_clean_evidence(validator):
    result = validator.validate(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
    )

    assert "baseline_status=200" in result.evidence
    assert "candidate_status=200" in result.evidence
    assert "response_changed=False" in result.evidence


def test_result_preserves_statuses(validator):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
        ),
        baseline_status=201,
        candidate_status=204,
    )

    assert result.baseline_status == 201
    assert result.candidate_status == 204


def test_result_is_frozen():
    result = CORSAdvancedValidator().validate(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
    )

    with pytest.raises(AttributeError):
        result.status = "potential"


def test_indicator_status_when_detected_but_not_security_relevant(
    validator,
):
    result = validator.validate(
        make_analysis(
            CORSAdvancedIndicatorType.CREDENTIALS_ENABLED,
            CORSAdvancedIndicatorType
            .ACCESS_CONTROL_ALLOW_ORIGIN_PRESENT,
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "indicator"
    assert result.potential_cors_issue is False
