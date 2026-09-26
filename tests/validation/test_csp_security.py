import pytest

from m_hunter.analyzers.csp_security import (
    CSPAnalysis,
    CSPIndicator,
    CSPIndicatorType,
)
from m_hunter.validation.csp_security import (
    CSPValidationResult,
    CSPValidator,
)


def make_analysis(*types):
    indicators = tuple(
        CSPIndicator(
            type=indicator_type,
            evidence=f"evidence: {indicator_type.value}",
            value=indicator_type.value,
        )
        for indicator_type in types
    )

    unique_types = tuple(dict.fromkeys(types))

    return CSPAnalysis(
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
    return CSPValidator()


def test_result_is_frozen():
    result = CSPValidationResult(
        baseline_status=200,
        candidate_status=200,
        status_changed=False,
        content_changed=False,
        content_length_changed=False,
        headers_changed=False,
        response_changed=False,
        security_indicator_present=False,
        dangerous_policy_present=False,
        potential_csp_issue=False,
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
                CSPIndicatorType.UNSAFE_INLINE
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
                CSPIndicatorType.UNSAFE_INLINE
            ),
            **kwargs,
        )


def test_clean_analysis_is_clean(validator):
    result = validator.validate(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "clean"
    assert result.potential_csp_issue is False
    assert result.response_changed is False


def test_csp_presence_is_detected_not_dangerous(validator):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.CSP_PRESENT
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status == "detected"
    assert result.security_indicator_present is False
    assert result.potential_csp_issue is False


@pytest.mark.parametrize(
    "indicator_type",
    [
        CSPIndicatorType.WILDCARD_SOURCE,
        CSPIndicatorType.UNSAFE_INLINE,
        CSPIndicatorType.UNSAFE_EVAL,
        CSPIndicatorType.UNSAFE_HASHES,
        CSPIndicatorType.DATA_SOURCE,
        CSPIndicatorType.BLOB_SOURCE,
        CSPIndicatorType.FRAME_ANCESTORS_WILDCARD,
        CSPIndicatorType.SCRIPT_SRC_WILDCARD,
        CSPIndicatorType.CONNECT_SRC_WILDCARD,
        CSPIndicatorType.IMG_SRC_WILDCARD,
        CSPIndicatorType.STYLE_SRC_WILDCARD,
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
    assert result.dangerous_policy_present is True
    assert result.status == "indicator"
    assert result.potential_csp_issue is False


def test_status_change_creates_potential_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_csp_issue is True
    assert result.status == "potential"


def test_content_change_creates_potential_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.UNSAFE_EVAL
        ),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.response_changed is True
    assert result.potential_csp_issue is True


def test_content_length_change_creates_potential_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.DATA_SOURCE
        ),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
    )

    assert result.response_changed is True
    assert result.potential_csp_issue is True


def test_header_change_creates_potential_issue(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.BLOB_SOURCE
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.response_changed is True
    assert result.potential_csp_issue is True


def test_security_indicator_without_change_is_not_potential(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "indicator"
    assert result.potential_csp_issue is False


def test_missing_directive_alone_is_not_security_indicator(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.SCRIPT_SRC_MISSING,
            CSPIndicatorType.DEFAULT_SRC_MISSING,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is False
    assert result.potential_csp_issue is False


def test_secure_policy_indicators_are_not_dangerous(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.CSP_PRESENT,
            CSPIndicatorType.OBJECT_NONE,
            CSPIndicatorType.BASE_NONE,
            CSPIndicatorType.FRAME_ANCESTORS_NONE,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is False
    assert result.potential_csp_issue is False


def test_multiple_security_indicators_are_detected(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE,
            CSPIndicatorType.UNSAFE_EVAL,
            CSPIndicatorType.WILDCARD_SOURCE,
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present is True
    assert result.potential_csp_issue is True


def test_evidence_contains_validation_state(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert "detected=True" in result.evidence
    assert "status_changed=True" in result.evidence
    assert "response_changed=True" in result.evidence


def test_baseline_and_candidate_status_are_preserved(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=500,
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 500


def test_response_change_combines_all_flags(
    validator,
):
    result = validator.validate(
        make_analysis(
            CSPIndicatorType.UNSAFE_EVAL
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
    assert result.potential_csp_issue is True
