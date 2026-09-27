import pytest

from m_hunter.analyzers.security_reporting import (
    SecurityReportingAnalysis,
    SecurityReportingIndicator,
    SecurityReportingIndicatorType,
)
from m_hunter.validation.security_reporting import (
    SecurityReportingValidationResult,
    SecurityReportingValidator,
)


def analysis(*types):
    return SecurityReportingAnalysis(
        detected=True,
        indicators=tuple(
            SecurityReportingIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_result_type():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert isinstance(
        result,
        SecurityReportingValidationResult,
    )


def test_valid_reporting_configuration():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "detected"
    assert not result.potential_security_reporting_issue


def test_invalid_reporting_endpoints_without_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present
    assert result.invalid_reporting_configuration
    assert not result.response_changed
    assert not result.potential_security_reporting_issue


def test_invalid_reporting_endpoints_with_status_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed
    assert result.response_changed
    assert result.potential_security_reporting_issue
    assert result.status == "potential"


def test_invalid_report_to_with_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=500,
    )

    assert result.security_indicator_present
    assert result.potential_security_reporting_issue


def test_multiple_reporting_endpoints_with_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.MULTIPLE_REPORTING_ENDPOINTS
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present
    assert result.potential_security_reporting_issue


def test_multiple_report_to_with_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.MULTIPLE_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert result.security_indicator_present
    assert result.potential_security_reporting_issue


def test_content_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_security_reporting_issue


def test_content_length_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
    )

    assert result.content_length_changed
    assert result.response_changed
    assert result.potential_security_reporting_issue


def test_headers_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_security_reporting_issue


def test_valid_endpoint_not_security_indicator():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present
    assert not result.potential_security_reporting_issue


def test_group_not_security_indicator():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.GROUP_PRESENT
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present


def test_csp_report_only_not_security_indicator():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.CSP_REPORT_ONLY
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present


def test_missing_reporting_endpoints_not_security_indicator():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present


def test_missing_report_to_not_security_indicator():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.REPORT_TO_MISSING
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert not result.security_indicator_present


def test_status_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=404,
    )

    assert result.status_changed
    assert result.response_changed


def test_no_status_change():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert not result.status_changed


def test_evidence_contains_statuses():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert "baseline_status=200" in result.evidence
    assert "candidate_status=403" in result.evidence


def test_evidence_contains_indicator():
    result = SecurityReportingValidator().validate(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
    )

    assert "invalid_report_to=invalid_report_to" in result.evidence


def test_all_security_indicators():
    for kind in SecurityReportingValidator.SECURITY_INDICATORS:
        result = SecurityReportingValidator().validate(
            analysis(kind),
            baseline_status=200,
            candidate_status=500,
        )

        assert result.security_indicator_present
        assert result.potential_security_reporting_issue


def test_analysis_type_validation():
    with pytest.raises(TypeError):
        SecurityReportingValidator().validate(
            object(),
            baseline_status=200,
            candidate_status=200,
        )


def test_baseline_status_validation():
    with pytest.raises(TypeError):
        SecurityReportingValidator().validate(
            analysis(
                SecurityReportingIndicatorType.ENDPOINT_PRESENT
            ),
            baseline_status="200",
            candidate_status=200,
        )


def test_candidate_status_validation():
    with pytest.raises(TypeError):
        SecurityReportingValidator().validate(
            analysis(
                SecurityReportingIndicatorType.ENDPOINT_PRESENT
            ),
            baseline_status=200,
            candidate_status="200",
        )


def test_boolean_validation():
    with pytest.raises(TypeError):
        SecurityReportingValidator().validate(
            analysis(
                SecurityReportingIndicatorType.ENDPOINT_PRESENT
            ),
            baseline_status=200,
            candidate_status=200,
            content_changed=1,
        )


def test_reusable_validator():
    validator = SecurityReportingValidator()

    first = validator.validate(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
    )

    second = validator.validate(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=200,
    )

    assert first.potential_security_reporting_issue
    assert not second.potential_security_reporting_issue
