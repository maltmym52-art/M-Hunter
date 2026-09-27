import pytest

from m_hunter.analyzers.http3_security import (
    HTTP3SecurityAnalyzer,
)
from m_hunter.validation.http3_security import (
    HTTP3ValidationAnalyzer,
    HTTP3ValidationResult,
)


@pytest.fixture
def validator():
    return HTTP3ValidationAnalyzer()


@pytest.fixture
def security_analysis():
    return HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )


@pytest.fixture
def clean_analysis():
    return HTTP3SecurityAnalyzer().analyze(
        scheme="h3",
        alpn="h3",
        alt_svc='h3=":443"',
    )


def test_name(validator):
    assert validator.name == "http3_security_validation"


def test_result_type(validator, security_analysis):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert isinstance(
        result,
        HTTP3ValidationResult,
    )


def test_status_changed(validator, security_analysis):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.status_changed


def test_content_changed(validator, security_analysis):
    result = validator.validate(
        security_analysis,
        baseline_content="before",
        candidate_content="after",
    )

    assert result.content_changed


def test_content_length_changed(
    validator,
    security_analysis,
):
    result = validator.validate(
        security_analysis,
        baseline_content_length=100,
        candidate_content_length=200,
    )

    assert result.content_length_changed


def test_headers_changed(validator, security_analysis):
    result = validator.validate(
        security_analysis,
        baseline_headers={"server": "a"},
        candidate_headers={"server": "b"},
    )

    assert result.headers_changed


def test_response_changed(validator, security_analysis):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.response_changed


def test_security_indicator_present(
    validator,
    security_analysis,
):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present


def test_protocol_security_issue(
    validator,
    security_analysis,
):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert result.protocol_security_issue


def test_potential_requires_response_change(
    validator,
    security_analysis,
):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert not result.potential_http3_security_issue


def test_status_detected_without_change(
    validator,
    security_analysis,
):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "detected"


def test_status_potential_with_change(
    validator,
    security_analysis,
):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.status == "potential"
    assert result.potential_http3_security_issue


def test_clean_analysis_not_detected(
    validator,
    clean_analysis,
):
    result = validator.validate(
        clean_analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert not result.security_indicator_present
    assert not result.protocol_security_issue
    assert not result.potential_http3_security_issue
    assert result.status == "not_detected"


def test_downgrade_indicator(
    validator,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        downgrade=True
    )

    result = validator.validate(
        analysis,
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_http3_security_issue


def test_fallback_indicator(
    validator,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        fallback=True
    )

    result = validator.validate(
        analysis,
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_http3_security_issue


def test_malformed_protocol_indicator(
    validator,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        malformed_protocol="invalid frame"
    )

    result = validator.validate(
        analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.potential_http3_security_issue


def test_quic_error_indicator(
    validator,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        quic_error="connection close"
    )

    result = validator.validate(
        analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.potential_http3_security_issue


def test_evidence_indicator(
    validator,
    security_analysis,
):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert "HTTP/3 indicator" in result.evidence


def test_evidence_status(
    validator,
    security_analysis,
):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert "200->500" in result.evidence


def test_analyze_alias(
    validator,
    security_analysis,
):
    result = validator.analyze(
        security_analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.potential_http3_security_issue


def test_analysis_type_required(validator):
    with pytest.raises(TypeError):
        validator.validate(
            object(),
            baseline_status=200,
            candidate_status=500,
        )


def test_no_change_no_potential_for_http3_error(
    validator,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    result = validator.validate(
        analysis,
        baseline_status=200,
        candidate_status=200,
        baseline_content="same",
        candidate_content="same",
        baseline_content_length=4,
        candidate_content_length=4,
        baseline_headers={"a": "1"},
        candidate_headers={"a": "1"},
    )

    assert result.response_changed is False
    assert result.potential_http3_security_issue is False


def test_multiple_response_changes(
    validator,
    security_analysis,
):
    result = validator.validate(
        security_analysis,
        baseline_status=200,
        candidate_status=500,
        baseline_content="a",
        candidate_content="b",
        baseline_content_length=1,
        candidate_content_length=2,
        baseline_headers={"a": "1"},
        candidate_headers={"a": "2"},
    )

    assert result.status_changed
    assert result.content_changed
    assert result.content_length_changed
    assert result.headers_changed
    assert result.response_changed
    assert result.potential_http3_security_issue


def test_alt_svc_alone_is_not_security_issue(
    validator,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        alt_svc='h3=":443"'
    )

    result = validator.validate(
        analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert not result.security_indicator_present
    assert not result.protocol_security_issue
    assert not result.potential_http3_security_issue
