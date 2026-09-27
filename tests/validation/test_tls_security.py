import pytest

from m_hunter.analyzers.tls_security import (
    TLSSecurityAnalyzer,
)
from m_hunter.validation.tls_security import (
    TLSValidationAnalyzer,
    TLSValidationResult,
)


@pytest.fixture
def analyzer():
    return TLSValidationAnalyzer()


@pytest.fixture
def weak_analysis():
    return TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.0"
    )


@pytest.fixture
def clean_analysis():
    return TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )


def test_name(analyzer):
    assert analyzer.name == "tls_security_validation"


def test_result_type(analyzer, weak_analysis):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert isinstance(result, TLSValidationResult)


def test_status_changed(analyzer, weak_analysis):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=403,
    )

    assert result.status_changed


def test_content_changed(analyzer, weak_analysis):
    result = analyzer.validate(
        weak_analysis,
        baseline_content="before",
        candidate_content="after",
    )

    assert result.content_changed


def test_content_length_changed(analyzer, weak_analysis):
    result = analyzer.validate(
        weak_analysis,
        baseline_content_length=100,
        candidate_content_length=120,
    )

    assert result.content_length_changed


def test_headers_changed(analyzer, weak_analysis):
    result = analyzer.validate(
        weak_analysis,
        baseline_headers={"server": "a"},
        candidate_headers={"server": "b"},
    )

    assert result.headers_changed


def test_response_changed(analyzer, weak_analysis):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.response_changed


def test_security_indicator_present(analyzer, weak_analysis):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert result.security_indicator_present


def test_weak_configuration(analyzer, weak_analysis):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert result.weak_tls_configuration


def test_potential_issue_requires_response_change(
    analyzer,
    weak_analysis,
):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert not result.potential_tls_security_issue


def test_potential_issue_with_status_change(
    analyzer,
    weak_analysis,
):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_tls_security_issue


def test_potential_issue_with_content_change(
    analyzer,
    weak_analysis,
):
    result = analyzer.validate(
        weak_analysis,
        baseline_content="a",
        candidate_content="b",
    )

    assert result.potential_tls_security_issue


def test_potential_issue_with_length_change(
    analyzer,
    weak_analysis,
):
    result = analyzer.validate(
        weak_analysis,
        baseline_content_length=10,
        candidate_content_length=20,
    )

    assert result.potential_tls_security_issue


def test_potential_issue_with_header_change(
    analyzer,
    weak_analysis,
):
    result = analyzer.validate(
        weak_analysis,
        baseline_headers={"a": "1"},
        candidate_headers={"a": "2"},
    )

    assert result.potential_tls_security_issue


def test_status_potential(analyzer, weak_analysis):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.status == "potential"


def test_status_detected_without_change(
    analyzer,
    weak_analysis,
):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "detected"


def test_status_not_detected(analyzer, clean_analysis):
    result = analyzer.validate(
        clean_analysis,
        baseline_status=200,
        candidate_status=200,
    )

    assert result.status == "not_detected"


def test_evidence_contains_indicator(
    analyzer,
    weak_analysis,
):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=403,
    )

    assert "TLS indicator" in result.evidence


def test_evidence_contains_status_change(
    analyzer,
    weak_analysis,
):
    result = analyzer.validate(
        weak_analysis,
        baseline_status=200,
        candidate_status=403,
    )

    assert "200->403" in result.evidence


def test_analyze_alias(analyzer, weak_analysis):
    result = analyzer.analyze(
        weak_analysis,
        baseline_status=200,
        candidate_status=403,
    )

    assert result.potential_tls_security_issue


def test_analysis_type_required(analyzer):
    with pytest.raises(TypeError):
        analyzer.validate(
            object(),
            baseline_status=200,
            candidate_status=403,
        )


def test_expired_certificate_indicator(
    analyzer,
):
    analysis = TLSSecurityAnalyzer().analyze(
        certificate_expired=True
    )

    result = analyzer.validate(
        analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.potential_tls_security_issue


def test_hostname_mismatch_indicator(
    analyzer,
):
    analysis = TLSSecurityAnalyzer().analyze(
        hostname_mismatch=True
    )

    result = analyzer.validate(
        analysis,
        baseline_status=200,
        candidate_status=400,
    )

    assert result.potential_tls_security_issue


def test_weak_cipher_indicator(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        cipher="RC4"
    )

    result = analyzer.validate(
        analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.potential_tls_security_issue


def test_weak_signature_indicator(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        signature_algorithm="SHA1"
    )

    result = analyzer.validate(
        analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert result.potential_tls_security_issue


def test_clean_tls_has_no_security_indicator(
    analyzer,
):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )

    result = analyzer.validate(
        analysis,
        baseline_status=200,
        candidate_status=500,
    )

    assert not result.security_indicator_present
    assert not result.weak_tls_configuration
    assert not result.potential_tls_security_issue
