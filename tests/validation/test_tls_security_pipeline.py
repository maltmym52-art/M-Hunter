import pytest

from m_hunter.analyzers.tls_security import (
    TLSSecurityAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.tls_security_pipeline import (
    TLSSecurityPipeline,
)


@pytest.fixture
def pipeline():
    return TLSSecurityPipeline()


@pytest.fixture
def weak_analysis():
    return TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.0",
        certificate_expired=True,
        cipher="RC4",
    )


@pytest.fixture
def clean_analysis():
    return TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )


def test_name(pipeline):
    assert pipeline.name == "tls_security_pipeline"


def test_no_potential_issue_returns_no_findings(
    pipeline,
    weak_analysis,
):
    validation, findings = pipeline.analyze(
        weak_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=200,
    )

    assert validation.status == "detected"
    assert findings == []


def test_potential_issue_returns_findings(
    pipeline,
    weak_analysis,
):
    validation, findings = pipeline.analyze(
        weak_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert validation.potential_tls_security_issue
    assert findings
    assert all(
        isinstance(item, Finding)
        for item in findings
    )


def test_content_change_accepts_findings(
    pipeline,
    weak_analysis,
):
    validation, findings = pipeline.analyze(
        weak_analysis,
        target="https://example.com",
        baseline_content="before",
        candidate_content="after",
    )

    assert validation.potential_tls_security_issue
    assert findings


def test_content_length_change_accepts_findings(
    pipeline,
    weak_analysis,
):
    validation, findings = pipeline.analyze(
        weak_analysis,
        target="https://example.com",
        baseline_content_length=100,
        candidate_content_length=200,
    )

    assert validation.potential_tls_security_issue
    assert findings


def test_header_change_accepts_findings(
    pipeline,
    weak_analysis,
):
    validation, findings = pipeline.analyze(
        weak_analysis,
        target="https://example.com",
        baseline_headers={"server": "a"},
        candidate_headers={"server": "b"},
    )

    assert validation.potential_tls_security_issue
    assert findings


def test_clean_analysis_returns_no_findings(
    pipeline,
    clean_analysis,
):
    validation, findings = pipeline.analyze(
        clean_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert not validation.security_indicator_present
    assert not validation.potential_tls_security_issue
    assert findings == []


def test_endpoint_is_forwarded(
    pipeline,
    weak_analysis,
):
    _, findings = pipeline.analyze(
        weak_analysis,
        target="https://example.com",
        endpoint="/login",
        baseline_status=200,
        candidate_status=403,
    )

    assert findings
    assert all(
        finding.endpoint == "/login"
        for finding in findings
    )


def test_target_is_forwarded(
    pipeline,
    weak_analysis,
):
    _, findings = pipeline.analyze(
        weak_analysis,
        target="https://target.example",
        baseline_status=200,
        candidate_status=403,
    )

    assert findings
    assert all(
        finding.target == "https://target.example"
        for finding in findings
    )


def test_expired_certificate(
    pipeline,
):
    analysis = TLSSecurityAnalyzer().analyze(
        certificate_expired=True
    )

    validation, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert validation.potential_tls_security_issue
    assert any(
        "expired" in finding.title.lower()
        for finding in findings
    )


def test_hostname_mismatch(
    pipeline,
):
    analysis = TLSSecurityAnalyzer().analyze(
        hostname_mismatch=True
    )

    validation, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert validation.potential_tls_security_issue
    assert findings


def test_weak_key_exchange(
    pipeline,
):
    analysis = TLSSecurityAnalyzer().analyze(
        key_exchange="DH_anon"
    )

    validation, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert validation.potential_tls_security_issue
    assert findings


def test_weak_signature(
    pipeline,
):
    analysis = TLSSecurityAnalyzer().analyze(
        signature_algorithm="SHA1"
    )

    validation, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert validation.potential_tls_security_issue
    assert findings


def test_run_alias(
    pipeline,
    weak_analysis,
):
    validation, findings = pipeline.run(
        weak_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert validation.potential_tls_security_issue
    assert findings


def test_analysis_type_required(pipeline):
    with pytest.raises(TypeError):
        pipeline.analyze(
            object(),
            target="https://example.com",
        )


def test_findings_match_analysis_indicators(
    pipeline,
    weak_analysis,
):
    _, findings = pipeline.analyze(
        weak_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert len(findings) == len(
        weak_analysis.indicators
    )


def test_finding_metadata_survives_pipeline(
    pipeline,
    weak_analysis,
):
    _, findings = pipeline.analyze(
        weak_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    for finding in findings:
        assert finding.severity
        assert finding.confidence
        assert finding.cwe
        assert finding.owasp
        assert finding.evidence
        assert finding.remediation


def test_multiple_changes(
    pipeline,
    weak_analysis,
):
    validation, findings = pipeline.analyze(
        weak_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
        baseline_content="a",
        candidate_content="b",
        baseline_content_length=1,
        candidate_content_length=2,
        baseline_headers={"a": "1"},
        candidate_headers={"a": "2"},
    )

    assert validation.status_changed
    assert validation.content_changed
    assert validation.content_length_changed
    assert validation.headers_changed
    assert validation.response_changed
    assert findings


def test_hsts_only_is_not_security_issue(
    pipeline,
):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3",
        hsts_present=True,
    )

    validation, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert not validation.security_indicator_present
    assert not validation.potential_tls_security_issue
    assert findings == []
