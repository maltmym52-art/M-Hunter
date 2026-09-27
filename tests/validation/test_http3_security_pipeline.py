import pytest

from m_hunter.analyzers.http3_security import (
    HTTP3SecurityAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.http3_security_pipeline import (
    HTTP3SecurityPipeline,
)


@pytest.fixture
def pipeline():
    return HTTP3SecurityPipeline()


@pytest.fixture
def security_analysis():
    return HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error",
        quic_error="connection close",
    )


@pytest.fixture
def clean_analysis():
    return HTTP3SecurityAnalyzer().analyze(
        scheme="h3",
        alpn="h3",
        alt_svc='h3=":443"',
    )


def test_name(pipeline):
    assert pipeline.name == "http3_security_pipeline"


def test_no_potential_returns_no_findings(
    pipeline,
    security_analysis,
):
    validation, findings = pipeline.analyze(
        security_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=200,
    )

    assert validation.status == "detected"
    assert findings == []


def test_potential_returns_findings(
    pipeline,
    security_analysis,
):
    validation, findings = pipeline.analyze(
        security_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert validation.potential_http3_security_issue
    assert findings
    assert all(
        isinstance(item, Finding)
        for item in findings
    )


def test_content_change_returns_findings(
    pipeline,
    security_analysis,
):
    validation, findings = pipeline.analyze(
        security_analysis,
        target="https://example.com",
        baseline_content="before",
        candidate_content="after",
    )

    assert validation.potential_http3_security_issue
    assert findings


def test_content_length_change_returns_findings(
    pipeline,
    security_analysis,
):
    validation, findings = pipeline.analyze(
        security_analysis,
        target="https://example.com",
        baseline_content_length=100,
        candidate_content_length=200,
    )

    assert validation.potential_http3_security_issue
    assert findings


def test_header_change_returns_findings(
    pipeline,
    security_analysis,
):
    validation, findings = pipeline.analyze(
        security_analysis,
        target="https://example.com",
        baseline_headers={"server": "a"},
        candidate_headers={"server": "b"},
    )

    assert validation.potential_http3_security_issue
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
    assert not validation.potential_http3_security_issue
    assert findings == []


def test_endpoint_forwarded(
    pipeline,
    security_analysis,
):
    _, findings = pipeline.analyze(
        security_analysis,
        target="https://example.com",
        endpoint="/api",
        baseline_status=200,
        candidate_status=500,
    )

    assert findings
    assert all(
        finding.endpoint == "/api"
        for finding in findings
    )


def test_target_forwarded(
    pipeline,
    security_analysis,
):
    _, findings = pipeline.analyze(
        security_analysis,
        target="https://target.example",
        baseline_status=200,
        candidate_status=500,
    )

    assert findings
    assert all(
        finding.target == "https://target.example"
        for finding in findings
    )


def test_downgrade(
    pipeline,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        downgrade=True
    )

    validation, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=403,
    )

    assert validation.potential_http3_security_issue
    assert findings


def test_fallback(
    pipeline,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        fallback=True
    )

    validation, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=403,
    )

    assert validation.potential_http3_security_issue
    assert findings


def test_malformed_protocol(
    pipeline,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        malformed_protocol="invalid frame"
    )

    validation, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert validation.potential_http3_security_issue
    assert findings


def test_run_alias(
    pipeline,
    security_analysis,
):
    validation, findings = pipeline.run(
        security_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert validation.potential_http3_security_issue
    assert findings


def test_analysis_type_required(pipeline):
    with pytest.raises(TypeError):
        pipeline.analyze(
            object(),
            target="https://example.com",
        )


def test_findings_match_indicators(
    pipeline,
    security_analysis,
):
    _, findings = pipeline.analyze(
        security_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert len(findings) == len(
        security_analysis.indicators
    )


def test_finding_metadata_survives_pipeline(
    pipeline,
    security_analysis,
):
    _, findings = pipeline.analyze(
        security_analysis,
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


def test_multiple_response_changes(
    pipeline,
    security_analysis,
):
    validation, findings = pipeline.analyze(
        security_analysis,
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


def test_alt_svc_alone_is_not_reported(
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
    assert not validation.potential_http3_security_issue
    assert findings == []


def test_http3_error_finding(
    pipeline,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    _, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert any(
        "HTTP/3 error" in finding.title
        for finding in findings
    )


def test_quic_error_finding(
    pipeline,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        quic_error="connection close"
    )

    _, findings = pipeline.analyze(
        analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert any(
        "QUIC error" in finding.title
        for finding in findings
    )


def test_findings_status_open(
    pipeline,
    security_analysis,
):
    _, findings = pipeline.analyze(
        security_analysis,
        target="https://example.com",
        baseline_status=200,
        candidate_status=500,
    )

    assert findings
    assert all(
        finding.status == "open"
        for finding in findings
    )
