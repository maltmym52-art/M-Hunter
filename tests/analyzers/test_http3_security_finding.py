import pytest

from m_hunter.analyzers.http3_security import (
    HTTP3IndicatorType,
    HTTP3SecurityAnalyzer,
)
from m_hunter.analyzers.http3_security_finding import (
    HTTP3SecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return HTTP3SecurityFindingAnalyzer()


def test_name(analyzer):
    assert analyzer.name == "http3_security_finding"


def test_empty_analysis(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze()

    assert analyzer.analyze(
        analysis,
        target="https://example.com",
    ) == []


def test_returns_findings(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings
    assert all(
        isinstance(item, Finding)
        for item in findings
    )


def test_quic_error_metadata(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        quic_error="connection close"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-400"
    assert finding.owasp == "A05:2021"


def test_http3_error_metadata(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-400"


def test_downgrade_metadata(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        downgrade=True
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-757"


def test_fallback_metadata(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        fallback=True
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.cwe == "CWE-757"


def test_malformed_protocol_metadata(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        malformed_protocol="invalid frame"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-20"


def test_info_protocol_indicators(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        scheme="h3",
        alpn="h3",
        protocol="HTTP/3 over QUIC",
        alt_svc='h3=":443"',
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings
    assert all(
        finding.severity == "Info"
        for finding in findings
    )


def test_indicator_value_in_evidence(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        quic_error="connection close"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert "connection close" in finding.evidence


def test_indicator_value_in_description(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert "stream error" in finding.description


def test_endpoint_forwarded(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/api",
    )[0]

    assert finding.endpoint == "/api"


def test_target_forwarded(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://target.example",
    )[0]

    assert finding.target == "https://target.example"


def test_status_open(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.status == "open"


def test_required_metadata(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.title
    assert finding.description
    assert finding.evidence
    assert finding.remediation
    assert finding.severity
    assert finding.confidence
    assert finding.cwe
    assert finding.owasp


def test_analysis_type_required(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            object(),
            target="https://example.com",
        )


def test_target_required(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    with pytest.raises(ValueError):
        analyzer.analyze(
            analysis,
            target="",
        )


def test_create_findings_alias(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        http3_error="stream error"
    )

    findings = analyzer.create_findings(
        analysis,
        target="https://example.com",
    )

    assert findings


def test_metadata_coverage(analyzer):
    analysis = HTTP3SecurityAnalyzer().analyze(
        scheme="h3",
        alpn="h3",
        protocol="HTTP/3 over QUIC",
        alt_svc='h3=":443"',
        authority="example.com",
        pseudo_headers=[":method"],
        quic_error="error",
        http3_error="error",
        downgrade=True,
        fallback=True,
        malformed_protocol="bad",
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) == len(
        analysis.indicators
    )

    for indicator in analysis.indicators:
        assert indicator.type in analyzer.FINDING_METADATA


def test_all_security_findings_have_valid_severity(
    analyzer,
):
    analysis = HTTP3SecurityAnalyzer().analyze(
        quic_error="error",
        http3_error="error",
        downgrade=True,
        fallback=True,
        malformed_protocol="bad",
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert all(
        finding.severity in {
            "Info",
            "Low",
            "Medium",
            "High",
            "Critical",
        }
        for finding in findings
    )


def test_specific_metadata_keys(analyzer):
    assert (
        HTTP3IndicatorType.QUIC_ERROR
        in analyzer.FINDING_METADATA
    )
    assert (
        HTTP3IndicatorType.HTTP3_ERROR
        in analyzer.FINDING_METADATA
    )
    assert (
        HTTP3IndicatorType.DOWNGRADE_INDICATOR
        in analyzer.FINDING_METADATA
    )
