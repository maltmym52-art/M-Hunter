import pytest

from m_hunter.analyzers.tls_security import (
    TLSSecurityAnalyzer,
    TLSIndicatorType,
)
from m_hunter.analyzers.tls_security_finding import (
    TLSSecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return TLSSecurityFindingAnalyzer()


def test_name(analyzer):
    assert analyzer.name == "tls_security_finding"


def test_empty_analysis(analyzer):
    analysis = TLSSecurityAnalyzer().analyze()

    assert analyzer.analyze(
        analysis,
        target="https://example.com",
    ) == []


def test_returns_findings(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.0"
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings
    assert all(isinstance(item, Finding) for item in findings)


def test_tls10_metadata(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.0"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[2]

    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-326"
    assert finding.owasp == "A02:2021"


def test_sslv2_critical(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="SSLv2"
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    finding = next(
        item
        for item in findings
        if "SSLv2" in item.title
    )

    assert finding.severity == "Critical"


def test_sslv3_high(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="SSLv3"
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    finding = next(
        item
        for item in findings
        if "SSLv3" in item.title
    )

    assert finding.severity == "High"


def test_expired_certificate(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        certificate_expired=True
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.cwe == "CWE-295"


def test_hostname_mismatch(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        hostname_mismatch=True
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.cwe == "CWE-297"


def test_weak_cipher(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        cipher="RC4"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert "RC4" in finding.evidence


def test_weak_key_exchange(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        key_exchange="DH_anon"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert "DH_anon" in finding.evidence


def test_weak_signature(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        signature_algorithm="sha1WithRSAEncryption"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert "sha1WithRSAEncryption" in finding.evidence


def test_hsts_info(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        hsts_present=True
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_tls13_info(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    finding = next(
        item
        for item in findings
        if "TLS 1.3" in item.title
    )

    assert finding.severity == "Info"


def test_endpoint(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        certificate_expired=True
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/login",
    )[0]

    assert finding.endpoint == "/login"


def test_target_required(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        certificate_expired=True
    )

    with pytest.raises(ValueError):
        analyzer.analyze(
            analysis,
            target="",
        )


def test_analysis_type_required(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            object(),
            target="https://example.com",
        )


def test_create_findings_alias(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        certificate_expired=True
    )

    assert analyzer.create_findings(
        analysis,
        target="https://example.com",
    )


def test_metadata_coverage(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3",
        certificate_present=True,
        certificate_expired=True,
        self_signed=True,
        hostname_mismatch=True,
        invalid_chain=True,
        cipher="RC4",
        key_exchange="DH_anon",
        signature_algorithm="SHA1",
        certificate_transparency=True,
        hsts_present=True,
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) == len(analysis.indicators)

    for indicator in analysis.indicators:
        assert indicator.type in analyzer.FINDING_METADATA


def test_all_findings_have_core_metadata(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.0",
        certificate_expired=True,
        signature_algorithm="SHA1",
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    for finding in findings:
        assert finding.title
        assert finding.severity
        assert finding.confidence
        assert finding.target
        assert finding.description
        assert finding.evidence
        assert finding.remediation


def test_value_is_in_description(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.0"
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[1]

    assert "TLSv1.0" in finding.description


def test_finding_status_open(analyzer):
    analysis = TLSSecurityAnalyzer().analyze(
        certificate_expired=True
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.status == "open"


def test_metadata_indicator_enum(analyzer):
    assert (
        TLSIndicatorType.EXPIRED_CERTIFICATE
        in analyzer.FINDING_METADATA
    )
