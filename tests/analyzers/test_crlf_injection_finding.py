import pytest

from m_hunter.analyzers.crlf_injection import (
    CRLFInjectionAnalysis,
    CRLFInjectionAnalyzer,
    CRLFInjectionIndicatorType,
)
from m_hunter.analyzers.crlf_injection_finding import (
    CRLFInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return CRLFInjectionAnalyzer()


@pytest.fixture
def finding_analyzer():
    return CRLFInjectionFindingAnalyzer()


def test_no_findings_when_no_indicator(finding_analyzer, analyzer):
    analysis = analyzer.analyze()

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert findings == []


def test_returns_findings_for_detected_analysis(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"next": "%0d%0aInjected: yes"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert findings
    assert all(isinstance(finding, Finding) for finding in findings)


def test_crlf_metadata(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        params={"next": "\r\n"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = findings[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-113"
    assert finding.owasp == "A03:2021"


def test_encoded_crlf_metadata(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert any(
        finding.title == "Encoded CRLF injection indicator"
        for finding in findings
    )


def test_header_injection_high(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        headers={"Location": "https://example.test"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "HTTP header injection indicator"
    )

    assert finding.severity == "High"
    assert finding.confidence == "Medium"


def test_location_header_metadata(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        location="https://example.test",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Location header indicator"
    )

    assert finding.severity == "Low"
    assert finding.confidence == "High"


def test_set_cookie_metadata(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        set_cookie="session=abc",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Set-Cookie header indicator"
    )

    assert finding.severity == "Low"
    assert finding.confidence == "High"


def test_response_header_metadata(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        response_headers={"X-Test": "value"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Response header indicator"
    )

    assert finding.severity == "Info"
    assert finding.confidence == "High"


def test_lf_metadata(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        params={"next": "%0a"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "LF injection indicator"
    )

    assert finding.cwe == "CWE-113"


def test_cr_metadata(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        params={"next": "%0d"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "CR injection indicator"
    )

    assert finding.cwe == "CWE-113"


def test_finding_target(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
        endpoint="/redirect",
    )

    assert findings[0].target == "https://example.test"
    assert findings[0].endpoint == "/redirect"


def test_evidence_contains_value(finding_analyzer, analyzer):
    value = "%0d%0aInjected: yes"

    analysis = analyzer.analyze(
        params={"next": value},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert any(value in finding.evidence for finding in findings)


def test_description_contains_validation_disclaimer(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert "does not prove" in findings[0].description


def test_remediation_present(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert findings[0].remediation


def test_findings_are_grouped_by_type(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        params={
            "a": "%0d%0a",
            "b": "%0a",
        }
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    titles = {finding.title for finding in findings}

    assert "CRLF injection indicator" in titles
    assert "LF injection indicator" in titles


def test_multiple_indicator_values_are_grouped(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        params={
            "a": "%0d%0aone",
            "b": "%0d%0atwo",
        }
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    crlf_finding = next(
        finding
        for finding in findings
        if finding.title == "CRLF injection indicator"
    )

    assert "one" in crlf_finding.evidence
    assert "two" in crlf_finding.evidence


def test_invalid_analysis_type_rejected(finding_analyzer):
    with pytest.raises(TypeError):
        finding_analyzer.analyze(
            "invalid",
            target="https://example.test",
        )


def test_empty_target_rejected(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    with pytest.raises(ValueError):
        finding_analyzer.analyze(
            analysis,
            target="",
        )


def test_non_string_endpoint_rejected(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    with pytest.raises(TypeError):
        finding_analyzer.analyze(
            analysis,
            target="https://example.test",
            endpoint=123,
        )


def test_all_indicator_types_have_metadata(finding_analyzer):
    assert set(finding_analyzer.METADATA) == set(
        CRLFInjectionIndicatorType
    )


def test_finding_has_correct_status_defaults(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )[0]

    assert finding.status == "open"


def test_finding_has_unique_ids(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        params={
            "a": "%0d%0a",
            "b": "%0a",
        }
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert len({finding.id for finding in findings}) == len(findings)
