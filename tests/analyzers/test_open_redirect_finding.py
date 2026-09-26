import pytest

from m_hunter.analyzers.open_redirect import OpenRedirectAnalyzer
from m_hunter.analyzers.open_redirect_finding import (
    OpenRedirectFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return OpenRedirectAnalyzer()


@pytest.fixture
def finding_analyzer():
    return OpenRedirectFindingAnalyzer()


def test_empty_analysis_returns_no_findings(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze()

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


def test_external_url_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example/path"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/login",
    )

    assert findings
    assert all(isinstance(finding, Finding) for finding in findings)
    assert any(
        finding.title == "External redirect destination detected"
        for finding in findings
    )


def test_external_host_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"next": "https://other.example/path"},
        target_host="example.com",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title == "External redirect host detected"
        for finding in findings
    )


def test_user_controlled_destination_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"url": "https://other.example/path"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title
        == "User-controlled redirect destination detected"
        for finding in findings
    )


def test_redirect_parameter_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"redirect": "/dashboard"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title == "Redirect parameter detected"
        for finding in findings
    )


def test_location_header_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        headers={"Location": "https://other.example"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title == "Location header detected"
        for finding in findings
    )


def test_redirect_response_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        status_code=302
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title == "HTTP redirect response detected"
        for finding in findings
    )


def test_protocol_relative_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"next": "//other.example/path"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title
        == "Protocol-relative redirect destination detected"
        for finding in findings
    )


def test_findings_grouped_by_type(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={
            "redirect": "https://one.example",
            "next": "https://two.example",
        }
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    external_findings = [
        finding
        for finding in findings
        if finding.title == "External redirect destination detected"
    ]

    assert len(external_findings) == 1
    assert "https://one.example" in external_findings[0].evidence
    assert "https://two.example" in external_findings[0].evidence


def test_target_and_endpoint(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://target.example",
        endpoint="/redirect",
    )

    assert findings
    assert all(
        finding.target == "https://target.example"
        for finding in findings
    )
    assert all(
        finding.endpoint == "/redirect"
        for finding in findings
    )


def test_disclaimer_present(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert "does not prove" in findings[0].description


def test_remediation_present(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings[0].remediation
    assert findings[0].cwe == "CWE-601"
    assert findings[0].owasp == "A07:2021"


@pytest.mark.parametrize(
    "target",
    ["", "   "],
)
def test_empty_target_rejected(
    analyzer,
    finding_analyzer,
    target,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example"}
    )

    with pytest.raises(ValueError):
        finding_analyzer.analyze(
            analysis,
            target=target,
        )


def test_invalid_analysis_rejected(finding_analyzer):
    with pytest.raises(TypeError):
        finding_analyzer.analyze(
            object(),
            target="https://example.com",
        )


def test_no_endpoint_allowed(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings
    assert all(
        finding.endpoint is None
        for finding in findings
    )


def test_multiple_indicator_types(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example"},
        location="https://another.example",
        status_code=302,
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) >= 5
