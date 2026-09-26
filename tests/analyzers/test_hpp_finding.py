import pytest

from m_hunter.analyzers.hpp import HPPAnalyzer
from m_hunter.analyzers.hpp_finding import HPPFindingAnalyzer
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return HPPAnalyzer()


@pytest.fixture
def finding_analyzer():
    return HPPFindingAnalyzer()


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


def test_duplicate_query_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/",
    )

    assert findings
    assert all(isinstance(finding, Finding) for finding in findings)
    assert any(
        finding.title == "Duplicate query parameter detected"
        for finding in findings
    )


def test_conflicting_value_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title == "Conflicting parameter values detected"
        for finding in findings
    )


def test_body_parameter_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        body="role=user&role=admin"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title == "Duplicate body parameter detected"
        for finding in findings
    )


def test_parameter_array_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"id": ["1", "2"]}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title == "Parameter array detected"
        for finding in findings
    )


@pytest.mark.parametrize(
    "url, expected_title",
    [
        (
            "https://example.com/?id=1&id=2",
            "Duplicate query parameter detected",
        ),
        (
            "https://example.com/?id=1&id=2",
            "Conflicting parameter values detected",
        ),
    ],
)
def test_expected_titles(
    analyzer,
    finding_analyzer,
    url,
    expected_title,
):
    analysis = analyzer.analyze(url=url)

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title == expected_title
        for finding in findings
    )


def test_findings_are_grouped_by_type(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2&id=3"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    duplicate_findings = [
        finding
        for finding in findings
        if finding.title == "Duplicate query parameter detected"
    ]

    assert len(duplicate_findings) == 1
    assert "appears 3 times" in duplicate_findings[0].evidence


def test_target_and_endpoint(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://target.example",
        endpoint="/search",
    )

    assert findings
    assert all(
        finding.target == "https://target.example"
        for finding in findings
    )
    assert all(
        finding.endpoint == "/search"
        for finding in findings
    )


def test_disclaimer_present(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert "do not by themselves prove" in findings[0].description


def test_remediation_present(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings[0].remediation
    assert findings[0].cwe == "CWE-235"
    assert findings[0].owasp == "A04:2021"


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
        url="https://example.com/?id=1&id=2"
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


def test_no_endpoint_is_allowed(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings
    assert all(finding.endpoint is None for finding in findings)


def test_multiple_types_generate_multiple_findings(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2",
        params={"role": ["user", "admin"]},
        body="token=a&token=b",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) >= 4
