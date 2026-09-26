import pytest

from m_hunter.analyzers.race_condition import RaceConditionAnalyzer
from m_hunter.analyzers.race_condition_finding import (
    RaceConditionFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return RaceConditionAnalyzer()


@pytest.fixture
def finding_analyzer():
    return RaceConditionFindingAnalyzer()


def test_no_findings_for_empty_analysis(analyzer, finding_analyzer):
    analysis = analyzer.analyze()
    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )
    assert findings == []


def test_finding_created(analyzer, finding_analyzer):
    analysis = analyzer.analyze(
        concurrent_requests=5,
        duplicate_operation=True,
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/api/transfer",
    )

    assert findings
    assert all(isinstance(finding, Finding) for finding in findings)
    assert all(finding.target == "https://example.com" for finding in findings)
    assert all(finding.endpoint == "/api/transfer" for finding in findings)


def test_findings_group_same_indicator(analyzer, finding_analyzer):
    analysis = analyzer.analyze(
        url="/api/payment",
        params={"payment": "true"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    sensitive_findings = [
        finding
        for finding in findings
        if finding.title == "Sensitive operation involved"
    ]

    assert len(sensitive_findings) == 1
    assert "Sensitive operation marker detected" in sensitive_findings[0].evidence


@pytest.mark.parametrize(
    "kwargs, expected_title",
    [
        (
            {"duplicate_operation": True},
            "Duplicate operation accepted",
        ),
        (
            {"balance_changed": True},
            "Balance-related state change detected",
        ),
        (
            {"password_changed": True},
            "Password change operation detected",
        ),
        (
            {"mfa_operation": True},
            "MFA operation detected",
        ),
        (
            {"response_variation": True},
            "Response variation detected",
        ),
    ],
)
def test_metadata_titles(
    analyzer,
    finding_analyzer,
    kwargs,
    expected_title,
):
    analysis = analyzer.analyze(**kwargs)

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(finding.title == expected_title for finding in findings)


def test_finding_contains_disclaimer(analyzer, finding_analyzer):
    analysis = analyzer.analyze(duplicate_operation=True)

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert "does not prove" in findings[0].description


@pytest.mark.parametrize(
    "target",
    ["", "   "],
)
def test_empty_target_rejected(
    analyzer,
    finding_analyzer,
    target,
):
    analysis = analyzer.analyze(duplicate_operation=True)

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


def test_remediation_present(analyzer, finding_analyzer):
    analysis = analyzer.analyze(duplicate_operation=True)

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings[0].remediation
    assert findings[0].cwe
    assert findings[0].owasp
