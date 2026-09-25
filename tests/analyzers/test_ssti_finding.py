import pytest

from m_hunter.analyzers.ssti import (
    SSTIAnalysis,
    SSTIAnalyzer,
    SSTIEngine,
    SSTIIndicator,
    SSTIIndicatorType,
)
from m_hunter.analyzers.ssti_finding import (
    SSTIFindingAnalyzer,
)


def test_template_syntax_creates_finding():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
        "/profile",
    )

    assert findings
    assert any(
        "template injection" in finding.title.lower()
        for finding in findings
    )


def test_template_syntax_metadata():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "template injection" in finding.title.lower()
    )

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-1336"
    assert finding.owasp == "A03:2021"


def test_reflection_creates_finding():
    analysis = SSTIAnalyzer().analyze(
        "UNIQUE",
        marker="UNIQUE",
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert any(
        "reflection" in finding.title.lower()
        for finding in findings
    )


def test_engine_marker_creates_finding():
    analysis = SSTIAnalyzer().analyze(
        "Powered by Jinja2"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert any(
        "engine marker" in finding.title.lower()
        for finding in findings
    )


def test_engine_marker_has_low_severity():
    analysis = SSTIAnalyzer().analyze(
        "Powered by Jinja2"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "engine marker" in finding.title.lower()
    )

    assert finding.severity == "Low"
    assert finding.confidence == "Low"


def test_reflection_has_medium_severity():
    analysis = SSTIAnalyzer().analyze(
        "UNIQUE",
        marker="UNIQUE",
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "reflection" in finding.title.lower()
    )

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"


def test_empty_analysis_returns_no_findings():
    findings = SSTIFindingAnalyzer().analyze(
        SSTIAnalysis(),
        "https://example.com",
    )

    assert findings == []


def test_invalid_analysis_type_is_rejected():
    with pytest.raises(TypeError):
        SSTIFindingAnalyzer().analyze(
            {},
            "https://example.com",
        )


def test_target_is_preserved():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://target.example",
    )

    assert findings
    assert all(
        finding.target == "https://target.example"
        for finding in findings
    )


def test_endpoint_is_preserved():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
        "/render",
    )

    assert findings
    assert all(
        finding.endpoint == "/render"
        for finding in findings
    )


def test_evidence_contains_indicator():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings
    assert any(
        "Indicator:" in finding.evidence
        for finding in findings
    )


def test_evidence_contains_target():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert all(
        "https://example.com" in finding.evidence
        for finding in findings
    )


def test_evidence_contains_engine():
    analysis = SSTIAnalyzer().analyze(
        "Powered by Jinja2"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert any(
        "Jinja2" in finding.evidence
        for finding in findings
    )


def test_remediation_is_present():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings
    assert all(
        finding.remediation.strip()
        for finding in findings
    )


def test_description_does_not_claim_confirmation():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings
    assert all(
        "does not confirm" in finding.description.lower()
        for finding in findings
    )


def test_template_description_mentions_evaluation():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "template injection" in finding.title.lower()
    )

    assert "server-side evaluation" in finding.description


def test_reflection_description_does_not_claim_execution():
    analysis = SSTIAnalyzer().analyze(
        "UNIQUE",
        marker="UNIQUE",
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "reflection" in finding.title.lower()
    )

    assert "server-side template evaluation" in finding.description


def test_engine_marker_description_is_contextual():
    analysis = SSTIAnalyzer().analyze(
        "Jinja2"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "engine marker" in finding.title.lower()
    )

    assert "technology context" in finding.description


def test_finding_count_matches_unique_indicator_types():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }} UNIQUE Jinja2",
        marker="UNIQUE",
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == len(set(analysis.types))


def test_multiple_indicators_are_grouped():
    analysis = SSTIAnalyzer().analyze(
        "{{ one }} {{ two }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert "Evidence count: 6" in findings[0].evidence


def test_multiple_types_create_multiple_findings():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }} UNIQUE",
        marker="UNIQUE",
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) >= 2


def test_finding_titles_are_non_empty():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert all(
        finding.title.strip()
        for finding in findings
    )


def test_valid_severity_values():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
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


def test_valid_confidence_values():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert all(
        finding.confidence in {
            "Low",
            "Medium",
            "High",
        }
        for finding in findings
    )


def test_cwe_is_preserved_for_all_findings():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}",
        marker="username",
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings
    assert all(
        finding.cwe == "CWE-1336"
        for finding in findings
    )


def test_owasp_is_preserved_for_all_findings():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}",
        marker="username",
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings
    assert all(
        finding.owasp == "A03:2021"
        for finding in findings
    )


def test_unknown_engine_is_supported():
    analysis = SSTIAnalysis(
        detected=True,
        indicator_count=1,
        engines=[SSTIEngine.UNKNOWN],
        types=[SSTIIndicatorType.TEMPLATE_SYNTAX],
        names=[SSTIIndicatorType.TEMPLATE_SYNTAX.value],
        indicators=[
            SSTIIndicator(
                type=SSTIIndicatorType.TEMPLATE_SYNTAX,
                evidence="custom-template",
                engine=SSTIEngine.UNKNOWN,
            )
        ],
    )

    findings = SSTIFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings
    assert "Unknown" in findings[0].evidence
