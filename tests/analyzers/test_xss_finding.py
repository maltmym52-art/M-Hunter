import pytest

from m_hunter.analyzers.xss import (
    XSSAnalysis,
    XSSContext,
    XSSReflection,
)
from m_hunter.analyzers.xss_finding import (
    XSSFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def make_analysis(
    *,
    marker="M-HUNTER",
    reflections=None,
):
    return XSSAnalysis(
        marker=marker,
        reflected=bool(reflections),
        reflections=reflections or [],
    )


def test_analyzer_can_be_created():
    analyzer = XSSFindingAnalyzer()

    assert isinstance(
        analyzer,
        XSSFindingAnalyzer,
    )


def test_non_analysis_is_rejected():
    analyzer = XSSFindingAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze(
            {},
            target="https://example.com",
        )


def test_no_reflection_creates_no_findings():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis()

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


def test_html_reflection_creates_finding():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        reflections=[
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.HTML_TEXT,
                position=10,
            )
        ]
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].severity == "Medium"
    assert findings[0].confidence == "Medium"
    assert findings[0].cwe == "CWE-79"
    assert findings[0].owasp == "A03:2021"


def test_javascript_context_is_high_severity():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        reflections=[
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.JAVASCRIPT,
                position=20,
            )
        ]
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings[0].severity == "High"


def test_json_reflection_has_low_confidence():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        reflections=[
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.JSON,
                position=15,
            )
        ]
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings[0].severity == "Low"
    assert findings[0].confidence == "Low"


def test_multiple_contexts_create_multiple_findings():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        reflections=[
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.HTML_TEXT,
                position=5,
            ),
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.HTML_ATTRIBUTE,
                position=30,
            ),
        ]
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) == 2


def test_same_context_is_grouped_into_one_finding():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        reflections=[
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.HTML_TEXT,
                position=5,
            ),
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.HTML_TEXT,
                position=30,
            ),
        ]
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) == 1
    assert "Reflection count: 2" in findings[0].evidence


def test_encoded_reflections_are_reported():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        reflections=[
            XSSReflection(
                value="M-HUNTER&amp;",
                context=XSSContext.HTML_TEXT,
                position=5,
                encoded=True,
            )
        ]
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) == 1
    assert "Encoded reflections: 1" in findings[0].evidence


def test_target_and_endpoint_are_preserved():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        reflections=[
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.HTML_TEXT,
                position=5,
            )
        ]
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="https://example.com/search",
        parameter="q",
    )

    finding = findings[0]

    assert finding.target == "https://example.com"
    assert finding.endpoint == (
        "https://example.com/search"
    )
    assert finding.parameter == "q"


def test_finding_contains_evidence():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        marker="UNIQUE-MARKER",
        reflections=[
            XSSReflection(
                value="UNIQUE-MARKER",
                context=XSSContext.HTML_TEXT,
                position=5,
            )
        ],
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert "UNIQUE-MARKER" in finding.evidence
    assert "html_text" in finding.evidence


def test_finding_contains_remediation():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        reflections=[
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.HTML_ATTRIBUTE,
                position=5,
            )
        ]
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.remediation


def test_reflection_is_not_marked_as_confirmed_execution():
    analyzer = XSSFindingAnalyzer()

    analysis = make_analysis(
        reflections=[
            XSSReflection(
                value="M-HUNTER",
                context=XSSContext.HTML_TEXT,
                position=5,
            )
        ]
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert "execution" in finding.description.lower()
    assert "does not prove" in finding.description.lower()
