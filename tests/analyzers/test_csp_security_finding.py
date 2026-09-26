import pytest

from m_hunter.analyzers.csp_security import (
    CSPAnalysis,
    CSPIndicator,
    CSPIndicatorType,
)
from m_hunter.analyzers.csp_security_finding import (
    CSPFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def make_analysis(*types):
    indicators = tuple(
        CSPIndicator(
            type=indicator_type,
            evidence=f"evidence: {indicator_type.value}",
            value=indicator_type.value,
        )
        for indicator_type in types
    )

    unique_types = tuple(dict.fromkeys(types))

    return CSPAnalysis(
        detected=bool(indicators),
        indicators=indicators,
        count=len(indicators),
        types=unique_types,
        names=tuple(item.value for item in unique_types),
    )


@pytest.fixture
def analyzer():
    return CSPFindingAnalyzer()


def test_analyzer_name(analyzer):
    assert analyzer.name == "csp_security_finding"


def test_requires_csp_analysis(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            object(),
            target="https://example.com",
        )


def test_requires_target(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            make_analysis(CSPIndicatorType.UNSAFE_INLINE),
            target="",
        )


def test_rejects_invalid_endpoint(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            make_analysis(CSPIndicatorType.UNSAFE_INLINE),
            target="https://example.com",
            endpoint=123,
        )


@pytest.mark.parametrize(
    "indicator_type",
    list(CSPIndicatorType),
)
def test_all_indicators_have_metadata(analyzer, indicator_type):
    assert indicator_type in analyzer.METADATA
    assert indicator_type in analyzer.TITLES


@pytest.mark.parametrize(
    "indicator_type",
    [
        CSPIndicatorType.WILDCARD_SOURCE,
        CSPIndicatorType.UNSAFE_INLINE,
        CSPIndicatorType.UNSAFE_EVAL,
        CSPIndicatorType.SCRIPT_SRC_WILDCARD,
    ],
)
def test_security_indicators_create_findings(
    analyzer,
    indicator_type,
):
    findings = analyzer.analyze(
        make_analysis(indicator_type),
        target="https://example.com",
    )

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)


def test_finding_preserves_target(analyzer):
    findings = analyzer.analyze(
        make_analysis(CSPIndicatorType.UNSAFE_INLINE),
        target="https://target.example",
    )

    assert findings[0].target == "https://target.example"


def test_finding_preserves_endpoint(analyzer):
    findings = analyzer.analyze(
        make_analysis(CSPIndicatorType.UNSAFE_EVAL),
        target="https://example.com",
        endpoint="/login",
    )

    assert findings[0].endpoint == "/login"


def test_finding_preserves_indicator_value(analyzer):
    findings = analyzer.analyze(
        make_analysis(CSPIndicatorType.UNSAFE_INLINE),
        target="https://example.com",
    )

    assert "value=unsafe_inline" in findings[0].evidence


def test_high_severity_script_wildcard(analyzer):
    findings = analyzer.analyze(
        make_analysis(CSPIndicatorType.SCRIPT_SRC_WILDCARD),
        target="https://example.com",
    )

    assert findings[0].severity == "High"
    assert findings[0].confidence == "High"


def test_medium_severity_unsafe_inline(analyzer):
    findings = analyzer.analyze(
        make_analysis(CSPIndicatorType.UNSAFE_INLINE),
        target="https://example.com",
    )

    assert findings[0].severity == "Medium"


def test_csp_presence_is_informational(analyzer):
    findings = analyzer.analyze(
        make_analysis(CSPIndicatorType.CSP_PRESENT),
        target="https://example.com",
    )

    assert findings[0].severity == "Informational"


def test_finding_has_cwe_and_owasp(analyzer):
    findings = analyzer.analyze(
        make_analysis(CSPIndicatorType.UNSAFE_EVAL),
        target="https://example.com",
    )

    assert findings[0].cwe == "CWE-693"
    assert findings[0].owasp == "A05:2021"


def test_description_is_conservative(analyzer):
    findings = analyzer.analyze(
        make_analysis(CSPIndicatorType.UNSAFE_INLINE),
        target="https://example.com",
    )

    assert "does not prove" in findings[0].description


def test_remediation_is_present(analyzer):
    findings = analyzer.analyze(
        make_analysis(CSPIndicatorType.UNSAFE_INLINE),
        target="https://example.com",
    )

    assert findings[0].remediation


def test_multiple_indicators_create_multiple_findings(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE,
            CSPIndicatorType.UNSAFE_EVAL,
            CSPIndicatorType.DATA_SOURCE,
        ),
        target="https://example.com",
    )

    assert len(findings) == 3


def test_empty_analysis_returns_no_findings(analyzer):
    findings = analyzer.analyze(
        make_analysis(),
        target="https://example.com",
    )

    assert findings == []


def test_finding_titles_are_specific(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            CSPIndicatorType.FRAME_ANCESTORS_WILDCARD
        ),
        target="https://example.com",
    )

    assert findings[0].title == "CSP Frame Ancestors Wildcard"
