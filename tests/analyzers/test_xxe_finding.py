import pytest

from m_hunter.analyzers.xxe import (
    XXEAnalysis,
    XXEAnalyzer,
    XXEIndicatorType,
)
from m_hunter.analyzers.xxe_finding import XXEFindingAnalyzer
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return XXEFindingAnalyzer()


@pytest.fixture
def xxe_analyzer():
    return XXEAnalyzer()


def test_empty_analysis_returns_no_findings(analyzer):
    analysis = XXEAnalysis()

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert findings == []


def test_invalid_analysis_type_raises(analyzer):
    with pytest.raises(
        TypeError,
        match="analysis must be an XXEAnalysis instance",
    ):
        analyzer.analyze(
            object(),
            "https://example.com",
        )


def test_empty_target_raises(analyzer):
    with pytest.raises(
        ValueError,
        match="target must be a non-empty string",
    ):
        analyzer.analyze(
            XXEAnalysis(),
            "",
        )


def test_whitespace_target_raises(analyzer):
    with pytest.raises(
        ValueError,
        match="target must be a non-empty string",
    ):
        analyzer.analyze(
            XXEAnalysis(),
            "   ",
        )


def test_invalid_endpoint_type_raises(analyzer):
    with pytest.raises(
        TypeError,
        match="endpoint must be a string or None",
    ):
        analyzer.analyze(
            XXEAnalysis(),
            "https://example.com",
            endpoint=123,
        )


def test_doctype_finding_metadata(analyzer, xxe_analyzer):
    analysis = xxe_analyzer.analyze(
        "<!DOCTYPE root><root>hello</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
        "/upload",
    )

    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-611"
    assert finding.owasp == "A05:2021"


def test_entity_declaration_finding_metadata(analyzer, xxe_analyzer):
    analysis = xxe_analyzer.analyze(
        '<!ENTITY test "hello">'
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert findings[0].severity == "Medium"
    assert findings[0].confidence == "Medium"


def test_external_entity_is_high_severity(analyzer, xxe_analyzer):
    analysis = xxe_analyzer.analyze(
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        item
        for item in findings
        if "external_entity" in item.title
    )

    assert finding.severity == "High"
    assert finding.confidence == "Medium"


def test_system_identifier_is_high_severity(analyzer, xxe_analyzer):
    analysis = xxe_analyzer.analyze(
        '<!ENTITY test SYSTEM "file:///tmp/example">'
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        item
        for item in findings
        if "system_identifier" in item.title
    )

    assert finding.severity == "High"
    assert finding.confidence == "Medium"


def test_public_identifier_is_high_severity(analyzer, xxe_analyzer):
    analysis = xxe_analyzer.analyze(
        '<!ENTITY test PUBLIC "-//Example//DTD//EN" '
        '"http://example.invalid/test.dtd">'
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        item
        for item in findings
        if "public_identifier" in item.title
    )

    assert finding.severity == "High"
    assert finding.confidence == "Medium"


def test_entity_reference_is_low_confidence(analyzer, xxe_analyzer):
    analysis = xxe_analyzer.analyze(
        "<root>&custom;</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        item
        for item in findings
        if "entity_reference" in item.title
    )

    assert finding.severity == "Low"
    assert finding.confidence == "Low"


def test_target_and_endpoint_are_preserved(analyzer, xxe_analyzer):
    analysis = xxe_analyzer.analyze(
        "<!DOCTYPE root><root>hello</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
        "/api/xml",
    )

    assert findings[0].target == "https://example.com"
    assert findings[0].endpoint == "/api/xml"


def test_description_does_not_claim_confirmed_xxe(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    description = findings[0].description.lower()

    assert "review" in description
    assert "unsafe" in description
    assert "confirmed" not in description


def test_remediation_mentions_external_entities(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        "<!DOCTYPE root><root>hello</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    remediation = findings[0].remediation.lower()

    assert "external entity" in remediation
    assert "dtd" in remediation


def test_cwe_and_owasp_are_consistent(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert all(finding.cwe == "CWE-611" for finding in findings)
    assert all(finding.owasp == "A05:2021" for finding in findings)


def test_multiple_indicator_types_create_multiple_findings(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        '<!DOCTYPE root ['
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
        ']>'
        "<root>&test;</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    titles = [finding.title for finding in findings]

    assert len(findings) == len(analysis.types)

    for indicator_type in analysis.types:
        assert any(
            indicator_type.value in title
            for title in titles
        )


def test_evidence_contains_indicator_type(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        "<!DOCTYPE root><root>hello</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert "Indicator type: doctype_declaration" in findings[0].evidence


def test_evidence_contains_raw_indicator(
    analyzer,
    xxe_analyzer,
):
    content = '<!ENTITY test SYSTEM "http://example.invalid/test">'

    analysis = xxe_analyzer.analyze(content)

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert any(
        "http://example.invalid/test" in finding.evidence
        for finding in findings
    )


def test_evidence_contains_count(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        "<!DOCTYPE root><!DOCTYPE second>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert "Evidence count: 2" in findings[0].evidence


def test_only_known_indicator_types_are_reported(
    analyzer,
):
    analysis = XXEAnalysis(
        detected=True,
        indicator_count=0,
        types=[],
        names=[],
        indicators=[],
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert findings == []


def test_finding_titles_identify_xxe(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        "<!DOCTYPE root><root>hello</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert findings[0].title.startswith(
        "Potential XXE indicator:"
    )


def test_findings_have_unique_ids(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        '<!DOCTYPE root>'
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
        "<root>&test;</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    ids = [finding.id for finding in findings]

    assert len(ids) == len(set(ids))


def test_finding_status_defaults_to_open(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        "<!DOCTYPE root><root>hello</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert findings[0].status == "open"


def test_entity_reference_does_not_raise_severity(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        "<root>&custom;</root>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert findings[0].severity == "Low"


def test_findings_preserve_analysis_grouping(
    analyzer,
    xxe_analyzer,
):
    analysis = xxe_analyzer.analyze(
        "<!DOCTYPE root><!DOCTYPE second>"
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert "Evidence count: 2" in findings[0].evidence
