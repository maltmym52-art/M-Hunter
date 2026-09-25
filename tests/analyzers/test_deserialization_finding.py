import pytest

from m_hunter.analyzers.deserialization import (
    DeserializationAnalysis,
    DeserializationIndicator,
    DeserializationIndicatorType,
)
from m_hunter.analyzers.deserialization_finding import (
    DeserializationFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return DeserializationFindingAnalyzer()


def make_analysis(indicator_type):
    indicator = DeserializationIndicator(
        type=indicator_type,
        evidence="Test serialized-data indicator",
        name="test-input",
    )

    return DeserializationAnalysis(
        detected=True,
        indicator_count=1,
        types=[indicator_type],
        names=["test-input"],
        indicators=[indicator],
    )


@pytest.mark.parametrize(
    "indicator_type",
    list(DeserializationIndicatorType),
)
def test_each_indicator_type_creates_finding(
    analyzer,
    indicator_type,
):
    findings = analyzer.analyze(
        make_analysis(indicator_type),
        "https://example.com",
    )

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)


@pytest.mark.parametrize(
    "indicator_type",
    list(DeserializationIndicatorType),
)
def test_finding_has_cwe_502(
    analyzer,
    indicator_type,
):
    findings = analyzer.analyze(
        make_analysis(indicator_type),
        "https://example.com",
    )

    assert findings[0].cwe == "CWE-502"


@pytest.mark.parametrize(
    "indicator_type",
    list(DeserializationIndicatorType),
)
def test_finding_has_owasp_a08(
    analyzer,
    indicator_type,
):
    findings = analyzer.analyze(
        make_analysis(indicator_type),
        "https://example.com",
    )

    assert findings[0].owasp == "A08:2021"


def test_empty_analysis_returns_no_findings(analyzer):
    findings = analyzer.analyze(
        DeserializationAnalysis(),
        "https://example.com",
    )

    assert findings == []


def test_multiple_indicator_types_create_multiple_findings(analyzer):
    indicators = [
        DeserializationIndicator(
            type=DeserializationIndicatorType.SERIALIZED_PARAMETER,
            evidence="Serialized parameter detected",
            name="pickle",
        ),
        DeserializationIndicator(
            type=DeserializationIndicatorType.SERIALIZED_COOKIE,
            evidence="Serialized cookie detected",
            name="serialized",
        ),
        DeserializationIndicator(
            type=DeserializationIndicatorType.SERIALIZED_FILE,
            evidence="Serialized file detected",
            name="object.ser",
        ),
    ]

    analysis = DeserializationAnalysis(
        detected=True,
        indicator_count=3,
        types=[
            DeserializationIndicatorType.SERIALIZED_PARAMETER,
            DeserializationIndicatorType.SERIALIZED_COOKIE,
            DeserializationIndicatorType.SERIALIZED_FILE,
        ],
        names=["pickle", "serialized", "object.ser"],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 3


def test_same_indicator_type_is_grouped(analyzer):
    indicators = [
        DeserializationIndicator(
            type=DeserializationIndicatorType.SERIALIZED_PARAMETER,
            evidence="First parameter",
            name="pickle",
        ),
        DeserializationIndicator(
            type=DeserializationIndicatorType.SERIALIZED_PARAMETER,
            evidence="Second parameter",
            name="marshal",
        ),
    ]

    analysis = DeserializationAnalysis(
        detected=True,
        indicator_count=2,
        types=[
            DeserializationIndicatorType.SERIALIZED_PARAMETER,
        ],
        names=["pickle", "marshal"],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert "Evidence count: 2" in findings[0].evidence
    assert "First parameter" in findings[0].evidence
    assert "Second parameter" in findings[0].evidence


def test_parameter_finding_is_high_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert findings[0].severity == "High"


def test_cookie_finding_is_high_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_COOKIE
        ),
        "https://example.com",
    )

    assert findings[0].severity == "High"


def test_content_type_finding_is_high_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_CONTENT_TYPE
        ),
        "https://example.com",
    )

    assert findings[0].severity == "High"


def test_file_finding_is_medium_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_FILE
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Medium"


def test_header_finding_is_medium_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZATION_HEADER
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Medium"


def test_finding_confidence_is_medium(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert findings[0].confidence == "Medium"


def test_target_is_preserved(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://target.example",
    )

    assert findings[0].target == "https://target.example"


def test_endpoint_is_preserved(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
        "/api/test",
    )

    assert findings[0].endpoint == "/api/test"


def test_endpoint_defaults_to_none(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert findings[0].endpoint is None


def test_finding_contains_evidence(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert "Test serialized-data indicator" in findings[0].evidence


def test_finding_contains_indicator_type(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert "serialized_parameter" in findings[0].evidence


def test_finding_contains_indicator_name(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert "test-input" in findings[0].evidence


def test_finding_contains_remediation(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert findings[0].remediation
    assert "untrusted data" in findings[0].remediation


def test_finding_contains_caution_about_proof(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert "does not" in findings[0].description.lower()
    assert "prove" in findings[0].description.lower()


def test_finding_title_identifies_deserialization(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert "deserialization" in findings[0].title.lower()


def test_finding_status_is_open(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
    )

    assert findings[0].status == "open"


def test_invalid_analysis_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            object(),
            "https://example.com",
        )


def test_empty_target_is_rejected(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            make_analysis(
                DeserializationIndicatorType.SERIALIZED_PARAMETER
            ),
            "",
        )


def test_whitespace_target_is_rejected(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            make_analysis(
                DeserializationIndicatorType.SERIALIZED_PARAMETER
            ),
            "   ",
        )


def test_invalid_endpoint_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            make_analysis(
                DeserializationIndicatorType.SERIALIZED_PARAMETER
            ),
            "https://example.com",
            123,
        )


def test_empty_endpoint_is_allowed(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_PARAMETER
        ),
        "https://example.com",
        "",
    )

    assert findings[0].endpoint == ""


def test_multiple_findings_have_distinct_titles(analyzer):
    indicators = [
        DeserializationIndicator(
            type=DeserializationIndicatorType.SERIALIZED_PARAMETER,
            evidence="Parameter evidence",
            name="pickle",
        ),
        DeserializationIndicator(
            type=DeserializationIndicatorType.SERIALIZED_COOKIE,
            evidence="Cookie evidence",
            name="serialized",
        ),
    ]

    analysis = DeserializationAnalysis(
        detected=True,
        indicator_count=2,
        types=[
            DeserializationIndicatorType.SERIALIZED_PARAMETER,
            DeserializationIndicatorType.SERIALIZED_COOKIE,
        ],
        names=["pickle", "serialized"],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 2
    assert findings[0].title != findings[1].title


def test_finding_description_mentions_further_validation(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_COOKIE
        ),
        "https://example.com",
    )

    assert "further" in findings[0].description.lower()


def test_remediation_mentions_safe_formats(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_FILE
        ),
        "https://example.com",
    )

    assert "structured data" in findings[0].remediation.lower()


def test_remediation_mentions_type_restrictions(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            DeserializationIndicatorType.SERIALIZED_CONTENT_TYPE
        ),
        "https://example.com",
    )

    assert "types" in findings[0].remediation.lower()


def test_all_findings_are_open(analyzer):
    indicators = [
        DeserializationIndicator(
            type=indicator_type,
            evidence=f"Evidence for {indicator_type.value}",
            name=indicator_type.value,
        )
        for indicator_type in DeserializationIndicatorType
    ]

    analysis = DeserializationAnalysis(
        detected=True,
        indicator_count=len(indicators),
        types=list(DeserializationIndicatorType),
        names=[item.name for item in indicators],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == len(DeserializationIndicatorType)
    assert all(finding.status == "open" for finding in findings)
