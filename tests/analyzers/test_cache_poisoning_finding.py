import pytest

from m_hunter.analyzers.cache_poisoning import (
    CachePoisoningAnalysis,
    CachePoisoningAnalyzer,
    CachePoisoningIndicator,
    CachePoisoningIndicatorType,
)
from m_hunter.analyzers.cache_poisoning_finding import (
    CachePoisoningFindingAnalyzer,
)


def analyzer():
    return CachePoisoningFindingAnalyzer()


def make_analysis(indicator_type, name="X-Cache", value="HIT"):
    indicator = CachePoisoningIndicator(
        type=indicator_type,
        evidence=f"{name}: {value}",
        name=name,
        value=value,
    )

    return CachePoisoningAnalysis(
        detected=True,
        count=1,
        types=[indicator_type.value],
        names=[name],
        indicators=[indicator],
    )


def test_empty_analysis_returns_no_findings():
    analysis = CachePoisoningAnalysis(
        detected=False,
        count=0,
        types=[],
        names=[],
        indicators=[],
    )

    assert analyzer().create_findings(
        analysis,
        "https://example.com",
    ) == []


def test_invalid_analysis_type():
    with pytest.raises(TypeError):
        analyzer().create_findings(
            "invalid",
            "https://example.com",
        )


def test_empty_target():
    analysis = make_analysis(
        CachePoisoningIndicatorType.CACHE_STATUS,
    )

    with pytest.raises(ValueError):
        analyzer().create_findings(analysis, "")


@pytest.mark.parametrize(
    "indicator_type,expected_severity,expected_confidence",
    [
        (CachePoisoningIndicatorType.CACHE_STATUS, "Info", "High"),
        (CachePoisoningIndicatorType.CACHE_CONTROL, "Info", "High"),
        (CachePoisoningIndicatorType.VARY_HEADER, "Info", "High"),
        (CachePoisoningIndicatorType.CACHE_KEY_INDICATOR, "Info", "Medium"),
        (CachePoisoningIndicatorType.AGE_HEADER, "Info", "High"),
        (CachePoisoningIndicatorType.ETAG_HEADER, "Info", "High"),
        (CachePoisoningIndicatorType.UNKEYED_INPUT, "Medium", "Medium"),
        (CachePoisoningIndicatorType.RESPONSE_VARIATION, "Medium", "Medium"),
    ],
)
def test_metadata(indicator_type, expected_severity, expected_confidence):
    finding = analyzer().create_findings(
        make_analysis(indicator_type),
        "https://example.com",
    )[0]

    assert finding.severity == expected_severity
    assert finding.confidence == expected_confidence


def test_cache_status_finding():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert finding.title == "Cache behavior detected"
    assert finding.cwe == "CWE-524"
    assert finding.owasp == "A05:2021"


def test_cache_control_finding():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.CACHE_CONTROL),
        "https://example.com",
    )[0]

    assert finding.title == "Cache-Control behavior detected"


def test_vary_finding():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.VARY_HEADER),
        "https://example.com",
    )[0]

    assert finding.title == "Vary header affects cache behavior"


def test_cache_key_finding():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.CACHE_KEY_INDICATOR),
        "https://example.com",
    )[0]

    assert finding.title == "Potential cache key indicator detected"


def test_age_finding():
    finding = analyzer().create_findings(
        make_analysis(
            CachePoisoningIndicatorType.AGE_HEADER,
            "Age",
            "120",
        ),
        "https://example.com",
    )[0]

    assert finding.title == "Cached response age detected"


def test_etag_finding():
    finding = analyzer().create_findings(
        make_analysis(
            CachePoisoningIndicatorType.ETAG_HEADER,
            "ETag",
            '"abc"',
        ),
        "https://example.com",
    )[0]

    assert finding.title == "ETag cache validator detected"


def test_unkeyed_input_finding():
    finding = analyzer().create_findings(
        make_analysis(
            CachePoisoningIndicatorType.UNKEYED_INPUT,
            "x-forwarded-host",
            "x-forwarded-host",
        ),
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-444"


def test_response_variation_finding():
    finding = analyzer().create_findings(
        make_analysis(
            CachePoisoningIndicatorType.RESPONSE_VARIATION,
            "response_body",
            "changed",
        ),
        "https://example.com",
    )[0]

    assert finding.title == "Response variation detected"


def test_endpoint_and_parameter_are_preserved():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.CACHE_STATUS),
        "https://example.com",
        endpoint="/account",
        parameter="id",
    )[0]

    assert finding.endpoint == "/account"
    assert finding.parameter == "id"


def test_evidence_contains_indicator_details():
    finding = analyzer().create_findings(
        make_analysis(
            CachePoisoningIndicatorType.CACHE_STATUS,
            "X-Cache",
            "HIT",
        ),
        "https://example.com",
    )[0]

    assert "cache_status" in finding.evidence
    assert "X-Cache" in finding.evidence
    assert "HIT" in finding.evidence


def test_description_contains_disclaimer():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert "does not" in finding.description
    assert "prove exploitable cache poisoning" in finding.description


def test_remediation_present():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert finding.remediation
    assert "cache key" in finding.remediation


def test_all_supported_types_generate_findings():
    for indicator_type in CachePoisoningIndicatorType:
        findings = analyzer().create_findings(
            make_analysis(indicator_type),
            "https://example.com",
        )

        assert len(findings) == 1


def test_multiple_indicators_generate_multiple_findings():
    analysis = CachePoisoningAnalyzer().analyze(
        headers={
            "X-Cache": "HIT",
            "Cache-Control": "public",
            "Age": "100",
            "ETag": '"abc"',
        },
    )

    findings = analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert len(findings) == analysis.count


def test_target_is_preserved():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.CACHE_STATUS),
        "https://target.example",
    )[0]

    assert finding.target == "https://target.example"


def test_status_defaults_to_open():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert finding.status == "open"


def test_created_at_is_present():
    finding = analyzer().create_findings(
        make_analysis(CachePoisoningIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert finding.created_at is not None
