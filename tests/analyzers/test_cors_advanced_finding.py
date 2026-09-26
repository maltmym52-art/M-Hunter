import pytest

from m_hunter.analyzers.cors_advanced import (
    CORSAdvancedAnalysis,
    CORSAdvancedIndicator,
    CORSAdvancedIndicatorType,
)
from m_hunter.analyzers.cors_advanced_finding import (
    CORSAdvancedFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def make_analysis(*indicators):
    return CORSAdvancedAnalysis(
        detected=bool(indicators),
        indicators=tuple(indicators),
        count=len(indicators),
        types=tuple(
            dict.fromkeys(
                indicator.type
                for indicator in indicators
            )
        ),
        names=tuple(
            indicator.type.value
            for indicator in indicators
        ),
    )


def indicator(
    indicator_type,
    *,
    evidence="test evidence",
    value=None,
):
    return CORSAdvancedIndicator(
        type=indicator_type,
        evidence=evidence,
        value=value,
    )


@pytest.fixture
def analyzer():
    return CORSAdvancedFindingAnalyzer()


def test_analyzer_can_be_created(analyzer):
    assert isinstance(
        analyzer,
        CORSAdvancedFindingAnalyzer,
    )


def test_empty_analysis_returns_no_findings(analyzer):
    result = analyzer.analyze(
        make_analysis(),
        target="https://example.com",
    )

    assert result == []


def test_requires_correct_analysis_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            {},
            target="https://example.com",
        )


def test_requires_target(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION
        )
    )

    with pytest.raises(ValueError):
        analyzer.analyze(
            analysis,
            target="",
        )


def test_endpoint_must_be_string(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION
        )
    )

    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis,
            target="https://example.com",
            endpoint=123,
        )


@pytest.mark.parametrize(
    "indicator_type",
    list(
        CORSAdvancedFindingAnalyzer.INDICATOR_METADATA
    ),
)
def test_every_metadata_indicator_creates_finding(
    analyzer,
    indicator_type,
):
    analysis = make_analysis(
        indicator(
            indicator_type,
            value="https://attacker.example",
        )
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/api",
    )

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert findings[0].target == "https://example.com"
    assert findings[0].endpoint == "/api"


def test_origin_reflection_metadata(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION,
            value="https://attacker.example",
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.title == "CORS Origin Reflection"
    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-942"
    assert finding.owasp == "A05:2021"


def test_credentialed_reflection_is_high(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType
            .CREDENTIALED_ORIGIN_REFLECTION
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.confidence == "High"


def test_arbitrary_origin_is_high_medium_confidence(
    analyzer,
):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.confidence == "Medium"


def test_wildcard_credentials_are_high(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType
            .WILDCARD_CREDENTIALS
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.confidence == "High"


def test_null_origin_is_medium(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType
            .NULL_ORIGIN_REFLECTION
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_subdomain_trust_is_medium(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_prefix_trust_is_medium(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.PREFIX_TRUST
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_suffix_trust_is_medium(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.SUFFIX_TRUST
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_vary_origin_missing_is_low(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.VARY_ORIGIN_MISSING
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Medium"


def test_credentials_enabled_is_info(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.CREDENTIALS_ENABLED
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "High"


def test_allow_origin_presence_is_info(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType
            .ACCESS_CONTROL_ALLOW_ORIGIN_PRESENT
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_allow_credentials_presence_is_info(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType
            .ACCESS_CONTROL_ALLOW_CREDENTIALS_PRESENT
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_preflight_methods_are_info(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.PREFLIGHT_METHODS
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_preflight_headers_are_info(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.PREFLIGHT_HEADERS
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_preflight_credentials_are_low(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.PREFLIGHT_CREDENTIALS
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"


def test_evidence_contains_indicator_value(analyzer):
    value = "https://attacker.example"

    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION,
            value=value,
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert value in finding.evidence


def test_evidence_without_value_is_valid(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.evidence == "test evidence"


def test_multiple_indicators_create_multiple_findings(
    analyzer,
):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION
        ),
        indicator(
            CORSAdvancedIndicatorType.CREDENTIALS_ENABLED
        ),
        indicator(
            CORSAdvancedIndicatorType.VARY_ORIGIN_MISSING
        ),
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) == 3
    assert all(
        isinstance(finding, Finding)
        for finding in findings
    )


def test_finding_ids_are_unique(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION
        ),
        indicator(
            CORSAdvancedIndicatorType.CREDENTIALS_ENABLED
        ),
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings[0].id != findings[1].id


def test_unknown_indicator_is_skipped(analyzer):
    class Unknown:
        type = "unknown"
        evidence = "unknown"
        value = None

    analysis = CORSAdvancedAnalysis(
        detected=True,
        indicators=(Unknown(),),
        count=1,
        types=(),
        names=("unknown",),
    )

    findings = analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


def test_target_is_preserved(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://target.example",
    )[0]

    assert finding.target == "https://target.example"


def test_endpoint_is_preserved(analyzer):
    analysis = make_analysis(
        indicator(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION
        )
    )

    finding = analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/account/profile",
    )[0]

    assert finding.endpoint == "/account/profile"


def test_metadata_titles_are_non_empty(analyzer):
    for metadata in analyzer.INDICATOR_METADATA.values():
        assert metadata["title"].strip()


def test_metadata_severities_are_valid(analyzer):
    valid = {
        "Info",
        "Low",
        "Medium",
        "High",
        "Critical",
    }

    for metadata in analyzer.INDICATOR_METADATA.values():
        assert metadata["severity"] in valid


def test_metadata_confidences_are_valid(analyzer):
    valid = {
        "Low",
        "Medium",
        "High",
    }

    for metadata in analyzer.INDICATOR_METADATA.values():
        assert metadata["confidence"] in valid
