import pytest

from m_hunter.analyzers.api_security import (
    APIAnalysis,
    APIIndicator,
    APIIndicatorType,
)
from m_hunter.analyzers.api_security_finding import (
    APISecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return APISecurityFindingAnalyzer()


def make_analysis(indicator_type):
    indicator = APIIndicator(
        type=indicator_type,
        evidence="Test API security indicator",
        name="test-name",
        value="test-value",
    )

    return APIAnalysis(
        detected=True,
        indicator_count=1,
        types=[indicator_type],
        names=["test-name"],
        indicators=[indicator],
    )


@pytest.mark.parametrize(
    "indicator_type",
    list(APIIndicatorType),
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


def test_empty_analysis_returns_no_findings(analyzer):
    findings = analyzer.analyze(
        APIAnalysis(),
        "https://example.com",
    )

    assert findings == []


def test_multiple_types_create_multiple_findings(analyzer):
    indicators = [
        APIIndicator(
            type=APIIndicatorType.EXCESSIVE_DATA_EXPOSURE,
            evidence="Sensitive data",
            name="password",
            value="redacted",
        ),
        APIIndicator(
            type=APIIndicatorType.SERVER_DISCLOSURE,
            evidence="Server disclosure",
            name="server",
            value="nginx",
        ),
        APIIndicator(
            type=APIIndicatorType.CORS_MISCONFIGURATION,
            evidence="Wildcard CORS",
            name="access-control-allow-origin",
            value="*",
        ),
    ]

    analysis = APIAnalysis(
        detected=True,
        indicator_count=3,
        types=[
            APIIndicatorType.EXCESSIVE_DATA_EXPOSURE,
            APIIndicatorType.SERVER_DISCLOSURE,
            APIIndicatorType.CORS_MISCONFIGURATION,
        ],
        names=[
            "password",
            "server",
            "access-control-allow-origin",
        ],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 3


def test_same_indicator_type_is_grouped(analyzer):
    indicators = [
        APIIndicator(
            type=APIIndicatorType.EXCESSIVE_DATA_EXPOSURE,
            evidence="Password exposed",
            name="password",
        ),
        APIIndicator(
            type=APIIndicatorType.EXCESSIVE_DATA_EXPOSURE,
            evidence="Token exposed",
            name="token",
        ),
    ]

    analysis = APIAnalysis(
        detected=True,
        indicator_count=2,
        types=[
            APIIndicatorType.EXCESSIVE_DATA_EXPOSURE,
        ],
        names=["password", "token"],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert "Evidence count: 2" in findings[0].evidence
    assert "Password exposed" in findings[0].evidence
    assert "Token exposed" in findings[0].evidence


@pytest.mark.parametrize(
    "indicator_type,expected_severity",
    [
        (
            APIIndicatorType.MISSING_SECURITY_HEADER,
            "Low",
        ),
        (
            APIIndicatorType.EXCESSIVE_DATA_EXPOSURE,
            "Medium",
        ),
        (
            APIIndicatorType.VERBOSE_ERROR,
            "Medium",
        ),
        (
            APIIndicatorType.DEBUG_INFORMATION,
            "Medium",
        ),
        (
            APIIndicatorType.SERVER_DISCLOSURE,
            "Low",
        ),
        (
            APIIndicatorType.VERSION_DISCLOSURE,
            "Low",
        ),
        (
            APIIndicatorType.UNRESTRICTED_METHOD,
            "Medium",
        ),
        (
            APIIndicatorType.MISSING_CONTENT_TYPE,
            "Low",
        ),
        (
            APIIndicatorType.WEAK_CONTENT_TYPE,
            "Low",
        ),
        (
            APIIndicatorType.CORS_MISCONFIGURATION,
            "High",
        ),
    ],
)
def test_severity_metadata(
    analyzer,
    indicator_type,
    expected_severity,
):
    findings = analyzer.analyze(
        make_analysis(indicator_type),
        "https://example.com",
    )

    assert findings[0].severity == expected_severity


@pytest.mark.parametrize(
    "indicator_type,expected_confidence",
    [
        (
            APIIndicatorType.MISSING_SECURITY_HEADER,
            "High",
        ),
        (
            APIIndicatorType.EXCESSIVE_DATA_EXPOSURE,
            "Medium",
        ),
        (
            APIIndicatorType.VERBOSE_ERROR,
            "High",
        ),
        (
            APIIndicatorType.DEBUG_INFORMATION,
            "High",
        ),
        (
            APIIndicatorType.SERVER_DISCLOSURE,
            "High",
        ),
        (
            APIIndicatorType.VERSION_DISCLOSURE,
            "High",
        ),
        (
            APIIndicatorType.UNRESTRICTED_METHOD,
            "Medium",
        ),
        (
            APIIndicatorType.MISSING_CONTENT_TYPE,
            "High",
        ),
        (
            APIIndicatorType.WEAK_CONTENT_TYPE,
            "High",
        ),
        (
            APIIndicatorType.CORS_MISCONFIGURATION,
            "High",
        ),
    ],
)
def test_confidence_metadata(
    analyzer,
    indicator_type,
    expected_confidence,
):
    findings = analyzer.analyze(
        make_analysis(indicator_type),
        "https://example.com",
    )

    assert findings[0].confidence == expected_confidence


def test_target_is_preserved(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
        ),
        "https://target.example",
    )

    assert findings[0].target == "https://target.example"


def test_endpoint_is_preserved(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
        ),
        "https://example.com",
        "/api/users",
    )

    assert findings[0].endpoint == "/api/users"


def test_endpoint_defaults_to_none(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
        ),
        "https://example.com",
    )

    assert findings[0].endpoint is None


def test_evidence_contains_indicator_type(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
        ),
        "https://example.com",
    )

    assert "server_disclosure" in findings[0].evidence


def test_evidence_contains_indicator_evidence(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
        ),
        "https://example.com",
    )

    assert "Test API security indicator" in (
        findings[0].evidence
    )


def test_evidence_contains_name(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
        ),
        "https://example.com",
    )

    assert "Name: test-name" in findings[0].evidence


def test_evidence_contains_value(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
        ),
        "https://example.com",
    )

    assert "Value: test-value" in findings[0].evidence


def test_empty_value_is_not_added_to_evidence(analyzer):
    analysis = APIAnalysis(
        detected=True,
        indicator_count=1,
        types=[
            APIIndicatorType.MISSING_CONTENT_TYPE
        ],
        names=[],
        indicators=[
            APIIndicator(
                type=APIIndicatorType.MISSING_CONTENT_TYPE,
                evidence="Missing content type",
                name=None,
                value=None,
            )
        ],
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert "Name:" not in findings[0].evidence
    assert "Value:" not in findings[0].evidence


def test_cwe_is_cwe_200(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.EXCESSIVE_DATA_EXPOSURE
        ),
        "https://example.com",
    )

    assert findings[0].cwe == "CWE-200"


def test_owasp_is_api3_2023(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.EXCESSIVE_DATA_EXPOSURE
        ),
        "https://example.com",
    )

    assert findings[0].owasp == "API3:2023"


def test_description_requires_further_validation(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.CORS_MISCONFIGURATION
        ),
        "https://example.com",
    )

    assert "further validation" in (
        findings[0].description.lower()
    )


def test_remediation_is_present(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.EXCESSIVE_DATA_EXPOSURE
        ),
        "https://example.com",
    )

    assert findings[0].remediation


def test_remediation_mentions_data_exposure(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.EXCESSIVE_DATA_EXPOSURE
        ),
        "https://example.com",
    )

    remediation = findings[0].remediation.lower()

    assert "sensitive data" in remediation


def test_remediation_mentions_cors(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.CORS_MISCONFIGURATION
        ),
        "https://example.com",
    )

    assert "cors" in findings[0].remediation.lower()


def test_title_identifies_api(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
        ),
        "https://example.com",
    )

    assert "api" in findings[0].title.lower()


def test_title_contains_indicator_name(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
        ),
        "https://example.com",
    )

    assert "server disclosure" in (
        findings[0].title.lower()
    )


def test_status_is_open(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            APIIndicatorType.SERVER_DISCLOSURE
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
                APIIndicatorType.SERVER_DISCLOSURE
            ),
            "",
        )


def test_whitespace_target_is_rejected(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            make_analysis(
                APIIndicatorType.SERVER_DISCLOSURE
            ),
            "   ",
        )


def test_invalid_endpoint_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            make_analysis(
                APIIndicatorType.SERVER_DISCLOSURE
            ),
            "https://example.com",
            123,
        )


def test_all_metadata_entries_exist(analyzer):
    for indicator_type in APIIndicatorType:
        assert indicator_type in analyzer.METADATA


def test_all_indicator_types_have_cwe(analyzer):
    for indicator_type in APIIndicatorType:
        findings = analyzer.analyze(
            make_analysis(indicator_type),
            "https://example.com",
        )

        assert findings[0].cwe == "CWE-200"


def test_all_indicator_types_have_owasp(analyzer):
    for indicator_type in APIIndicatorType:
        findings = analyzer.analyze(
            make_analysis(indicator_type),
            "https://example.com",
        )

        assert findings[0].owasp == "API3:2023"


def test_all_findings_are_open(analyzer):
    indicators = [
        APIIndicator(
            type=indicator_type,
            evidence=f"Evidence {indicator_type.value}",
            name=indicator_type.value,
        )
        for indicator_type in APIIndicatorType
    ]

    analysis = APIAnalysis(
        detected=True,
        indicator_count=len(indicators),
        types=list(APIIndicatorType),
        names=[
            indicator.name
            for indicator in indicators
        ],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == len(APIIndicatorType)
    assert all(
        finding.status == "open"
        for finding in findings
    )


def test_titles_are_distinct(analyzer):
    indicators = [
        APIIndicator(
            type=APIIndicatorType.SERVER_DISCLOSURE,
            evidence="Server",
        ),
        APIIndicator(
            type=APIIndicatorType.VERSION_DISCLOSURE,
            evidence="Version",
        ),
    ]

    analysis = APIAnalysis(
        detected=True,
        indicator_count=2,
        types=[
            APIIndicatorType.SERVER_DISCLOSURE,
            APIIndicatorType.VERSION_DISCLOSURE,
        ],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert findings[0].title != findings[1].title
