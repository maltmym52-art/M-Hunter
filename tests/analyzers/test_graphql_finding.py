import pytest

from m_hunter.analyzers.graphql import (
    GraphQLAnalysis,
    GraphQLIndicator,
    GraphQLIndicatorType,
)
from m_hunter.analyzers.graphql_finding import (
    GraphQLFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return GraphQLFindingAnalyzer()


def make_analysis(indicator_type):
    indicator = GraphQLIndicator(
        type=indicator_type,
        evidence="Test GraphQL security indicator",
        name="test-indicator",
    )

    return GraphQLAnalysis(
        detected=True,
        indicator_count=1,
        types=[indicator_type],
        names=["test-indicator"],
        indicators=[indicator],
    )


@pytest.mark.parametrize(
    "indicator_type",
    list(GraphQLIndicatorType),
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
        GraphQLAnalysis(),
        "https://example.com",
    )

    assert findings == []


def test_multiple_indicator_types_create_multiple_findings(
    analyzer,
):
    indicators = [
        GraphQLIndicator(
            type=GraphQLIndicatorType.INTROSPECTION_ENABLED,
            evidence="Introspection detected",
            name="introspection",
        ),
        GraphQLIndicator(
            type=GraphQLIndicatorType.BATCHING,
            evidence="Batching detected",
            name="batch",
        ),
        GraphQLIndicator(
            type=GraphQLIndicatorType.SENSITIVE_FIELD,
            evidence="Sensitive field detected",
            name="password",
        ),
    ]

    analysis = GraphQLAnalysis(
        detected=True,
        indicator_count=3,
        types=[
            GraphQLIndicatorType.INTROSPECTION_ENABLED,
            GraphQLIndicatorType.BATCHING,
            GraphQLIndicatorType.SENSITIVE_FIELD,
        ],
        names=["introspection", "batch", "password"],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 3


def test_same_indicator_type_is_grouped(analyzer):
    indicators = [
        GraphQLIndicator(
            type=GraphQLIndicatorType.SENSITIVE_FIELD,
            evidence="First sensitive field",
            name="password",
        ),
        GraphQLIndicator(
            type=GraphQLIndicatorType.SENSITIVE_FIELD,
            evidence="Second sensitive field",
            name="token",
        ),
    ]

    analysis = GraphQLAnalysis(
        detected=True,
        indicator_count=2,
        types=[
            GraphQLIndicatorType.SENSITIVE_FIELD,
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
    assert "First sensitive field" in findings[0].evidence
    assert "Second sensitive field" in findings[0].evidence


def test_introspection_is_medium_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.INTROSPECTION_ENABLED
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Medium"
    assert findings[0].confidence == "High"


def test_query_operation_is_info(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.QUERY_OPERATION
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Info"


def test_mutation_operation_is_info(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.MUTATION_OPERATION
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Info"


def test_subscription_operation_is_info(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.SUBSCRIPTION_OPERATION
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Info"


def test_alias_is_low_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.ALIAS_USAGE
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Low"


def test_batching_is_medium_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Medium"


def test_deep_query_is_medium_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.DEEP_QUERY
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Medium"


def test_large_query_is_low_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.LARGE_QUERY
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Low"


def test_sensitive_field_is_medium_severity(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.SENSITIVE_FIELD
        ),
        "https://example.com",
    )

    assert findings[0].severity == "Medium"


def test_target_is_preserved(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://target.example",
    )

    assert findings[0].target == "https://target.example"


def test_endpoint_is_preserved(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://example.com",
        "/graphql",
    )

    assert findings[0].endpoint == "/graphql"


def test_endpoint_defaults_to_none(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://example.com",
    )

    assert findings[0].endpoint is None


def test_finding_contains_evidence(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://example.com",
    )

    assert "Test GraphQL security indicator" in (
        findings[0].evidence
    )


def test_finding_contains_indicator_type(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://example.com",
    )

    assert "batching" in findings[0].evidence


def test_finding_contains_indicator_name(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://example.com",
    )

    assert "test-indicator" in findings[0].evidence


def test_finding_contains_remediation(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.INTROSPECTION_ENABLED
        ),
        "https://example.com",
    )

    assert findings[0].remediation
    assert "authorization" in findings[0].remediation.lower()


def test_finding_contains_further_validation(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.SENSITIVE_FIELD
        ),
        "https://example.com",
    )

    assert "further validation" in (
        findings[0].description.lower()
    )


def test_finding_has_cwe_200(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.SENSITIVE_FIELD
        ),
        "https://example.com",
    )

    assert findings[0].cwe == "CWE-200"


def test_finding_has_owasp_api8(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.SENSITIVE_FIELD
        ),
        "https://example.com",
    )

    assert findings[0].owasp == "API8:2023"


def test_finding_status_is_open(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.SENSITIVE_FIELD
        ),
        "https://example.com",
    )

    assert findings[0].status == "open"


def test_finding_title_identifies_graphql(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://example.com",
    )

    assert "graphql" in findings[0].title.lower()


def test_finding_title_contains_indicator_name(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://example.com",
    )

    assert "batching" in findings[0].title.lower()


def test_position_is_included_in_evidence(analyzer):
    indicator = GraphQLIndicator(
        type=GraphQLIndicatorType.SENSITIVE_FIELD,
        evidence="Sensitive field detected",
        name="password",
        position=42,
    )

    analysis = GraphQLAnalysis(
        detected=True,
        indicator_count=1,
        types=[GraphQLIndicatorType.SENSITIVE_FIELD],
        names=["password"],
        indicators=[indicator],
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert "Position: 42" in findings[0].evidence


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
                GraphQLIndicatorType.BATCHING
            ),
            "",
        )


def test_whitespace_target_is_rejected(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            make_analysis(
                GraphQLIndicatorType.BATCHING
            ),
            "   ",
        )


def test_invalid_endpoint_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            make_analysis(
                GraphQLIndicatorType.BATCHING
            ),
            "https://example.com",
            123,
        )


def test_empty_endpoint_is_allowed(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            GraphQLIndicatorType.BATCHING
        ),
        "https://example.com",
        "",
    )

    assert findings[0].endpoint == ""


def test_all_indicator_types_have_metadata(analyzer):
    for indicator_type in GraphQLIndicatorType:
        assert indicator_type in analyzer.METADATA


def test_all_findings_have_cwe(analyzer):
    for indicator_type in GraphQLIndicatorType:
        findings = analyzer.analyze(
            make_analysis(indicator_type),
            "https://example.com",
        )

        assert findings[0].cwe


def test_all_findings_have_owasp(analyzer):
    for indicator_type in GraphQLIndicatorType:
        findings = analyzer.analyze(
            make_analysis(indicator_type),
            "https://example.com",
        )

        assert findings[0].owasp


def test_all_findings_are_open(analyzer):
    indicators = [
        GraphQLIndicator(
            type=indicator_type,
            evidence=f"Evidence for {indicator_type.value}",
            name=indicator_type.value,
        )
        for indicator_type in GraphQLIndicatorType
    ]

    analysis = GraphQLAnalysis(
        detected=True,
        indicator_count=len(indicators),
        types=list(GraphQLIndicatorType),
        names=[item.name for item in indicators],
        indicators=indicators,
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == len(GraphQLIndicatorType)
    assert all(
        finding.status == "open"
        for finding in findings
    )
