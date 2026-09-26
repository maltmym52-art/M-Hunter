import pytest

from m_hunter.analyzers.idor import (
    IDORAnalysis,
    IDORIndicator,
    IDORIndicatorType,
)
from m_hunter.analyzers.idor_finding import IDORFindingAnalyzer


def make_analysis(*indicators):
    return IDORAnalysis(
        detected=bool(indicators),
        indicators=list(indicators),
    )


@pytest.fixture
def analyzer():
    return IDORFindingAnalyzer()


def test_empty_analysis_returns_no_findings(analyzer):
    result = analyzer.analyze(
        make_analysis(),
        target="https://example.com",
    )

    assert result == []


@pytest.mark.parametrize(
    "indicator_type",
    list(IDORIndicatorType),
)
def test_all_indicator_types_have_findings(
    analyzer,
    indicator_type,
):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=indicator_type,
                name=indicator_type.value,
                value="123",
            )
        ),
        target="https://example.com",
    )

    assert len(result) == 1
    assert result[0].severity == "Info"
    assert result[0].confidence == "High"
    assert result[0].cwe is not None
    assert result[0].owasp is not None


def test_target_preserved(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.OBJECT_IDENTIFIER,
                name="resource_parameter",
                value="id=123",
            )
        ),
        target="https://example.com",
    )

    assert result[0].target == "https://example.com"


def test_endpoint_preserved(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.OBJECT_IDENTIFIER,
                name="resource_parameter",
                value="id=123",
            )
        ),
        target="https://example.com",
        endpoint="/api/object",
    )

    assert result[0].endpoint == "/api/object"


def test_parameter_preserved(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.OBJECT_IDENTIFIER,
                name="resource_parameter",
                value="id=123",
            )
        ),
        target="https://example.com",
        parameter="id",
    )

    assert result[0].parameter == "id"


def test_indicator_value_in_evidence(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.USER_IDENTIFIER,
                name="resource_parameter",
                value="user_id=42",
            )
        ),
        target="https://example.com",
    )

    assert "user_id=42" in result[0].evidence


def test_no_value_indicator(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.SESSION_CONTEXT,
                name="session_context",
            )
        ),
        target="https://example.com",
    )

    assert result[0].evidence
    assert result[0].remediation


def test_idor_is_not_claimed_as_proven(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.OBJECT_IDENTIFIER,
                name="resource_parameter",
                value="id=123",
            )
        ),
        target="https://example.com",
    )

    assert "does not prove" in result[0].description


def test_invalid_analysis_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            object(),
            target="https://example.com",
        )


def test_multiple_indicators_create_multiple_findings(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.USER_IDENTIFIER,
                name="resource_parameter",
                value="user_id=1",
            ),
            IDORIndicator(
                type=IDORIndicatorType.DOCUMENT_IDENTIFIER,
                name="resource_parameter",
                value="document_id=2",
            ),
        ),
        target="https://example.com",
    )

    assert len(result) == 2


def test_metadata_has_cwe_639_for_resource(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.OBJECT_IDENTIFIER,
                name="resource_parameter",
                value="id=123",
            )
        ),
        target="https://example.com",
    )

    assert result[0].cwe == "CWE-639"


def test_metadata_has_cwe_862_for_authentication_context(
    analyzer,
):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.AUTHENTICATION_CONTEXT,
                name="authentication_context",
            )
        ),
        target="https://example.com",
    )

    assert result[0].cwe == "CWE-862"


def test_remediation_mentions_server_side_authorization(
    analyzer,
):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.OBJECT_IDENTIFIER,
                name="resource_parameter",
                value="id=123",
            )
        ),
        target="https://example.com",
    )

    assert "server-side" in result[0].remediation


def test_findings_have_unique_ids(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.USER_IDENTIFIER,
                name="resource_parameter",
                value="user_id=1",
            ),
            IDORIndicator(
                type=IDORIndicatorType.DOCUMENT_IDENTIFIER,
                name="resource_parameter",
                value="document_id=2",
            ),
        ),
        target="https://example.com",
    )

    assert result[0].id != result[1].id


def test_all_findings_are_open(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.OBJECT_IDENTIFIER,
                name="resource_parameter",
                value="id=123",
            )
        ),
        target="https://example.com",
    )

    assert result[0].status == "open"


def test_owasp_is_a01(analyzer):
    result = analyzer.analyze(
        make_analysis(
            IDORIndicator(
                type=IDORIndicatorType.OBJECT_IDENTIFIER,
                name="resource_parameter",
                value="id=123",
            )
        ),
        target="https://example.com",
    )

    assert result[0].owasp == "A01:2021"
