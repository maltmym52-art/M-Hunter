import pytest

from m_hunter.analyzers.clickjacking import (
    ClickjackingAnalysis,
    ClickjackingIndicator,
    ClickjackingIndicatorType,
)
from m_hunter.analyzers.clickjacking_finding import (
    ClickjackingFindingAnalyzer,
)


def make_analysis(*indicators):
    return ClickjackingAnalysis(
        detected=bool(indicators),
        indicators=list(indicators),
    )


@pytest.fixture
def analyzer():
    return ClickjackingFindingAnalyzer()


def test_empty_analysis_returns_no_findings(analyzer):
    result = analyzer.analyze(
        make_analysis(),
        target="https://example.com",
    )

    assert result == []


@pytest.mark.parametrize(
    "indicator_type",
    list(ClickjackingIndicatorType),
)
def test_all_indicator_types_have_metadata(
    analyzer,
    indicator_type,
):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=indicator_type,
                name=indicator_type.value,
                value="test",
            )
        ),
        target="https://example.com",
    )

    assert len(result) == 1
    assert result[0].severity in {
        "Low",
        "Medium",
        "High",
        "Critical",
        "Info",
    }
    assert result[0].confidence in {
        "Low",
        "Medium",
        "High",
    }
    assert result[0].cwe
    assert result[0].owasp


def test_missing_xfo_is_medium(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                name="missing_x_frame_options",
            )
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Medium"
    assert result[0].cwe == "CWE-1021"


def test_invalid_xfo_is_medium(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS,
                name="invalid_x_frame_options",
                value="INVALID",
            )
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Medium"


def test_wildcard_frame_ancestors_is_medium(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD,
                name="frame_ancestors_wildcard",
                value="*",
            )
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Medium"


def test_allow_from_is_low(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.X_FRAME_OPTIONS_ALLOW_FROM,
                name="x_frame_options_allow_from",
                value="ALLOW-FROM https://example.com",
            )
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Low"


def test_safe_deny_is_info(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.X_FRAME_OPTIONS_DENY,
                name="x_frame_options_deny",
                value="DENY",
            )
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Info"


def test_safe_sameorigin_is_info(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.X_FRAME_OPTIONS_SAMEORIGIN,
                name="x_frame_options_sameorigin",
                value="SAMEORIGIN",
            )
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Info"


def test_target_preserved(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                name="missing_x_frame_options",
            )
        ),
        target="https://target.example",
    )

    assert result[0].target == "https://target.example"


def test_endpoint_preserved(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                name="missing_x_frame_options",
            )
        ),
        target="https://example.com",
        endpoint="/login",
    )

    assert result[0].endpoint == "/login"


def test_indicator_value_is_in_evidence(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS,
                name="invalid_x_frame_options",
                value="INVALID",
            )
        ),
        target="https://example.com",
    )

    assert "INVALID" in result[0].evidence


def test_description_does_not_claim_exploitability(
    analyzer,
):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                name="missing_x_frame_options",
            )
        ),
        target="https://example.com",
    )

    assert "does not prove" in result[0].description


def test_remediation_mentions_frame_policy(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                name="missing_x_frame_options",
            )
        ),
        target="https://example.com",
    )

    assert "frame-ancestors" in result[0].remediation


def test_multiple_indicators_create_multiple_findings(
    analyzer,
):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                name="missing_x_frame_options",
            ),
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS,
                name="missing_frame_ancestors",
            ),
        ),
        target="https://example.com",
    )

    assert len(result) == 2


def test_findings_have_unique_ids(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                name="missing_x_frame_options",
            ),
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS,
                name="missing_frame_ancestors",
            ),
        ),
        target="https://example.com",
    )

    assert result[0].id != result[1].id


def test_all_findings_are_open(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                name="missing_x_frame_options",
            )
        ),
        target="https://example.com",
    )

    assert result[0].status == "open"


def test_all_findings_use_a05(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD,
                name="frame_ancestors_wildcard",
                value="*",
            )
        ),
        target="https://example.com",
    )

    assert result[0].owasp == "A05:2021"


def test_invalid_analysis_is_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            object(),
            target="https://example.com",
        )


def test_safe_frame_ancestors_none_has_info_severity(
    analyzer,
):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.FRAME_ANCESTORS_NONE,
                name="frame_ancestors_none",
                value="'none'",
            )
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Info"


def test_safe_frame_ancestors_self_has_info_severity(
    analyzer,
):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.FRAME_ANCESTORS_SELF,
                name="frame_ancestors_self",
                value="'self'",
            )
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Info"


def test_csp_present_has_info_severity(analyzer):
    result = analyzer.analyze(
        make_analysis(
            ClickjackingIndicator(
                type=ClickjackingIndicatorType.CSP_PRESENT,
                name="csp_present",
                value="default-src 'self'",
            )
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Info"
