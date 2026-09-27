import pytest

from m_hunter.analyzers.referrer_policy import (
    ReferrerPolicyAnalysis,
    ReferrerPolicyIndicator,
    ReferrerPolicyIndicatorType,
)
from m_hunter.analyzers.referrer_policy_finding import (
    ReferrerPolicyFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def make_analysis(*types):
    indicators = tuple(
        ReferrerPolicyIndicator(
            type=indicator_type,
            evidence=f"evidence: {indicator_type.value}",
            value=indicator_type.value,
        )
        for indicator_type in types
    )

    unique_types = tuple(dict.fromkeys(types))

    return ReferrerPolicyAnalysis(
        detected=bool(indicators),
        indicators=indicators,
        count=len(indicators),
        types=unique_types,
        names=tuple(
            item.value for item in unique_types
        ),
    )


@pytest.fixture
def analyzer():
    return ReferrerPolicyFindingAnalyzer()


def test_analyzer_name(analyzer):
    assert analyzer.name == "referrer_policy_finding"


def test_requires_analysis(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            object(),
            target="https://example.com",
        )


def test_requires_target(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            make_analysis(
                ReferrerPolicyIndicatorType.UNSAFE_URL
            ),
            target="",
        )


def test_rejects_invalid_endpoint(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            make_analysis(
                ReferrerPolicyIndicatorType.UNSAFE_URL
            ),
            target="https://example.com",
            endpoint=123,
        )


@pytest.mark.parametrize(
    "indicator_type",
    list(ReferrerPolicyIndicatorType),
)
def test_all_indicators_have_metadata(
    analyzer,
    indicator_type,
):
    assert indicator_type in analyzer.METADATA
    assert indicator_type in analyzer.TITLES


@pytest.mark.parametrize(
    "indicator_type",
    [
        ReferrerPolicyIndicatorType.UNSAFE_URL,
        ReferrerPolicyIndicatorType.NO_REFERRER_WHEN_DOWNGRADE,
        ReferrerPolicyIndicatorType.INVALID_POLICY,
        ReferrerPolicyIndicatorType.MULTIPLE_POLICIES,
    ],
)
def test_security_findings_are_created(
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
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        target="https://target.example",
    )

    assert findings[0].target == (
        "https://target.example"
    )


def test_finding_preserves_endpoint(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        target="https://example.com",
        endpoint="/account",
    )

    assert findings[0].endpoint == "/account"


def test_indicator_value_is_in_evidence(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        target="https://example.com",
    )

    assert "value=unsafe_url" in findings[0].evidence


def test_unsafe_url_is_medium(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        target="https://example.com",
    )

    assert findings[0].severity == "Medium"
    assert findings[0].confidence == "High"


def test_missing_policy_is_low(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.POLICY_MISSING
        ),
        target="https://example.com",
    )

    assert findings[0].severity == "Low"


def test_policy_presence_is_info(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.POLICY_PRESENT
        ),
        target="https://example.com",
    )

    assert findings[0].severity == "Info"


def test_invalid_policy_is_medium(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.INVALID_POLICY
        ),
        target="https://example.com",
    )

    assert findings[0].severity == "Medium"


def test_multiple_policies_are_low(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.MULTIPLE_POLICIES
        ),
        target="https://example.com",
    )

    assert findings[0].severity == "Low"
    assert findings[0].confidence == "Medium"


def test_cwe_and_owasp_are_present(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        target="https://example.com",
    )

    assert findings[0].cwe == "CWE-200"
    assert findings[0].owasp == "A05:2021"


def test_description_is_conservative(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        target="https://example.com",
    )

    assert "does not by itself prove" in (
        findings[0].description
    )


def test_remediation_is_present(analyzer):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL
        ),
        target="https://example.com",
    )

    assert findings[0].remediation


def test_multiple_indicators_create_multiple_findings(
    analyzer,
):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.UNSAFE_URL,
            ReferrerPolicyIndicatorType.INVALID_POLICY,
            ReferrerPolicyIndicatorType.MULTIPLE_POLICIES,
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


def test_all_valid_policies_can_create_findings(
    analyzer,
):
    findings = analyzer.analyze(
        make_analysis(
            ReferrerPolicyIndicatorType.POLICY_PRESENT,
            ReferrerPolicyIndicatorType.UNSAFE_URL,
            ReferrerPolicyIndicatorType.NO_REFERRER_WHEN_DOWNGRADE,
            ReferrerPolicyIndicatorType.ORIGIN_WHEN_CROSS_ORIGIN,
            ReferrerPolicyIndicatorType.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
            ReferrerPolicyIndicatorType.SAME_ORIGIN,
            ReferrerPolicyIndicatorType.STRICT_ORIGIN,
            ReferrerPolicyIndicatorType.NO_REFERRER,
        ),
        target="https://example.com",
    )

    assert len(findings) == 8
    assert all(
        isinstance(finding, Finding)
        for finding in findings
    )
