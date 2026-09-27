import pytest

from m_hunter.analyzers.referrer_policy import (
    ReferrerPolicyAnalysis,
    ReferrerPolicyAnalyzer,
    ReferrerPolicyIndicatorType,
)
from m_hunter.core.response import HttpResponse


def make_response(headers=None):
    return HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers=headers or {},
        content=b"<html></html>",
        cookies={},
        response_time=0.1,
        content_length=13,
    )


@pytest.fixture
def analyzer():
    return ReferrerPolicyAnalyzer()


def test_analyzer_name(analyzer):
    assert analyzer.name == "referrer_policy"


def test_requires_http_response(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(object())


def test_missing_policy(analyzer):
    analysis = analyzer.analyze(
        make_response()
    )

    assert isinstance(
        analysis,
        ReferrerPolicyAnalysis,
    )
    assert analysis.has_type(
        ReferrerPolicyIndicatorType.POLICY_MISSING
    )


def test_policy_present(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy": "strict-origin-when-cross-origin"
        })
    )

    assert analysis.has_type(
        ReferrerPolicyIndicatorType.POLICY_PRESENT
    )


@pytest.mark.parametrize(
    "policy,indicator",
    [
        (
            "unsafe-url",
            ReferrerPolicyIndicatorType.UNSAFE_URL,
        ),
        (
            "no-referrer-when-downgrade",
            ReferrerPolicyIndicatorType.NO_REFERRER_WHEN_DOWNGRADE,
        ),
        (
            "origin-when-cross-origin",
            ReferrerPolicyIndicatorType.ORIGIN_WHEN_CROSS_ORIGIN,
        ),
        (
            "strict-origin-when-cross-origin",
            ReferrerPolicyIndicatorType.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
        ),
        (
            "same-origin",
            ReferrerPolicyIndicatorType.SAME_ORIGIN,
        ),
        (
            "strict-origin",
            ReferrerPolicyIndicatorType.STRICT_ORIGIN,
        ),
        (
            "no-referrer",
            ReferrerPolicyIndicatorType.NO_REFERRER,
        ),
    ],
)
def test_detects_policy_values(
    analyzer,
    policy,
    indicator,
):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy": policy
        })
    )

    assert analysis.has_type(indicator)


def test_detects_invalid_policy(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy": "invalid-policy"
        })
    )

    assert analysis.has_type(
        ReferrerPolicyIndicatorType.INVALID_POLICY
    )


def test_detects_multiple_policy_values(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy":
                "unsafe-url, no-referrer"
        })
    )

    assert analysis.has_type(
        ReferrerPolicyIndicatorType.MULTIPLE_POLICIES
    )


def test_detects_multiple_header_values(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy":
                "unsafe-url, strict-origin"
        })
    )

    assert analysis.has_type(
        ReferrerPolicyIndicatorType.MULTIPLE_POLICIES
    )


def test_policy_values_are_case_insensitive(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy":
                "Strict-Origin-When-Cross-Origin"
        })
    )

    assert analysis.has_type(
        ReferrerPolicyIndicatorType
        .STRICT_ORIGIN_WHEN_CROSS_ORIGIN
    )


def test_whitespace_is_ignored(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy":
                "  strict-origin  "
        })
    )

    assert analysis.has_type(
        ReferrerPolicyIndicatorType.STRICT_ORIGIN
    )


def test_multiple_valid_policies_are_detected(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy":
                "unsafe-url, strict-origin"
        })
    )

    assert analysis.has_type(
        ReferrerPolicyIndicatorType.UNSAFE_URL
    )
    assert analysis.has_type(
        ReferrerPolicyIndicatorType.STRICT_ORIGIN
    )


def test_invalid_and_valid_policy_are_both_detected(
    analyzer,
):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy":
                "strict-origin, invalid-policy"
        })
    )

    assert analysis.has_type(
        ReferrerPolicyIndicatorType.STRICT_ORIGIN
    )
    assert analysis.has_type(
        ReferrerPolicyIndicatorType.INVALID_POLICY
    )


def test_indicator_value_is_preserved(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy": "unsafe-url"
        })
    )

    indicator = next(
        item
        for item in analysis.indicators
        if item.type
        == ReferrerPolicyIndicatorType.UNSAFE_URL
    )

    assert indicator.value == "unsafe-url"


def test_names_match_types(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy": "unsafe-url"
        })
    )

    assert len(analysis.types) == len(analysis.names)
    assert tuple(
        item.value
        for item in analysis.types
    ) == analysis.names


def test_count_matches_indicators(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy":
                "unsafe-url, strict-origin"
        })
    )

    assert analysis.count == len(
        analysis.indicators
    )


def test_has_type_returns_false_when_absent(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy": "strict-origin"
        })
    )

    assert analysis.has_type(
        ReferrerPolicyIndicatorType.UNSAFE_URL
    ) is False


def test_secure_policy_structure(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Referrer-Policy":
                "strict-origin-when-cross-origin"
        })
    )

    assert analysis.detected is True
    assert analysis.count >= 2
    assert analysis.has_type(
        ReferrerPolicyIndicatorType.POLICY_PRESENT
    )
    assert analysis.has_type(
        ReferrerPolicyIndicatorType
        .STRICT_ORIGIN_WHEN_CROSS_ORIGIN
    )
