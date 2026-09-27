import pytest

from m_hunter.analyzers.corp import (
    CORPAnalysis,
    CORPAnalyzer,
    CORPIndicator,
    CORPIndicatorType,
)
from m_hunter.core.response import HttpResponse


def response(
    headers=None,
    *,
    repeated_headers=None,
    status_code=200,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com",
        headers=headers or {},
        content=b"OK",
        cookies={},
        response_time=0.1,
        content_length=2,
        repeated_headers=repeated_headers or {},
    )


def test_name():
    assert CORPAnalyzer.name == "corp"


def test_description():
    assert "Cross-Origin-Resource-Policy" in CORPAnalyzer.description


def test_analysis_type():
    result = CORPAnalyzer().analyze(response())

    assert isinstance(result, CORPAnalysis)


def test_missing_policy_detected():
    result = CORPAnalyzer().analyze(response())

    assert result.detected
    assert result.has_type(CORPIndicatorType.POLICY_MISSING)


def test_present_policy():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "same-origin",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.POLICY_PRESENT)
    assert result.has_type(CORPIndicatorType.SAME_ORIGIN)


def test_same_site():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "same-site",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.SAME_SITE)


def test_cross_origin():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "cross-origin",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.CROSS_ORIGIN)


def test_case_insensitive_policy():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "SaMe-OrIgIn",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.SAME_ORIGIN)


def test_header_name_case_insensitive():
    result = CORPAnalyzer().analyze(
        response(
            {
                "cross-origin-resource-policy": "same-site",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.SAME_SITE)


def test_invalid_policy():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "invalid-policy",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.INVALID_POLICY)


def test_empty_policy():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.INVALID_POLICY)


def test_multiple_headers():
    result = CORPAnalyzer().analyze(
        response(
            repeated_headers={
                "Cross-Origin-Resource-Policy": [
                    "same-origin",
                    "cross-origin",
                ]
            }
        )
    )

    assert result.has_type(CORPIndicatorType.POLICY_PRESENT)
    assert result.has_type(CORPIndicatorType.MULTIPLE_POLICIES)
    assert result.has_type(CORPIndicatorType.SAME_ORIGIN)
    assert result.has_type(CORPIndicatorType.CROSS_ORIGIN)


def test_multiple_policy_tokens():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy":
                    "same-origin, cross-origin",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.SAME_ORIGIN)
    assert result.has_type(CORPIndicatorType.CROSS_ORIGIN)


def test_whitespace_is_ignored():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy":
                    "  same-site  ",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.SAME_SITE)


def test_count():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "same-origin",
            }
        )
    )

    assert result.count == 2


def test_types():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "same-origin",
            }
        )
    )

    assert CORPIndicatorType.POLICY_PRESENT in result.types
    assert CORPIndicatorType.SAME_ORIGIN in result.types


def test_names():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "same-origin",
            }
        )
    )

    assert "Cross-Origin-Resource-Policy same-origin" in result.names


def test_indicator_value():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy": "same-origin",
            }
        )
    )

    same_origin = next(
        indicator
        for indicator in result.indicators
        if indicator.type == CORPIndicatorType.SAME_ORIGIN
    )

    assert same_origin.value == "same-origin"


def test_missing_indicator_value():
    result = CORPAnalyzer().analyze(response())

    missing = next(
        indicator
        for indicator in result.indicators
        if indicator.type == CORPIndicatorType.POLICY_MISSING
    )

    assert missing.value is None


def test_all_known_policies():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy":
                    "same-origin, same-site, cross-origin",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.SAME_ORIGIN)
    assert result.has_type(CORPIndicatorType.SAME_SITE)
    assert result.has_type(CORPIndicatorType.CROSS_ORIGIN)


def test_mixed_valid_invalid():
    result = CORPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Resource-Policy":
                    "same-origin, invalid",
            }
        )
    )

    assert result.has_type(CORPIndicatorType.SAME_ORIGIN)
    assert result.has_type(CORPIndicatorType.INVALID_POLICY)


def test_invalid_response_type():
    with pytest.raises(TypeError):
        CORPAnalyzer().analyze(object())


def test_indicator_is_frozen():
    indicator = CORPIndicator(
        type=CORPIndicatorType.SAME_ORIGIN,
        name="test",
        value="same-origin",
    )

    with pytest.raises(Exception):
        indicator.value = "changed"


def test_analysis_is_frozen():
    result = CORPAnalyzer().analyze(response())

    with pytest.raises(Exception):
        result.detected = False
