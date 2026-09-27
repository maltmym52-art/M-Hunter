from m_hunter.analyzers.coop import (
    COOPAnalyzer,
    COOPIndicatorType,
)
from m_hunter.core.response import HttpResponse


def response(headers=None):
    return HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers=headers or {},
        content=b"ok",
        cookies={},
        response_time=0.1,
        content_length=2,
    )


def test_missing_policy():
    analysis = COOPAnalyzer().analyze(response())

    assert analysis.detected
    assert analysis.has_type(
        COOPIndicatorType.POLICY_MISSING
    )


def test_policy_present():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin"
            }
        )
    )

    assert analysis.has_type(
        COOPIndicatorType.POLICY_PRESENT
    )


def test_same_origin():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin"
            }
        )
    )

    assert analysis.has_type(
        COOPIndicatorType.SAME_ORIGIN
    )


def test_same_origin_allow_popups():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin-allow-popups"
            }
        )
    )

    assert analysis.has_type(
        COOPIndicatorType.SAME_ORIGIN_ALLOW_POPUPS
    )


def test_unsafe_none():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "unsafe-none"
            }
        )
    )

    assert analysis.has_type(
        COOPIndicatorType.UNSAFE_NONE
    )


def test_invalid_policy():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "invalid-policy"
            }
        )
    )

    assert analysis.has_type(
        COOPIndicatorType.INVALID_POLICY
    )


def test_multiple_header_values():
    response_obj = HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers={
            "Cross-Origin-Opener-Policy":
                "same-origin",
        },
        content=b"ok",
        cookies={},
        response_time=0.1,
        content_length=2,
        repeated_headers={
            "Cross-Origin-Opener-Policy":
                ["unsafe-none"],
        },
    )

    analysis = COOPAnalyzer().analyze(response_obj)

    assert analysis.has_type(
        COOPIndicatorType.MULTIPLE_POLICIES
    )


def test_multiple_policy_tokens():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin, unsafe-none"
            }
        )
    )

    assert analysis.has_type(
        COOPIndicatorType.SAME_ORIGIN
    )
    assert analysis.has_type(
        COOPIndicatorType.UNSAFE_NONE
    )


def test_policy_case_insensitive():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "Same-Origin"
            }
        )
    )

    assert analysis.has_type(
        COOPIndicatorType.SAME_ORIGIN
    )


def test_whitespace_is_ignored():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "  same-origin  "
            }
        )
    )

    assert analysis.has_type(
        COOPIndicatorType.SAME_ORIGIN
    )


def test_count():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin"
            }
        )
    )

    assert analysis.count >= 2


def test_types():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin"
            }
        )
    )

    assert COOPIndicatorType.SAME_ORIGIN in analysis.types


def test_names():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin"
            }
        )
    )

    assert "same-origin" in analysis.names


def test_empty_header_value():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    ""
            }
        )
    )

    assert analysis.has_type(
        COOPIndicatorType.POLICY_PRESENT
    )


def test_invalid_response_type():
    try:
        COOPAnalyzer().analyze(object())
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_header_lookup_is_case_insensitive():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin"
            }
        )
    )

    assert analysis.detected is True


def test_policy_value_preserved():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin"
            }
        )
    )

    policy_indicators = [
        indicator
        for indicator in analysis.indicators
        if indicator.type == COOPIndicatorType.SAME_ORIGIN
    ]

    assert policy_indicators[0].value == "same-origin"


def test_invalid_value_preserved():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "bad-policy"
            }
        )
    )

    invalid = [
        indicator
        for indicator in analysis.indicators
        if indicator.type == COOPIndicatorType.INVALID_POLICY
    ]

    assert invalid[0].value == "bad-policy"


def test_policy_missing_is_detected():
    analysis = COOPAnalyzer().analyze(response())

    assert analysis.detected is True
    assert analysis.count == 1


def test_valid_policies_do_not_create_invalid_indicator():
    analysis = COOPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Opener-Policy":
                    "same-origin"
            }
        )
    )

    assert not analysis.has_type(
        COOPIndicatorType.INVALID_POLICY
    )
