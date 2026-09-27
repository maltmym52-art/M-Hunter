from m_hunter.analyzers.coep import (
    COEPAnalyzer,
    COEPIndicatorType,
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
    analysis = COEPAnalyzer().analyze(response())

    assert analysis.detected
    assert analysis.has_type(
        COEPIndicatorType.POLICY_MISSING
    )


def test_policy_present():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "require-corp"
            }
        )
    )

    assert analysis.has_type(
        COEPIndicatorType.POLICY_PRESENT
    )


def test_require_corp():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "require-corp"
            }
        )
    )

    assert analysis.has_type(
        COEPIndicatorType.REQUIRE_CORP
    )


def test_credentialless():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "credentialless"
            }
        )
    )

    assert analysis.has_type(
        COEPIndicatorType.CREDENTIALLESS
    )


def test_unsafe_none():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "unsafe-none"
            }
        )
    )

    assert analysis.has_type(
        COEPIndicatorType.UNSAFE_NONE
    )


def test_invalid_policy():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "invalid-policy"
            }
        )
    )

    assert analysis.has_type(
        COEPIndicatorType.INVALID_POLICY
    )


def test_multiple_header_values():
    response_obj = HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers={
            "Cross-Origin-Embedder-Policy":
                "require-corp",
        },
        content=b"ok",
        cookies={},
        response_time=0.1,
        content_length=2,
        repeated_headers={
            "Cross-Origin-Embedder-Policy":
                ["unsafe-none"],
        },
    )

    analysis = COEPAnalyzer().analyze(response_obj)

    assert analysis.has_type(
        COEPIndicatorType.MULTIPLE_POLICIES
    )


def test_multiple_policy_tokens():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "require-corp, credentialless"
            }
        )
    )

    assert analysis.has_type(
        COEPIndicatorType.REQUIRE_CORP
    )
    assert analysis.has_type(
        COEPIndicatorType.CREDENTIALLESS
    )


def test_policy_case_insensitive():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "Require-Corp"
            }
        )
    )

    assert analysis.has_type(
        COEPIndicatorType.REQUIRE_CORP
    )


def test_whitespace_is_ignored():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "  require-corp  "
            }
        )
    )

    assert analysis.has_type(
        COEPIndicatorType.REQUIRE_CORP
    )


def test_count():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "require-corp"
            }
        )
    )

    assert analysis.count >= 2


def test_types():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "require-corp"
            }
        )
    )

    assert COEPIndicatorType.REQUIRE_CORP in analysis.types


def test_names():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "require-corp"
            }
        )
    )

    assert "require-corp" in analysis.names


def test_empty_header_value():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    ""
            }
        )
    )

    assert analysis.has_type(
        COEPIndicatorType.POLICY_PRESENT
    )


def test_invalid_response_type():
    try:
        COEPAnalyzer().analyze(object())
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_policy_value_preserved():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "require-corp"
            }
        )
    )

    matches = [
        indicator
        for indicator in analysis.indicators
        if indicator.type
        == COEPIndicatorType.REQUIRE_CORP
    ]

    assert matches[0].value == "require-corp"


def test_invalid_value_preserved():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "bad-policy"
            }
        )
    )

    matches = [
        indicator
        for indicator in analysis.indicators
        if indicator.type
        == COEPIndicatorType.INVALID_POLICY
    ]

    assert matches[0].value == "bad-policy"


def test_missing_policy_is_detected():
    analysis = COEPAnalyzer().analyze(response())

    assert analysis.detected is True
    assert analysis.count == 1


def test_valid_policies_do_not_create_invalid_indicator():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "require-corp"
            }
        )
    )

    assert not analysis.has_type(
        COEPIndicatorType.INVALID_POLICY
    )


def test_credentialless_value_preserved():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "credentialless"
            }
        )
    )

    matches = [
        indicator
        for indicator in analysis.indicators
        if indicator.type
        == COEPIndicatorType.CREDENTIALLESS
    ]

    assert matches[0].value == "credentialless"


def test_unsafe_none_value_preserved():
    analysis = COEPAnalyzer().analyze(
        response(
            {
                "Cross-Origin-Embedder-Policy":
                    "unsafe-none"
            }
        )
    )

    matches = [
        indicator
        for indicator in analysis.indicators
        if indicator.type
        == COEPIndicatorType.UNSAFE_NONE
    ]

    assert matches[0].value == "unsafe-none"
