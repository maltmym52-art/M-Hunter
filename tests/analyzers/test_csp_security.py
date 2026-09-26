import pytest

from m_hunter.analyzers.csp_security import (
    CSPAnalysis,
    CSPIndicatorType,
    CSPSecurityAnalyzer,
)
from m_hunter.core.response import HttpResponse


def make_response(
    headers=None,
    status_code=200,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/",
        headers=headers or {},
        content=b"<html></html>",
        cookies={},
        response_time=0.1,
        content_length=13,
    )


@pytest.fixture
def analyzer():
    return CSPSecurityAnalyzer()


def test_analyzer_name(analyzer):
    assert analyzer.name == "csp_security"


def test_requires_http_response(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(object())


def test_no_csp_returns_clean_analysis(analyzer):
    analysis = analyzer.analyze(
        make_response()
    )

    assert isinstance(analysis, CSPAnalysis)
    assert analysis.detected is False
    assert analysis.count == 0


def test_detects_csp(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy": "default-src 'self'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.CSP_PRESENT
    )


def test_detects_report_only(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy-Report-Only":
                "default-src 'self'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.CSP_REPORT_ONLY
    )


@pytest.mark.parametrize(
    "policy,indicator",
    [
        (
            "default-src *",
            CSPIndicatorType.WILDCARD_SOURCE,
        ),
        (
            "script-src 'unsafe-inline'",
            CSPIndicatorType.UNSAFE_INLINE,
        ),
        (
            "script-src 'unsafe-eval'",
            CSPIndicatorType.UNSAFE_EVAL,
        ),
        (
            "script-src 'unsafe-hashes'",
            CSPIndicatorType.UNSAFE_HASHES,
        ),
        (
            "script-src 'nonce-test'",
            CSPIndicatorType.NONCE_SOURCE,
        ),
        (
            "img-src data:",
            CSPIndicatorType.DATA_SOURCE,
        ),
        (
            "img-src blob:",
            CSPIndicatorType.BLOB_SOURCE,
        ),
    ],
)
def test_detects_source_indicators(
    analyzer,
    policy,
    indicator,
):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy": policy
        })
    )

    assert analysis.has_type(indicator)


def test_detects_object_none(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'; object-src 'none'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.OBJECT_NONE
    )


def test_detects_base_none(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'; base-uri 'none'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.BASE_NONE
    )


def test_detects_frame_ancestors_none(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'; frame-ancestors 'none'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.FRAME_ANCESTORS_NONE
    )


def test_detects_frame_ancestors_wildcard(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'; frame-ancestors *"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.FRAME_ANCESTORS_WILDCARD
    )


def test_detects_missing_script_src(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.SCRIPT_SRC_MISSING
    )


def test_detects_missing_default_src(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "script-src 'self'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.DEFAULT_SRC_MISSING
    )


def test_detects_script_wildcard(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'; script-src *"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.SCRIPT_SRC_WILDCARD
    )


def test_detects_connect_wildcard(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'; connect-src *"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.CONNECT_SRC_WILDCARD
    )


def test_detects_img_wildcard(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'; img-src *"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.IMG_SRC_WILDCARD
    )


def test_detects_style_wildcard(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'; style-src *"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.STYLE_SRC_WILDCARD
    )


def test_detects_missing_form_action(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.FORM_ACTION_MISSING
    )


def test_detects_missing_upgrade_directive(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.UPGRADE_INSECURE_REQUESTS_MISSING
    )


def test_detects_missing_mixed_content_directive(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.BLOCK_ALL_MIXED_CONTENT_MISSING
    )


def test_secure_policy_produces_expected_structure(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'; "
                "script-src 'self'; "
                "object-src 'none'; "
                "base-uri 'none'; "
                "frame-ancestors 'none'; "
                "form-action 'self'; "
                "upgrade-insecure-requests; "
                "block-all-mixed-content"
        })
    )

    assert analysis.detected is True
    assert analysis.count == len(analysis.indicators)
    assert len(analysis.types) == len(analysis.names)
    assert analysis.has_type(
        CSPIndicatorType.CSP_PRESENT
    )


def test_multiple_indicators_are_detected(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src *; "
                "script-src * 'unsafe-inline' 'unsafe-eval'; "
                "img-src data: blob:"
        })
    )

    assert analysis.count >= 7
    assert analysis.has_type(
        CSPIndicatorType.WILDCARD_SOURCE
    )
    assert analysis.has_type(
        CSPIndicatorType.UNSAFE_INLINE
    )
    assert analysis.has_type(
        CSPIndicatorType.UNSAFE_EVAL
    )
    assert analysis.has_type(
        CSPIndicatorType.DATA_SOURCE
    )
    assert analysis.has_type(
        CSPIndicatorType.BLOB_SOURCE
    )


def test_indicator_values_are_preserved(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "script-src 'unsafe-inline'"
        })
    )

    indicator = next(
        item
        for item in analysis.indicators
        if item.type == CSPIndicatorType.UNSAFE_INLINE
    )

    assert indicator.value == "'unsafe-inline'"


def test_has_type_false_for_missing_indicator(analyzer):
    analysis = analyzer.analyze(
        make_response({
            "Content-Security-Policy":
                "default-src 'self'"
        })
    )

    assert analysis.has_type(
        CSPIndicatorType.UNSAFE_EVAL
    ) is False
