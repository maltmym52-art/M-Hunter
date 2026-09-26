import pytest

from m_hunter.analyzers.clickjacking import (
    ClickjackingAnalysis,
    ClickjackingAnalyzer,
    ClickjackingIndicatorType,
)
from m_hunter.core.response import HttpResponse


def make_response(
    *,
    headers=None,
    content=b"test",
):
    return HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def analyzer():
    return ClickjackingAnalyzer()


def test_analyzer_can_be_created(analyzer):
    assert isinstance(analyzer, ClickjackingAnalyzer)


def test_requires_http_response(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze("invalid")


def test_missing_x_frame_options(analyzer):
    result = analyzer.analyze(
        make_response()
    )

    assert isinstance(result, ClickjackingAnalysis)
    assert result.has_type(
        ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS
    )


def test_x_frame_options_deny(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "X-Frame-Options": "DENY",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.X_FRAME_OPTIONS_DENY
    )


def test_x_frame_options_sameorigin(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "X-Frame-Options": "SAMEORIGIN",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.X_FRAME_OPTIONS_SAMEORIGIN
    )


def test_x_frame_options_allow_from(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "X-Frame-Options": "ALLOW-FROM https://example.com",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.X_FRAME_OPTIONS_ALLOW_FROM
    )


def test_invalid_x_frame_options(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "X-Frame-Options": "INVALID",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS
    )


def test_csp_present(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy": "default-src 'self'",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.CSP_PRESENT
    )


def test_missing_frame_ancestors(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy": "default-src 'self'",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS
    )


def test_frame_ancestors_none(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy":
                    "default-src 'self'; frame-ancestors 'none'",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.FRAME_ANCESTORS_NONE
    )


def test_frame_ancestors_self(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy":
                    "frame-ancestors 'self'",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.FRAME_ANCESTORS_SELF
    )


def test_frame_ancestors_wildcard(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy":
                    "frame-ancestors *",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD
    )


def test_frame_ancestors_origin(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy":
                    "frame-ancestors https://trusted.example",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.FRAME_ANCESTORS_ORIGIN
    )


def test_case_insensitive_headers(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "x-frame-options": "DENY",
                "content-security-policy":
                    "frame-ancestors 'none'",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.X_FRAME_OPTIONS_DENY
    )
    assert result.has_type(
        ClickjackingIndicatorType.FRAME_ANCESTORS_NONE
    )


def test_frame_ancestors_is_parsed_among_other_directives(
    analyzer,
):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy":
                    "default-src 'self'; "
                    "script-src 'self'; "
                    "frame-ancestors 'none'; "
                    "img-src 'self'",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.FRAME_ANCESTORS_NONE
    )


def test_frame_ancestors_is_case_insensitive(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy":
                    "FRAME-ANCESTORS 'none'",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.FRAME_ANCESTORS_NONE
    )


def test_multiple_origins_are_detected(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy":
                    "frame-ancestors "
                    "https://a.example https://b.example",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.FRAME_ANCESTORS_ORIGIN
    )


def test_analysis_count_matches(analyzer):
    result = analyzer.analyze(
        make_response()
    )

    assert result.count == len(result.indicators)


def test_types_are_unique(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "X-Frame-Options": "DENY",
                "Content-Security-Policy":
                    "frame-ancestors 'none'",
            }
        )
    )

    assert len(result.types) == len(set(result.types))


def test_names_are_unique(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "X-Frame-Options": "DENY",
                "Content-Security-Policy":
                    "frame-ancestors 'none'",
            }
        )
    )

    assert len(result.names) == len(set(result.names))


def test_empty_csp_has_missing_frame_ancestors(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Content-Security-Policy": "",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS
    )


def test_xfo_and_csp_are_both_analyzed(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Security-Policy":
                    "frame-ancestors 'self'",
            }
        )
    )

    assert result.has_type(
        ClickjackingIndicatorType.X_FRAME_OPTIONS_SAMEORIGIN
    )
    assert result.has_type(
        ClickjackingIndicatorType.FRAME_ANCESTORS_SELF
    )


def test_detected_is_true_when_indicators_exist(analyzer):
    result = analyzer.analyze(
        make_response()
    )

    assert result.detected is True


def test_values_are_preserved(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "X-Frame-Options": "DENY",
            }
        )
    )

    indicator = next(
        indicator
        for indicator in result.indicators
        if indicator.type
        == ClickjackingIndicatorType.X_FRAME_OPTIONS_DENY
    )

    assert indicator.value == "DENY"
