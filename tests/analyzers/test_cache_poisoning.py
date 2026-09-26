from m_hunter.analyzers.cache_poisoning import (
    CachePoisoningAnalyzer,
    CachePoisoningIndicatorType,
)
from m_hunter.core.response import HttpResponse


def analyzer():
    return CachePoisoningAnalyzer()


def test_empty_response():
    result = analyzer().analyze(headers={})

    assert result.detected is False
    assert result.count == 0
    assert result.types == []
    assert result.names == []
    assert result.indicators == []


def test_x_cache_detected():
    result = analyzer().analyze(
        headers={"X-Cache": "HIT"},
    )

    assert result.detected is True
    assert result.has_type(CachePoisoningIndicatorType.CACHE_STATUS)
    assert "x-cache" in result.names


def test_cloudflare_cache_status_detected():
    result = analyzer().analyze(
        headers={"CF-Cache-Status": "HIT"},
    )

    assert result.has_type(CachePoisoningIndicatorType.CACHE_STATUS)


def test_cache_control_detected():
    result = analyzer().analyze(
        headers={"Cache-Control": "public, max-age=3600"},
    )

    assert result.has_type(CachePoisoningIndicatorType.CACHE_CONTROL)


def test_surrogate_control_detected():
    result = analyzer().analyze(
        headers={"Surrogate-Control": "max-age=3600"},
    )

    assert result.has_type(CachePoisoningIndicatorType.CACHE_CONTROL)


def test_age_detected():
    result = analyzer().analyze(
        headers={"Age": "120"},
    )

    assert result.has_type(CachePoisoningIndicatorType.AGE_HEADER)


def test_etag_detected():
    result = analyzer().analyze(
        headers={"ETag": '"abc123"'},
    )

    assert result.has_type(CachePoisoningIndicatorType.ETAG_HEADER)


def test_vary_detected():
    result = analyzer().analyze(
        headers={"Vary": "Accept-Encoding"},
    )

    assert result.has_type(CachePoisoningIndicatorType.VARY_HEADER)
    assert result.has_type(CachePoisoningIndicatorType.CACHE_KEY_INDICATOR)


def test_cache_key_headers_detected():
    result = analyzer().analyze(
        headers={
            "Cache-Control": "public",
            "Vary": "Accept-Encoding",
        },
    )

    assert result.has_type(CachePoisoningIndicatorType.CACHE_KEY_INDICATOR)


def test_response_body_variation():
    result = analyzer().analyze(
        baseline_body="normal response",
        candidate_body="different response",
    )

    assert result.detected is True
    assert result.has_type(CachePoisoningIndicatorType.RESPONSE_VARIATION)


def test_identical_response_body_no_variation():
    result = analyzer().analyze(
        baseline_body="same response",
        candidate_body="same response",
    )

    assert result.detected is False


def test_response_header_variation():
    result = analyzer().analyze(
        baseline_headers={"Content-Type": "text/html"},
        candidate_headers={"Content-Type": "application/json"},
    )

    assert result.has_type(CachePoisoningIndicatorType.RESPONSE_VARIATION)


def test_identical_response_headers_no_variation():
    result = analyzer().analyze(
        baseline_headers={"Content-Type": "text/html"},
        candidate_headers={"Content-Type": "text/html"},
    )

    assert result.detected is False


def test_unkeyed_input_marker():
    result = analyzer().analyze(
        response_body="Request received from X-Forwarded-Host",
    )

    assert result.has_type(CachePoisoningIndicatorType.UNKEYED_INPUT)


def test_original_url_marker():
    result = analyzer().analyze(
        response_body="processed X-Original-URL value",
    )

    assert result.has_type(CachePoisoningIndicatorType.UNKEYED_INPUT)


def test_rewrite_url_marker():
    result = analyzer().analyze(
        response_body="X-Rewrite-URL was observed",
    )

    assert result.has_type(CachePoisoningIndicatorType.UNKEYED_INPUT)


def test_multiple_cache_indicators():
    result = analyzer().analyze(
        headers={
            "X-Cache": "MISS",
            "Cache-Control": "public",
            "Age": "10",
            "ETag": '"abc"',
            "Vary": "Accept-Encoding",
        },
    )

    assert result.detected is True
    assert result.count >= 5
    assert result.has_type(CachePoisoningIndicatorType.CACHE_STATUS)
    assert result.has_type(CachePoisoningIndicatorType.CACHE_CONTROL)
    assert result.has_type(CachePoisoningIndicatorType.AGE_HEADER)
    assert result.has_type(CachePoisoningIndicatorType.ETAG_HEADER)
    assert result.has_type(CachePoisoningIndicatorType.VARY_HEADER)


def test_http_response_input():
    response = HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers={
            "Content-Type": "text/html",
            "X-Cache": "HIT",
        },
        content=b"hello",
        cookies={},
        response_time=0.1,
        content_length=5,
    )

    result = analyzer().analyze(response)

    assert result.detected is True
    assert result.has_type(CachePoisoningIndicatorType.CACHE_STATUS)


def test_case_insensitive_headers():
    result = analyzer().analyze(
        headers={"x-cAcHe": "HIT"},
    )

    assert result.has_type(CachePoisoningIndicatorType.CACHE_STATUS)


def test_duplicate_indicators_are_deduplicated():
    result = analyzer().analyze(
        headers={
            "X-Cache": "HIT",
        },
    )

    assert result.count == 1


def test_has_type_unknown():
    result = analyzer().analyze(headers={"X-Cache": "HIT"})

    assert result.has_type(CachePoisoningIndicatorType.CACHE_STATUS)
    assert not result.has_type(CachePoisoningIndicatorType.UNKEYED_INPUT)


def test_analysis_types_are_unique():
    result = analyzer().analyze(
        headers={
            "X-Cache": "HIT",
            "X-Cache-Hits": "10",
        },
    )

    assert result.types.count(
        CachePoisoningIndicatorType.CACHE_STATUS.value
    ) == 1


def test_analysis_names_are_unique():
    result = analyzer().analyze(
        headers={
            "X-Cache": "HIT",
            "x-cache": "HIT",
        },
    )

    assert result.names.count("x-cache") == 1
