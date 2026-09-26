from m_hunter.analyzers.web_cache_deception import (
    WebCacheDeceptionAnalyzer,
    WebCacheDeceptionIndicatorType,
)
from m_hunter.core.response import HttpResponse


def analyzer():
    return WebCacheDeceptionAnalyzer()


def test_empty_response():
    result = analyzer().analyze(headers={})

    assert result.detected is False
    assert result.count == 0
    assert result.types == []
    assert result.names == []


def test_cache_status_detected():
    result = analyzer().analyze(
        headers={"X-Cache": "HIT"},
    )

    assert result.has_type(WebCacheDeceptionIndicatorType.CACHE_STATUS)


def test_cache_header_detected():
    result = analyzer().analyze(
        headers={"Cache-Control": "public, max-age=3600"},
    )

    assert result.has_type(WebCacheDeceptionIndicatorType.CACHE_HEADER)


def test_cacheable_response_detected():
    result = analyzer().analyze(
        headers={"Cache-Control": "public, max-age=3600"},
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.CACHEABLE_RESPONSE
    )


def test_private_cache_directive():
    result = analyzer().analyze(
        headers={"Cache-Control": "private, no-store"},
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.PRIVATE_CONTENT
    )


def test_age_header():
    result = analyzer().analyze(
        headers={"Age": "120"},
    )

    assert result.has_type(WebCacheDeceptionIndicatorType.AGE_HEADER)


def test_vary_header():
    result = analyzer().analyze(
        headers={"Vary": "Accept-Encoding"},
    )

    assert result.has_type(WebCacheDeceptionIndicatorType.VARY_HEADER)


def test_static_extension():
    result = analyzer().analyze(
        url="https://example.com/account.css",
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.STATIC_EXTENSION
    )


def test_static_extension_case_insensitive():
    result = analyzer().analyze(
        url="https://example.com/account.CSS",
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.STATIC_EXTENSION
    )


def test_path_variation():
    result = analyzer().analyze(
        url="https://example.com/account.css/profile",
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.PATH_VARIATION
    )


def test_sensitive_path_marker():
    result = analyzer().analyze(
        url="https://example.com/account/profile",
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.SENSITIVE_CONTENT
    )


def test_sensitive_body_marker():
    result = analyzer().analyze(
        url="https://example.com/resource",
        response_body="User email: user@example.com",
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.SENSITIVE_CONTENT
    )


def test_content_type_mismatch():
    result = analyzer().analyze(
        url="https://example.com/account.css",
        headers={"Content-Type": "text/html"},
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH
    )


def test_matching_static_content_type():
    result = analyzer().analyze(
        url="https://example.com/style.css",
        headers={"Content-Type": "text/css"},
    )

    assert not result.has_type(
        WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH
    )


def test_javascript_content_type():
    result = analyzer().analyze(
        url="https://example.com/app.js",
        headers={"Content-Type": "application/javascript"},
    )

    assert not result.has_type(
        WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH
    )


def test_image_content_type():
    result = analyzer().analyze(
        url="https://example.com/image.png",
        headers={"Content-Type": "image/png"},
    )

    assert not result.has_type(
        WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH
    )


def test_query_string_does_not_break_extension_detection():
    result = analyzer().analyze(
        url="https://example.com/account.css?v=1",
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.STATIC_EXTENSION
    )


def test_http_response_input():
    response = HttpResponse(
        status_code=200,
        url="https://example.com/account.css",
        headers={
            "Content-Type": "text/html",
            "X-Cache": "HIT",
        },
        content=b"private account content",
        cookies={},
        response_time=0.1,
        content_length=22,
    )

    result = analyzer().analyze(response)

    assert result.detected is True
    assert result.has_type(
        WebCacheDeceptionIndicatorType.STATIC_EXTENSION
    )
    assert result.has_type(
        WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH
    )


def test_case_insensitive_headers():
    result = analyzer().analyze(
        headers={"x-cAcHe": "HIT"},
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.CACHE_STATUS
    )


def test_no_store_is_not_cacheable():
    result = analyzer().analyze(
        headers={"Cache-Control": "no-store"},
    )

    assert not result.has_type(
        WebCacheDeceptionIndicatorType.CACHEABLE_RESPONSE
    )


def test_private_is_not_cacheable():
    result = analyzer().analyze(
        headers={"Cache-Control": "private, max-age=3600"},
    )

    assert not result.has_type(
        WebCacheDeceptionIndicatorType.CACHEABLE_RESPONSE
    )


def test_s_maxage_is_cacheable():
    result = analyzer().analyze(
        headers={"Cache-Control": "s-maxage=3600"},
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.CACHEABLE_RESPONSE
    )


def test_multiple_indicators():
    result = analyzer().analyze(
        url="https://example.com/account.css",
        headers={
            "X-Cache": "HIT",
            "Cache-Control": "public, max-age=3600",
            "Age": "100",
            "Vary": "Accept-Encoding",
            "Content-Type": "text/html",
        },
        response_body="private account dashboard",
    )

    assert result.detected is True
    assert result.count >= 5


def test_indicator_types_are_unique():
    result = analyzer().analyze(
        headers={
            "X-Cache": "HIT",
            "X-Cache-Hits": "10",
        },
    )

    assert len(result.types) == len(set(result.types))


def test_indicator_names_are_unique():
    result = analyzer().analyze(
        headers={
            "X-Cache": "HIT",
        },
    )

    assert len(result.names) == len(set(result.names))


def test_has_type_false_for_missing_type():
    result = analyzer().analyze(
        headers={"X-Cache": "HIT"},
    )

    assert not result.has_type(
        WebCacheDeceptionIndicatorType.PATH_VARIATION
    )


def test_content_type_header_parsing():
    result = analyzer().analyze(
        url="https://example.com/account.css",
        headers={
            "Content-Type": "text/html; charset=utf-8",
        },
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH
    )


def test_custom_path():
    result = analyzer().analyze(
        path="/profile.js",
        headers={"Content-Type": "text/html"},
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.STATIC_EXTENSION
    )


def test_original_url_used_when_path_is_not_provided():
    result = analyzer().analyze(
        url="https://example.com/dashboard.js",
    )

    assert result.has_type(
        WebCacheDeceptionIndicatorType.STATIC_EXTENSION
    )
