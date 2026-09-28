from m_hunter.analyzers.web_cache_key_security import (
    WebCacheKeyIndicatorType,
    WebCacheKeySecurityAnalyzer,
)
from m_hunter.core.response import HttpResponse


def make_response(headers=None):
    return HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers=headers or {},
        content=b"ok",
        cookies={},
        response_time=0.0,
        content_length=len(b"ok"),
    )


def test_cacheable_response():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(),
        cacheable=True,
    )

    assert analysis.has_type(
        WebCacheKeyIndicatorType.CACHEABLE_RESPONSE
    )


def test_cache_key_and_unkeyed_parameters():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(),
        request_url="https://example.com/?id=1&debug=true",
        cache_key_parameters={"id"},
        unkeyed_parameters={"debug"},
    )

    assert analysis.has_type(
        WebCacheKeyIndicatorType.CACHE_KEY_QUERY_PARAMETER
    )
    assert analysis.has_type(
        WebCacheKeyIndicatorType.UNKEYED_QUERY_PARAMETER
    )


def test_sensitive_parameter():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(),
        request_url="https://example.com/?token=secret",
    )

    assert analysis.has_type(
        WebCacheKeyIndicatorType.SENSITIVE_QUERY_PARAMETER
    )


def test_duplicate_query_parameter():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(),
        request_url="https://example.com/?id=1&id=2",
    )

    assert analysis.has_type(
        WebCacheKeyIndicatorType.DUPLICATE_QUERY_PARAMETER
    )


def test_fragment_present():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(),
        request_url="https://example.com/?id=1#private",
    )

    assert analysis.has_type(
        WebCacheKeyIndicatorType.FRAGMENT_PRESENT
    )


def test_cookie_and_authorization():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(),
        cookie_present=True,
        authorization_present=True,
    )

    assert analysis.has_type(
        WebCacheKeyIndicatorType.COOKIE_PRESENT
    )
    assert analysis.has_type(
        WebCacheKeyIndicatorType.AUTHORIZATION_PRESENT
    )


def test_vary_present():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(),
        vary_header="Accept-Encoding, Origin",
    )

    assert analysis.has_type(
        WebCacheKeyIndicatorType.VARY_PRESENT
    )
    assert not analysis.has_type(
        WebCacheKeyIndicatorType.VARY_MISSING
    )


def test_vary_missing():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(),
    )

    assert analysis.has_type(
        WebCacheKeyIndicatorType.VARY_MISSING
    )


def test_cache_control_directives():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(
            {"cache-control": "private, no-store, no-cache"}
        ),
    )

    assert analysis.has_type(
        WebCacheKeyIndicatorType.CACHE_CONTROL_PRIVATE
    )
    assert analysis.has_type(
        WebCacheKeyIndicatorType.CACHE_CONTROL_NO_STORE
    )
    assert analysis.has_type(
        WebCacheKeyIndicatorType.CACHE_CONTROL_NO_CACHE
    )


def test_analysis_count():
    analysis = WebCacheKeySecurityAnalyzer().analyze(
        make_response(),
        cacheable=True,
        request_url="https://example.com/?id=1&id=2&token=x#fragment",
        cache_key_parameters={"id"},
        unkeyed_parameters={"id"},
        cookie_present=True,
        authorization_present=True,
    )

    assert analysis.count == len(analysis.types)
    assert analysis.count >= 6
