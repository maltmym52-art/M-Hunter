import pytest

from m_hunter.analyzers.cache_control_security import (
    CacheControlAnalysis,
    CacheControlIndicator,
    CacheControlIndicatorType,
    CacheControlSecurityAnalyzer,
)


@pytest.fixture
def analyzer():
    return CacheControlSecurityAnalyzer()


def test_name(analyzer):
    assert analyzer.name == "cache_control_security"


def test_description(analyzer):
    assert "cache" in analyzer.description.lower()


def test_analysis_type(analyzer):
    result = analyzer.analyze(
        cache_control="no-store"
    )

    assert isinstance(result, CacheControlAnalysis)


def test_cache_control_present(analyzer):
    result = analyzer.analyze(
        cache_control="no-store"
    )

    assert result.has_type(
        CacheControlIndicatorType.CACHE_CONTROL_PRESENT
    )


def test_cache_control_missing(analyzer):
    result = analyzer.analyze()

    assert result.has_type(
        CacheControlIndicatorType.CACHE_CONTROL_MISSING
    )


def test_no_store(analyzer):
    result = analyzer.analyze(
        cache_control="no-store"
    )

    assert result.has_type(
        CacheControlIndicatorType.NO_STORE
    )


def test_no_cache(analyzer):
    result = analyzer.analyze(
        cache_control="no-cache"
    )

    assert result.has_type(
        CacheControlIndicatorType.NO_CACHE
    )


def test_private(analyzer):
    result = analyzer.analyze(
        cache_control="private"
    )

    assert result.has_type(
        CacheControlIndicatorType.PRIVATE
    )


def test_public(analyzer):
    result = analyzer.analyze(
        cache_control="public"
    )

    assert result.has_type(
        CacheControlIndicatorType.PUBLIC
    )


def test_must_revalidate(analyzer):
    result = analyzer.analyze(
        cache_control="must-revalidate"
    )

    assert result.has_type(
        CacheControlIndicatorType.MUST_REVALIDATE
    )


def test_s_maxage(analyzer):
    result = analyzer.analyze(
        cache_control="s-maxage=3600"
    )

    assert result.has_type(
        CacheControlIndicatorType.S_MAXAGE
    )


def test_max_age(analyzer):
    result = analyzer.analyze(
        cache_control="max-age=3600"
    )

    assert result.has_type(
        CacheControlIndicatorType.MAX_AGE
    )


def test_pragma(analyzer):
    result = analyzer.analyze(
        pragma="no-cache"
    )

    assert result.has_type(
        CacheControlIndicatorType.PRAGMA_PRESENT
    )


def test_expires(analyzer):
    result = analyzer.analyze(
        expires="0"
    )

    assert result.has_type(
        CacheControlIndicatorType.EXPIRES_PRESENT
    )


def test_age(analyzer):
    result = analyzer.analyze(
        age="120"
    )

    assert result.has_type(
        CacheControlIndicatorType.AGE_PRESENT
    )


def test_vary(analyzer):
    result = analyzer.analyze(
        vary="Authorization"
    )

    assert result.has_type(
        CacheControlIndicatorType.VARY_PRESENT
    )


def test_surrogate_control(analyzer):
    result = analyzer.analyze(
        surrogate_control="max-age=3600"
    )

    assert result.has_type(
        CacheControlIndicatorType.SURROGATE_CONTROL_PRESENT
    )


def test_cacheable_response(analyzer):
    result = analyzer.analyze(
        cache_control="public, max-age=3600"
    )

    assert result.has_type(
        CacheControlIndicatorType.CACHEABLE_RESPONSE
    )


def test_sensitive_content(analyzer):
    result = analyzer.analyze(
        sensitive_content=True
    )

    assert result.has_type(
        CacheControlIndicatorType.SENSITIVE_CONTENT
    )


def test_public_sensitive_content(analyzer):
    result = analyzer.analyze(
        cache_control="public, max-age=3600",
        sensitive_content=True,
    )

    assert result.has_type(
        CacheControlIndicatorType.PUBLIC_SENSITIVE_CONTENT
    )


def test_missing_vary_for_sensitive_content(analyzer):
    result = analyzer.analyze(
        cache_control="public, max-age=3600",
        sensitive_content=True,
    )

    assert result.has_type(
        CacheControlIndicatorType.MISSING_VARY
    )


def test_vary_prevents_missing_vary(analyzer):
    result = analyzer.analyze(
        cache_control="public, max-age=3600",
        sensitive_content=True,
        vary="Authorization",
    )

    assert not result.has_type(
        CacheControlIndicatorType.MISSING_VARY
    )


def test_conflicting_public_private(analyzer):
    result = analyzer.analyze(
        cache_control="public, private"
    )

    assert result.has_type(
        CacheControlIndicatorType.CONFLICTING_CACHE_DIRECTIVES
    )


def test_conflicting_no_store_public(analyzer):
    result = analyzer.analyze(
        cache_control="no-store, public"
    )

    assert result.has_type(
        CacheControlIndicatorType.CONFLICTING_CACHE_DIRECTIVES
    )


def test_multiple_cache_control(analyzer):
    result = analyzer.analyze(
        cache_control="public",
        multiple_cache_control=True,
    )

    assert result.has_type(
        CacheControlIndicatorType.MULTIPLE_CACHE_CONTROL
    )


def test_indicator_properties(analyzer):
    result = analyzer.analyze(
        cache_control="public, max-age=3600"
    )

    assert result.count > 0
    assert result.types
    assert result.names


def test_indicator_value(analyzer):
    result = analyzer.analyze(
        cache_control="max-age=3600"
    )

    indicator = next(
        item
        for item in result.indicators
        if item.type == CacheControlIndicatorType.MAX_AGE
    )

    assert indicator.value == "max-age=3600"


def test_frozen_indicator():
    indicator = CacheControlIndicator(
        type=CacheControlIndicatorType.PUBLIC,
        name="public",
        value="public",
    )

    with pytest.raises(Exception):
        indicator.value = "private"


def test_frozen_analysis(analyzer):
    result = analyzer.analyze(
        cache_control="public"
    )

    with pytest.raises(Exception):
        result.detected = False


def test_invalid_cache_control(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            cache_control=123
        )


def test_invalid_sensitive_content(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            sensitive_content=1
        )


def test_invalid_multiple_cache_control(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            multiple_cache_control=1
        )


def test_all_contexts(analyzer):
    result = analyzer.analyze(
        cache_control="public, max-age=3600, s-maxage=1800",
        pragma="no-cache",
        expires="0",
        age="120",
        vary="Authorization",
        surrogate_control="max-age=600",
        sensitive_content=True,
        multiple_cache_control=True,
    )

    assert result.detected
    assert result.count >= 10
