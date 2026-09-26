import pytest

from m_hunter.analyzers.web_cache_deception import (
    WebCacheDeceptionAnalysis,
    WebCacheDeceptionAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.web_cache_deception import (
    WebCacheDeceptionValidator,
)


def response(
    *,
    body=b"same",
    headers=None,
    status=200,
):
    return HttpResponse(
        status_code=status,
        url="https://example.com/",
        headers=headers or {},
        content=body,
        cookies={},
        response_time=0.1,
        content_length=len(body),
    )


def detected_analysis():
    return WebCacheDeceptionAnalyzer().analyze(
        url="https://example.com/account.css",
        headers={
            "X-Cache": "HIT",
            "Cache-Control": "public, max-age=3600",
            "Content-Type": "text/html",
        },
        response_body="private account dashboard",
    )


def static_analysis():
    return WebCacheDeceptionAnalyzer().analyze(
        url="https://example.com/account.css",
    )


def empty_analysis():
    return WebCacheDeceptionAnalysis(
        detected=False,
        count=0,
        types=[],
        names=[],
        indicators=[],
    )


def validator():
    return WebCacheDeceptionValidator()


def test_identical_responses_not_accepted():
    result = validator().compare(
        response(),
        response(),
        detected_analysis(),
    )

    assert result.potential_web_cache_deception is False
    assert result.status == "indicator_detected"


def test_cache_behavior_change_alone_not_accepted():
    result = validator().compare(
        response(headers={"X-Cache": "MISS"}),
        response(headers={"X-Cache": "HIT"}),
        detected_analysis(),
    )

    assert result.cache_behavior_changed is True
    assert result.potential_web_cache_deception is False


def test_sensitive_content_without_cache_change_not_accepted():
    result = validator().compare(
        response(body=b"public"),
        response(body=b"private account dashboard"),
        detected_analysis(),
    )

    assert result.content_changed is True
    assert result.sensitive_content_exposed is True
    assert result.potential_web_cache_deception is False


def test_cache_change_with_sensitive_content_is_potential():
    result = validator().compare(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account dashboard",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
    )

    assert result.cache_behavior_changed is True
    assert result.content_changed is True
    assert result.sensitive_content_exposed is True
    assert result.potential_web_cache_deception is True
    assert result.status == "potential_web_cache_deception"


def test_content_length_change():
    result = validator().compare(
        response(
            body=b"short",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account dashboard",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
    )

    assert result.content_length_changed is True
    assert result.response_changed is True


def test_status_change_without_cache_change():
    result = validator().compare(
        response(status=200),
        response(
            status=403,
            body=b"private account dashboard",
        ),
        detected_analysis(),
    )

    assert result.status_changed is True
    assert result.potential_web_cache_deception is False


def test_header_change_detected():
    result = validator().compare(
        response(headers={"Content-Type": "text/html"}),
        response(headers={"Content-Type": "application/json"}),
        static_analysis(),
    )

    assert result.headers_changed is True
    assert result.response_changed is True


def test_cache_control_change_detected():
    result = validator().compare(
        response(
            headers={"Cache-Control": "no-store"},
        ),
        response(
            headers={"Cache-Control": "public, max-age=3600"},
        ),
        detected_analysis(),
    )

    assert result.cache_behavior_changed is True


def test_age_change_detected():
    result = validator().compare(
        response(headers={"Age": "0"}),
        response(headers={"Age": "120"}),
        detected_analysis(),
    )

    assert result.cache_behavior_changed is True


def test_vary_change_detected():
    result = validator().compare(
        response(headers={"Vary": "Accept-Encoding"}),
        response(headers={"Vary": "Origin"}),
        detected_analysis(),
    )

    assert result.cache_behavior_changed is True


def test_no_indicator():
    result = validator().compare(
        response(body=b"old"),
        response(body=b"private account"),
        empty_analysis(),
    )

    assert result.response_changed is True
    assert result.potential_web_cache_deception is False


def test_static_path_indicator_alone_not_enough():
    result = validator().compare(
        response(),
        response(),
        static_analysis(),
    )

    assert result.potential_web_cache_deception is False


def test_cache_header_case_insensitive():
    result = validator().compare(
        response(headers={"x-cache": "MISS"}),
        response(headers={"X-CACHE": "HIT"}),
        detected_analysis(),
    )

    assert result.cache_behavior_changed is True


def test_multiple_cache_changes():
    result = validator().compare(
        response(
            body=b"public",
            headers={
                "X-Cache": "MISS",
                "Cache-Control": "no-store",
                "Age": "0",
            },
        ),
        response(
            body=b"private account",
            headers={
                "X-Cache": "HIT",
                "Cache-Control": "public, max-age=3600",
                "Age": "120",
            },
        ),
        detected_analysis(),
    )

    assert result.cache_behavior_changed is True
    assert result.sensitive_content_exposed is True
    assert result.potential_web_cache_deception is True


def test_invalid_baseline():
    with pytest.raises(TypeError):
        validator().compare(
            "invalid",
            response(),
            detected_analysis(),
        )


def test_invalid_candidate():
    with pytest.raises(TypeError):
        validator().compare(
            response(),
            "invalid",
            detected_analysis(),
        )


def test_invalid_analysis():
    with pytest.raises(TypeError):
        validator().compare(
            response(),
            response(),
            "invalid",
        )


def test_result_fields():
    result = validator().compare(
        response(),
        response(),
        detected_analysis(),
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 200
    assert isinstance(result.status_changed, bool)
    assert isinstance(result.content_changed, bool)
    assert isinstance(result.content_length_changed, bool)
    assert isinstance(result.headers_changed, bool)
    assert isinstance(result.cache_behavior_changed, bool)
    assert isinstance(result.response_changed, bool)
    assert isinstance(result.sensitive_content_exposed, bool)
    assert isinstance(result.potential_web_cache_deception, bool)


def test_evidence_contains_state():
    result = validator().compare(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
    )

    assert "cache_behavior_changed=True" in result.evidence
    assert "sensitive_content_exposed=True" in result.evidence
    assert "potential_web_cache_deception=True" in result.evidence


def test_response_change_is_reported():
    result = validator().compare(
        response(body=b"one"),
        response(body=b"two"),
        static_analysis(),
    )

    assert result.response_changed is True
    assert result.content_changed is True


def test_empty_cache_headers_are_not_considered_changed():
    result = validator().compare(
        response(headers={"Content-Type": "text/html"}),
        response(headers={"Content-Type": "text/html"}),
        detected_analysis(),
    )

    assert result.cache_behavior_changed is False
