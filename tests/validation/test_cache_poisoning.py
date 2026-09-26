from m_hunter.analyzers.cache_poisoning import (
    CachePoisoningAnalysis,
    CachePoisoningAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.cache_poisoning import (
    CachePoisoningValidator,
)


def response(
    *,
    status=200,
    body=b"same",
    headers=None,
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


def analysis(detected=True):
    if detected:
        return CachePoisoningAnalyzer().analyze(
            headers={"X-Cache": "HIT"},
        )

    return CachePoisoningAnalysis(
        detected=False,
        count=0,
        types=[],
        names=[],
        indicators=[],
    )


def validator():
    return CachePoisoningValidator()


def test_identical_responses():
    baseline = response(body=b"same")
    candidate = response(body=b"same")

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.response_changed is False
    assert result.potential_cache_poisoning is False
    assert result.status == "indicator_detected"


def test_status_change():
    baseline = response(status=200)
    candidate = response(status=403)

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True


def test_content_change():
    baseline = response(body=b"normal")
    candidate = response(body=b"changed")

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.content_changed is True
    assert result.potential_cache_poisoning is True
    assert result.status == "potential_cache_poisoning"


def test_content_length_change():
    baseline = response(body=b"short")
    candidate = response(body=b"much longer response")

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.content_length_changed is True
    assert result.response_changed is True


def test_header_change():
    baseline = response(
        headers={"Content-Type": "text/html"},
    )
    candidate = response(
        headers={"Content-Type": "application/json"},
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.headers_changed is True
    assert result.response_changed is True


def test_cache_header_change():
    baseline = response(
        headers={"X-Cache": "MISS"},
    )
    candidate = response(
        headers={"X-Cache": "HIT"},
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.cache_behavior_changed is True
    assert result.potential_cache_poisoning is False
    assert result.status == "cache_behavior_changed"


def test_cache_control_change():
    baseline = response(
        headers={"Cache-Control": "no-store"},
    )
    candidate = response(
        headers={"Cache-Control": "public, max-age=3600"},
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.cache_behavior_changed is True


def test_age_change():
    baseline = response(
        headers={"Age": "0"},
    )
    candidate = response(
        headers={"Age": "120"},
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.cache_behavior_changed is True


def test_etag_change():
    baseline = response(
        headers={"ETag": '"old"'},
    )
    candidate = response(
        headers={"ETag": '"new"'},
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.cache_behavior_changed is True


def test_vary_change():
    baseline = response(
        headers={"Vary": "Accept-Encoding"},
    )
    candidate = response(
        headers={"Vary": "Origin"},
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.cache_behavior_changed is True


def test_no_indicator():
    baseline = response(body=b"same")
    candidate = response(body=b"changed")

    result = validator().compare(
        baseline,
        candidate,
        analysis(False),
    )

    assert result.response_changed is True
    assert result.potential_cache_poisoning is False
    assert result.status == "response_changed"


def test_indicator_without_response_change():
    baseline = response(
        headers={"X-Cache": "HIT"},
    )
    candidate = response(
        headers={"X-Cache": "HIT"},
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.potential_cache_poisoning is False
    assert result.status == "indicator_detected"


def test_cache_change_without_body_change():
    baseline = response(
        body=b"same",
        headers={"X-Cache": "MISS"},
    )
    candidate = response(
        body=b"same",
        headers={"X-Cache": "HIT"},
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.cache_behavior_changed is True
    assert result.potential_cache_poisoning is False


def test_multiple_changes():
    baseline = response(
        status=200,
        body=b"original",
        headers={
            "X-Cache": "MISS",
            "Cache-Control": "no-store",
        },
    )
    candidate = response(
        status=200,
        body=b"modified",
        headers={
            "X-Cache": "HIT",
            "Cache-Control": "public",
        },
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.response_changed is True
    assert result.cache_behavior_changed is True
    assert result.potential_cache_poisoning is True


def test_invalid_baseline():
    candidate = response()

    try:
        validator().compare(
            "invalid",
            candidate,
            analysis(),
        )
        assert False
    except TypeError:
        assert True


def test_invalid_candidate():
    baseline = response()

    try:
        validator().compare(
            baseline,
            "invalid",
            analysis(),
        )
        assert False
    except TypeError:
        assert True


def test_invalid_analysis():
    baseline = response()
    candidate = response()

    try:
        validator().compare(
            baseline,
            candidate,
            "invalid",
        )
        assert False
    except TypeError:
        assert True


def test_evidence_contains_state():
    baseline = response(body=b"old")
    candidate = response(body=b"new")

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert "baseline_status=200" in result.evidence
    assert "candidate_status=200" in result.evidence
    assert "content_changed=True" in result.evidence


def test_result_fields():
    baseline = response()
    candidate = response()

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 200
    assert isinstance(result.status_changed, bool)
    assert isinstance(result.content_changed, bool)
    assert isinstance(result.content_length_changed, bool)
    assert isinstance(result.headers_changed, bool)
    assert isinstance(result.response_changed, bool)
    assert isinstance(result.cache_behavior_changed, bool)
    assert isinstance(result.potential_cache_poisoning, bool)


def test_case_insensitive_cache_headers():
    baseline = response(
        headers={"x-cache": "MISS"},
    )
    candidate = response(
        headers={"X-CACHE": "HIT"},
    )

    result = validator().compare(
        baseline,
        candidate,
        analysis(),
    )

    assert result.cache_behavior_changed is True
