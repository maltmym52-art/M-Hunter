import pytest

from m_hunter.analyzers.web_cache_deception import (
    WebCacheDeceptionAnalysis,
    WebCacheDeceptionAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.web_cache_deception_pipeline import (
    WebCacheDeceptionValidationPipeline,
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


def empty_analysis():
    return WebCacheDeceptionAnalysis(
        detected=False,
        count=0,
        types=[],
        names=[],
        indicators=[],
    )


def pipeline():
    return WebCacheDeceptionValidationPipeline()


def test_identical_responses_not_accepted():
    result = pipeline().process(
        response(),
        response(),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_cache_change_alone_not_accepted():
    result = pipeline().process(
        response(headers={"X-Cache": "MISS"}),
        response(headers={"X-Cache": "HIT"}),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_sensitive_content_without_cache_change_not_accepted():
    result = pipeline().process(
        response(body=b"public"),
        response(body=b"private account dashboard"),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_cache_change_with_sensitive_content_is_accepted():
    result = pipeline().process(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account dashboard",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is True
    assert result.validation.potential_web_cache_deception is True
    assert result.findings


def test_no_indicator_not_accepted():
    result = pipeline().process(
        response(body=b"public"),
        response(body=b"private account dashboard"),
        empty_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_status_change_without_cache_behavior_not_accepted():
    result = pipeline().process(
        response(status=200),
        response(
            status=403,
            body=b"private account dashboard",
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is False


def test_endpoint_preserved():
    result = pipeline().process(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account dashboard",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
        "https://example.com",
        endpoint="/account",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        finding.endpoint == "/account"
        for finding in result.findings
    )


def test_parameter_preserved():
    result = pipeline().process(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account dashboard",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
        "https://example.com",
        parameter="id",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        finding.parameter == "id"
        for finding in result.findings
    )


def test_target_preserved():
    result = pipeline().process(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account dashboard",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
        "https://target.example",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_invalid_baseline():
    with pytest.raises(TypeError):
        pipeline().process(
            "invalid",
            response(),
            detected_analysis(),
            "https://example.com",
        )


def test_invalid_candidate():
    with pytest.raises(TypeError):
        pipeline().process(
            response(),
            "invalid",
            detected_analysis(),
            "https://example.com",
        )


def test_invalid_analysis():
    with pytest.raises(TypeError):
        pipeline().process(
            response(),
            response(),
            "invalid",
            "https://example.com",
        )


def test_empty_target():
    with pytest.raises(ValueError):
        pipeline().process(
            response(),
            response(
                body=b"private account",
                headers={"X-Cache": "HIT"},
            ),
            detected_analysis(),
            "",
        )


def test_validation_result_exposed():
    result = pipeline().process(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert result.validation is not None
    assert result.validation.cache_behavior_changed is True


def test_findings_only_when_accepted():
    rejected = pipeline().process(
        response(),
        response(),
        detected_analysis(),
        "https://example.com",
    )

    accepted = pipeline().process(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert rejected.findings == []
    assert accepted.findings


def test_multiple_findings_returned():
    analysis = WebCacheDeceptionAnalyzer().analyze(
        url="https://example.com/account.css",
        headers={
            "X-Cache": "HIT",
            "Cache-Control": "public, max-age=3600",
            "Age": "120",
            "Vary": "Accept-Encoding",
            "Content-Type": "text/html",
        },
        response_body="private account dashboard",
    )

    result = pipeline().process(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account dashboard",
            headers={"X-Cache": "HIT"},
        ),
        analysis,
        "https://example.com",
    )

    assert result.accepted is True
    assert len(result.findings) == analysis.count


def test_result_fields():
    result = pipeline().process(
        response(),
        response(),
        detected_analysis(),
        "https://example.com",
    )

    assert hasattr(result, "validation")
    assert hasattr(result, "accepted")
    assert hasattr(result, "findings")


def test_findings_are_finding_objects():
    result = pipeline().process(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"private account",
            headers={"X-Cache": "HIT"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert all(
        hasattr(finding, "title")
        and hasattr(finding, "severity")
        for finding in result.findings
    )


def test_cache_control_change_with_sensitive_content():
    result = pipeline().process(
        response(
            body=b"public",
            headers={"Cache-Control": "no-store"},
        ),
        response(
            body=b"private account",
            headers={"Cache-Control": "public, max-age=3600"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is True


def test_age_change_with_sensitive_content():
    result = pipeline().process(
        response(
            body=b"public",
            headers={"Age": "0"},
        ),
        response(
            body=b"private account",
            headers={"Age": "120"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is True


def test_static_path_without_sensitive_content_not_accepted():
    result = pipeline().process(
        response(
            body=b"public",
            headers={"X-Cache": "MISS"},
        ),
        response(
            body=b"public static content",
            headers={"X-Cache": "HIT"},
        ),
        WebCacheDeceptionAnalyzer().analyze(
            url="https://example.com/style.css",
            headers={"X-Cache": "HIT"},
        ),
        "https://example.com",
    )

    assert result.accepted is False


def test_pipeline_does_not_accept_header_change_alone():
    result = pipeline().process(
        response(
            headers={"Cache-Control": "no-store"},
        ),
        response(
            headers={"Cache-Control": "public"},
        ),
        detected_analysis(),
        "https://example.com",
    )

    assert result.accepted is False
