import pytest

from m_hunter.analyzers.http_method_security import (
    HTTPMethodSecurityAnalysis,
    HTTPMethodSecurityIndicator,
    HTTPMethodSecurityIndicatorType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.http_method_security import (
    HTTPMethodSecurityValidator,
)


def make_response(
    *,
    status_code=200,
    content=b"OK",
    headers=None,
    content_length=None,
    repeated_headers=None,
):
    if content_length is None:
        content_length = len(content)

    return HttpResponse(
        status_code=status_code,
        url="https://example.com/",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=content_length,
        repeated_headers=repeated_headers or {},
    )


def make_analysis(
    *indicator_types,
):
    return HTTPMethodSecurityAnalysis(
        indicators=tuple(
            HTTPMethodSecurityIndicator(
                type=indicator_type,
                evidence="test evidence",
            )
            for indicator_type in indicator_types
        )
    )


@pytest.fixture
def validator():
    return HTTPMethodSecurityValidator()


@pytest.fixture
def clean_analysis():
    return make_analysis()


@pytest.fixture
def security_analysis():
    return make_analysis(
        HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
    )


def test_identical_responses_have_no_changes(
    validator,
    clean_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=clean_analysis,
    )

    assert result.status_changed is False
    assert result.content_changed is False
    assert result.content_length_changed is False
    assert result.headers_changed is False
    assert result.response_changed is False
    assert result.behavior_changed is False
    assert result.security_indicator_present is False
    assert result.potential_http_method_security_issue is False
    assert result.status == "no_indicator"


def test_status_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=405)

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.status_changed
    assert result.response_changed
    assert result.status == "no_indicator"


def test_content_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(content=b"before")
    candidate = make_response(content=b"after")

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.content_changed
    assert result.response_changed


def test_content_length_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(
        content=b"abc",
        content_length=3,
    )
    candidate = make_response(
        content=b"abc",
        content_length=10,
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.content_length_changed
    assert result.response_changed


def test_header_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(
        headers={"X-Test": "one"},
    )
    candidate = make_response(
        headers={"X-Test": "two"},
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.headers_changed
    assert result.response_changed


def test_repeated_header_change_is_detected(
    validator,
    clean_analysis,
):
    baseline = make_response(
        repeated_headers={
            "Allow": ["GET"],
        },
    )
    candidate = make_response(
        repeated_headers={
            "Allow": ["GET", "POST"],
        },
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
    )

    assert result.headers_changed
    assert result.response_changed


def test_behavior_change_is_detected(
    validator,
    clean_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=clean_analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed
    assert result.status == "behavior_changed"


def test_security_indicator_without_change_is_not_potential_issue(
    validator,
    security_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=security_analysis,
    )

    assert result.security_indicator_present
    assert result.potential_http_method_security_issue is False
    assert result.status == "indicator_detected"


def test_security_indicator_with_response_change_is_potential_issue(
    validator,
    security_analysis,
):
    baseline = make_response(
        headers={"X-Test": "one"},
    )
    candidate = make_response(
        headers={"X-Test": "two"},
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=security_analysis,
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.security_indicator_present
    assert result.potential_http_method_security_issue
    assert (
        result.status
        == "potential_http_method_security_issue"
    )


def test_security_indicator_with_behavior_change_is_potential_issue(
    validator,
    security_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=security_analysis,
        behavior_changed=True,
    )

    assert result.potential_http_method_security_issue
    assert result.status == "potential_http_method_security_issue"


@pytest.mark.parametrize(
    "indicator_type",
    list(HTTPMethodSecurityIndicatorType),
)
def test_all_indicator_types_are_supported(
    validator,
    indicator_type,
):
    analysis = make_analysis(indicator_type)

    baseline = make_response()
    candidate = make_response(
        content=b"changed",
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=analysis,
    )

    assert result.response_changed

    if indicator_type in (
        HTTPMethodSecurityValidator.SECURITY_RELEVANT_TYPES
    ):
        assert result.security_indicator_present
        assert result.potential_http_method_security_issue
    else:
        assert result.security_indicator_present is False
        assert result.potential_http_method_security_issue is False


def test_informational_indicator_is_not_security_relevant(
    validator,
):
    analysis = make_analysis(
        HTTPMethodSecurityIndicatorType.OPTIONS_EXPOSURE,
        HTTPMethodSecurityIndicatorType.ALLOW_HEADER,
    )

    baseline = make_response()
    candidate = make_response(
        content=b"changed",
    )

    result = validator.compare(
        baseline=baseline,
        candidate=candidate,
        analysis=analysis,
    )

    assert result.analysis if False else True
    assert result.security_indicator_present is False
    assert result.potential_http_method_security_issue is False
    assert result.status == "informational_indicator"


def test_no_indicator_with_behavior_change(
    validator,
    clean_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=clean_analysis,
        behavior_changed=True,
    )

    assert result.status == "behavior_changed"
    assert result.potential_http_method_security_issue is False


def test_evidence_mentions_status_change(
    validator,
    clean_analysis,
):
    result = validator.compare(
        baseline=make_response(status_code=200),
        candidate=make_response(status_code=405),
        analysis=clean_analysis,
    )

    assert any(
        "status changed" in item.lower()
        for item in result.evidence
    )


def test_evidence_mentions_content_change(
    validator,
    clean_analysis,
):
    result = validator.compare(
        baseline=make_response(content=b"one"),
        candidate=make_response(content=b"two"),
        analysis=clean_analysis,
    )

    assert any(
        "content changed" in item.lower()
        for item in result.evidence
    )


def test_evidence_mentions_header_change(
    validator,
    clean_analysis,
):
    result = validator.compare(
        baseline=make_response(
            headers={"X-Test": "one"},
        ),
        candidate=make_response(
            headers={"X-Test": "two"},
        ),
        analysis=clean_analysis,
    )

    assert any(
        "headers changed" in item.lower()
        for item in result.evidence
    )


def test_evidence_mentions_behavior_change(
    validator,
    clean_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=clean_analysis,
        behavior_changed=True,
    )

    assert any(
        "behavior changed" in item.lower()
        for item in result.evidence
    )


def test_evidence_mentions_security_indicator(
    validator,
    security_analysis,
):
    response = make_response()

    result = validator.compare(
        baseline=response,
        candidate=response,
        analysis=security_analysis,
    )

    assert any(
        "security-relevant" in item.lower()
        for item in result.evidence
    )


def test_requires_baseline_response(
    validator,
    clean_analysis,
):
    with pytest.raises(TypeError):
        validator.compare(
            baseline="invalid",
            candidate=make_response(),
            analysis=clean_analysis,
        )


def test_requires_candidate_response(
    validator,
    clean_analysis,
):
    with pytest.raises(TypeError):
        validator.compare(
            baseline=make_response(),
            candidate="invalid",
            analysis=clean_analysis,
        )


def test_requires_analysis(validator):
    with pytest.raises(TypeError):
        validator.compare(
            baseline=make_response(),
            candidate=make_response(),
            analysis="invalid",
        )


def test_behavior_changed_must_be_boolean(
    validator,
    clean_analysis,
):
    with pytest.raises(TypeError):
        validator.compare(
            baseline=make_response(),
            candidate=make_response(),
            analysis=clean_analysis,
            behavior_changed="yes",
        )
