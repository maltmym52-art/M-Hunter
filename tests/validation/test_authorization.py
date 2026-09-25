import pytest

from m_hunter.core.response import HttpResponse
from m_hunter.validation.authorization import (
    AuthorizationValidationResult,
    AuthorizationValidator,
    ResponseComparator,
    ResponseComparison,
)


def make_response(
    *,
    status_code=200,
    url="https://example.com/api",
    headers=None,
    content=b"same",
    cookies=None,
    content_length=None,
):
    if content_length is None:
        content_length = len(content)

    return HttpResponse(
        status_code=status_code,
        url=url,
        headers=headers or {},
        content=content,
        cookies=cookies or {},
        response_time=0.1,
        content_length=content_length,
    )


def test_response_comparison_defaults_to_no_changes():
    baseline = make_response()
    candidate = make_response()

    result = ResponseComparator().compare(
        baseline,
        candidate,
    )

    assert isinstance(result, ResponseComparison)
    assert result.behavior_changed is False
    assert result.difference_count == 0


def test_status_code_change_is_detected():
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=403)

    result = ResponseComparator().compare(
        baseline,
        candidate,
    )

    assert result.status_code_changed is True
    assert result.status_category_changed is True
    assert result.behavior_changed is True


def test_status_category_change_is_detected():
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=302)

    result = ResponseComparator().compare(
        baseline,
        candidate,
    )

    assert result.status_code_changed is True
    assert result.status_category_changed is True


def test_content_length_change_is_detected():
    baseline = make_response(
        content=b"abc",
        content_length=3,
    )
    candidate = make_response(
        content=b"abc",
        content_length=4,
    )

    result = ResponseComparator().compare(
        baseline,
        candidate,
    )

    assert result.content_length_changed is True
    assert result.content_changed is False
    assert result.behavior_changed is True


def test_content_change_is_detected():
    baseline = make_response(content=b"owner-a")
    candidate = make_response(content=b"owner-b")

    result = ResponseComparator().compare(
        baseline,
        candidate,
    )

    assert result.content_changed is True
    assert result.behavior_changed is True


def test_header_change_is_detected():
    baseline = make_response(
        headers={
            "Content-Type": "application/json",
        }
    )
    candidate = make_response(
        headers={
            "Content-Type": "text/html",
        }
    )

    result = ResponseComparator().compare(
        baseline,
        candidate,
    )

    assert result.headers_changed is True
    assert result.behavior_changed is True


def test_cookie_change_is_detected():
    baseline = make_response(
        cookies={
            "session": "one",
        }
    )
    candidate = make_response(
        cookies={
            "session": "two",
        }
    )

    result = ResponseComparator().compare(
        baseline,
        candidate,
    )

    assert result.cookies_changed is True
    assert result.behavior_changed is True


def test_difference_count_counts_each_difference():
    baseline = make_response(
        status_code=200,
        headers={"X-Test": "one"},
        content=b"one",
        cookies={"a": "one"},
    )

    candidate = make_response(
        status_code=403,
        headers={"X-Test": "two"},
        content=b"two",
        cookies={"a": "two"},
    )

    result = ResponseComparator().compare(
        baseline,
        candidate,
    )

    assert result.difference_count == 5


def test_comparator_requires_baseline_response():
    with pytest.raises(TypeError):
        ResponseComparator().compare(
            "invalid",
            make_response(),
        )


def test_comparator_requires_candidate_response():
    with pytest.raises(TypeError):
        ResponseComparator().compare(
            make_response(),
            "invalid",
        )


def test_validator_without_context_is_not_potentially_authorization_relevant():
    baseline = make_response(content=b"one")
    candidate = make_response(content=b"two")

    result = AuthorizationValidator().validate(
        baseline=baseline,
        candidate=candidate,
    )

    assert isinstance(
        result,
        AuthorizationValidationResult,
    )
    assert result.behavior_changed is True
    assert result.potentially_authorization_relevant is False


def test_resource_change_with_behavior_change_is_relevant():
    baseline = make_response(content=b"user-a")
    candidate = make_response(content=b"user-b")

    result = AuthorizationValidator().validate(
        baseline=baseline,
        candidate=candidate,
        resource_changed=True,
    )

    assert result.behavior_changed is True
    assert result.potentially_authorization_relevant is True


def test_identity_change_with_behavior_change_is_relevant():
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=403)

    result = AuthorizationValidator().validate(
        baseline=baseline,
        candidate=candidate,
        identity_changed=True,
    )

    assert result.potentially_authorization_relevant is True


def test_authorization_context_change_with_behavior_change_is_relevant():
    baseline = make_response(content=b"private")
    candidate = make_response(content=b"denied")

    result = AuthorizationValidator().validate(
        baseline=baseline,
        candidate=candidate,
        authorization_context_changed=True,
    )

    assert result.potentially_authorization_relevant is True


def test_evidence_describes_status_change():
    result = AuthorizationValidator().validate(
        baseline=make_response(status_code=200),
        candidate=make_response(status_code=403),
    )

    assert "HTTP status code changed." in result.evidence


def test_evidence_describes_content_change():
    result = AuthorizationValidator().validate(
        baseline=make_response(content=b"one"),
        candidate=make_response(content=b"two"),
    )

    assert "Response content changed." in result.evidence


def test_evidence_describes_header_change():
    result = AuthorizationValidator().validate(
        baseline=make_response(
            headers={"X-Test": "one"},
        ),
        candidate=make_response(
            headers={"X-Test": "two"},
        ),
    )

    assert "Response headers changed." in result.evidence


def test_evidence_describes_cookie_change():
    result = AuthorizationValidator().validate(
        baseline=make_response(
            cookies={"session": "one"},
        ),
        candidate=make_response(
            cookies={"session": "two"},
        ),
    )

    assert "Response cookies changed." in result.evidence


def test_no_change_produces_no_evidence():
    result = AuthorizationValidator().validate(
        baseline=make_response(),
        candidate=make_response(),
        resource_changed=True,
    )

    assert result.evidence == ()
    assert result.potentially_authorization_relevant is False


def test_custom_comparator_is_used():
    comparator = ResponseComparator()

    validator = AuthorizationValidator(
        comparator=comparator,
    )

    assert validator.comparator is comparator


def test_validator_instances_have_independent_comparators():
    first = AuthorizationValidator()
    second = AuthorizationValidator()

    assert first.comparator is not second.comparator
