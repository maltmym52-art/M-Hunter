import pytest

from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.validation.idor import (
    IDORCandidate,
    IDORValidationResult,
    IDORValidator,
)


def make_request(
    *,
    url="https://example.com/api",
    params=None,
):
    return HttpRequest(
        method="GET",
        url=url,
        params=params or {},
    )


def make_response(
    *,
    status_code=200,
    content=b"same",
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/api",
        headers={},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def test_validator_can_be_created():
    validator = IDORValidator()

    assert isinstance(
        validator,
        IDORValidator,
    )


def test_validator_requires_http_request():
    validator = IDORValidator()

    with pytest.raises(TypeError):
        validator.build_candidate_request(
            "invalid",
            parameter="id",
            candidate_value="2",
        )


def test_empty_parameter_is_rejected():
    validator = IDORValidator()

    request = make_request(
        params={
            "id": "1",
        }
    )

    with pytest.raises(ValueError):
        validator.build_candidate_request(
            request,
            parameter="   ",
            candidate_value="2",
        )


def test_missing_parameter_is_rejected():
    validator = IDORValidator()

    request = make_request(
        params={
            "user_id": "1",
        }
    )

    with pytest.raises(KeyError):
        validator.build_candidate_request(
            request,
            parameter="id",
            candidate_value="2",
        )


def test_candidate_request_changes_only_requested_parameter():
    validator = IDORValidator()

    request = make_request(
        params={
            "id": "1",
            "page": "2",
        }
    )

    candidate = validator.build_candidate_request(
        request,
        parameter="id",
        candidate_value="42",
    )

    assert candidate.params == {
        "id": "42",
        "page": "2",
    }


def test_original_request_is_not_modified():
    validator = IDORValidator()

    request = make_request(
        params={
            "id": "1",
        }
    )

    validator.build_candidate_request(
        request,
        parameter="id",
        candidate_value="42",
    )

    assert request.params == {
        "id": "1",
    }


def test_candidate_request_preserves_request_properties():
    validator = IDORValidator()

    request = HttpRequest(
        method="POST",
        url="https://example.com/api",
        headers={
            "Authorization": "Bearer token",
        },
        cookies={
            "session": "abc",
        },
        params={
            "user_id": "1",
        },
        body='{"test":true}',
    )

    candidate = validator.build_candidate_request(
        request,
        parameter="user_id",
        candidate_value="2",
    )

    assert candidate.method == "POST"
    assert candidate.url == request.url
    assert candidate.headers == request.headers
    assert candidate.cookies == request.cookies
    assert candidate.body == request.body
    assert candidate.params["user_id"] == "2"


def test_validate_returns_idor_validation_result():
    validator = IDORValidator()

    baseline_request = make_request(
        params={
            "id": "1",
        }
    )

    candidate_request = validator.build_candidate_request(
        baseline_request,
        parameter="id",
        candidate_value="2",
    )

    result = validator.validate(
        baseline_request=baseline_request,
        baseline_response=make_response(
            content=b"user-1",
        ),
        candidate_request=candidate_request,
        candidate_response=make_response(
            content=b"user-2",
        ),
        parameter="id",
        original_value="1",
        candidate_value="2",
    )

    assert isinstance(
        result,
        IDORValidationResult,
    )
    assert isinstance(
        result.candidate,
        IDORCandidate,
    )


def test_resource_change_with_response_change_is_potentially_accessible():
    validator = IDORValidator()

    baseline_request = make_request(
        params={
            "id": "1",
        }
    )

    candidate_request = validator.build_candidate_request(
        baseline_request,
        parameter="id",
        candidate_value="2",
    )

    result = validator.validate(
        baseline_request=baseline_request,
        baseline_response=make_response(
            content=b"user-1",
        ),
        candidate_request=candidate_request,
        candidate_response=make_response(
            content=b"user-2",
        ),
        parameter="id",
        original_value="1",
        candidate_value="2",
    )

    assert result.behavior_changed is True
    assert result.potentially_accessible is True


def test_resource_change_without_response_change_is_not_potentially_accessible():
    validator = IDORValidator()

    baseline_request = make_request(
        params={
            "id": "1",
        }
    )

    candidate_request = validator.build_candidate_request(
        baseline_request,
        parameter="id",
        candidate_value="2",
    )

    result = validator.validate(
        baseline_request=baseline_request,
        baseline_response=make_response(
            content=b"same",
        ),
        candidate_request=candidate_request,
        candidate_response=make_response(
            content=b"same",
        ),
        parameter="id",
        original_value="1",
        candidate_value="2",
    )

    assert result.behavior_changed is False
    assert result.potentially_accessible is False


def test_identity_change_is_preserved():
    validator = IDORValidator()

    baseline_request = make_request(
        params={
            "user_id": "1",
        }
    )

    candidate_request = validator.build_candidate_request(
        baseline_request,
        parameter="user_id",
        candidate_value="2",
    )

    result = validator.validate(
        baseline_request=baseline_request,
        baseline_response=make_response(),
        candidate_request=candidate_request,
        candidate_response=make_response(
            status_code=403,
        ),
        parameter="user_id",
        original_value="1",
        candidate_value="2",
        identity_changed=True,
    )

    assert (
        result.authorization_result.identity_changed
        is True
    )


def test_authorization_context_change_is_preserved():
    validator = IDORValidator()

    baseline_request = make_request(
        params={
            "id": "1",
        }
    )

    candidate_request = validator.build_candidate_request(
        baseline_request,
        parameter="id",
        candidate_value="2",
    )

    result = validator.validate(
        baseline_request=baseline_request,
        baseline_response=make_response(),
        candidate_request=candidate_request,
        candidate_response=make_response(
            status_code=403,
        ),
        parameter="id",
        original_value="1",
        candidate_value="2",
        authorization_context_changed=True,
    )

    assert (
        result.authorization_result
        .authorization_context_changed
        is True
    )


def test_validate_requires_baseline_request():
    validator = IDORValidator()

    candidate_request = make_request(
        params={
            "id": "2",
        }
    )

    with pytest.raises(TypeError):
        validator.validate(
            baseline_request="invalid",
            baseline_response=make_response(),
            candidate_request=candidate_request,
            candidate_response=make_response(),
            parameter="id",
            original_value="1",
            candidate_value="2",
        )


def test_validate_requires_candidate_request():
    validator = IDORValidator()

    baseline_request = make_request(
        params={
            "id": "1",
        }
    )

    with pytest.raises(TypeError):
        validator.validate(
            baseline_request=baseline_request,
            baseline_response=make_response(),
            candidate_request="invalid",
            candidate_response=make_response(),
            parameter="id",
            original_value="1",
            candidate_value="2",
        )


def test_identical_requests_are_rejected():
    validator = IDORValidator()

    request = make_request(
        params={
            "id": "1",
        }
    )

    with pytest.raises(ValueError):
        validator.validate(
            baseline_request=request,
            baseline_response=make_response(),
            candidate_request=request.copy(),
            candidate_response=make_response(),
            parameter="id",
            original_value="1",
            candidate_value="1",
        )


def test_candidate_metadata_is_preserved():
    validator = IDORValidator()

    baseline_request = make_request(
        params={
            "id": "1",
        }
    )

    candidate_request = validator.build_candidate_request(
        baseline_request,
        parameter="id",
        candidate_value="2",
    )

    result = validator.validate(
        baseline_request=baseline_request,
        baseline_response=make_response(),
        candidate_request=candidate_request,
        candidate_response=make_response(
            content=b"changed",
        ),
        parameter="id",
        original_value="1",
        candidate_value="2",
    )

    assert result.candidate.parameter == "id"
    assert result.candidate.original_value == "1"
    assert result.candidate.candidate_value == "2"


def test_custom_authorization_validator_is_used():
    validator = IDORValidator()

    assert validator.authorization_validator is not None
