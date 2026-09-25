import pytest

from m_hunter.analyzers.saml import SAMLAnalyzer
from m_hunter.core.response import HttpResponse
from m_hunter.validation.saml import (
    SAMLValidator,
    SAMLValidationResult,
)


@pytest.fixture
def validator():
    return SAMLValidator()


@pytest.fixture
def analyzer():
    return SAMLAnalyzer()


def make_response(
    *,
    status_code=200,
    url="https://example.com/sso",
    headers=None,
    content=b"OK",
    cookies=None,
    response_time=0.1,
):
    return HttpResponse(
        status_code=status_code,
        url=url,
        headers=headers or {},
        content=content,
        cookies=cookies or {},
        response_time=response_time,
        content_length=len(content),
    )


def test_identical_responses_without_indicator(
    validator,
    analyzer,
):
    response = make_response()

    result = validator.compare(
        response,
        response,
        analyzer.analyze(),
    )

    assert isinstance(result, SAMLValidationResult)
    assert result.status == "no_indicator"
    assert not result.status_changed
    assert not result.content_changed
    assert not result.content_length_changed
    assert not result.headers_changed
    assert not result.response_changed
    assert not result.potential_saml_issue


def test_indicator_without_response_change(
    validator,
    analyzer,
):
    response = make_response()

    result = validator.compare(
        response,
        response,
        analyzer.analyze(issuer="idp.example"),
    )

    assert result.status == "indicator_detected"
    assert not result.response_changed
    assert not result.potential_saml_issue


def test_status_change(
    validator,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=302)

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(issuer="idp.example"),
    )

    assert result.status_changed
    assert result.response_changed
    assert result.potential_saml_issue
    assert result.status == "potential_saml_issue"
    assert "status changed" in result.evidence


def test_content_change(
    validator,
    analyzer,
):
    baseline = make_response(content=b"baseline")
    candidate = make_response(content=b"candidate")

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(assertion="assertion"),
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_saml_issue


def test_content_length_change(
    validator,
    analyzer,
):
    baseline = make_response(content=b"short")
    candidate = make_response(content=b"a much longer response")

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(audience="sp.example"),
    )

    assert result.content_length_changed
    assert result.response_changed
    assert result.potential_saml_issue


def test_header_change(
    validator,
    analyzer,
):
    baseline = make_response(
        headers={"content-type": "text/html"}
    )
    candidate = make_response(
        headers={
            "content-type": "text/html",
            "x-saml-test": "changed",
        }
    )

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(issuer="idp"),
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_saml_issue
    assert "response headers changed" in result.evidence


def test_behavior_change(
    validator,
    analyzer,
):
    response = make_response()

    result = validator.compare(
        response,
        response,
        analyzer.analyze(
            assertion="assertion",
            signed_assertion=False,
        ),
        behavior_changed=True,
    )

    assert result.behavior_changed
    assert result.potential_saml_issue
    assert result.status == "behavior_changed"
    assert "application behavior changed" in result.evidence


def test_behavior_change_without_response_difference(
    validator,
    analyzer,
):
    response = make_response()

    result = validator.compare(
        response,
        response,
        analyzer.analyze(
            signature_algorithm="rsa-sha1",
        ),
        behavior_changed=True,
    )

    assert result.response_changed is False
    assert result.behavior_changed
    assert result.potential_saml_issue


def test_multiple_changes(
    validator,
    analyzer,
):
    baseline = make_response(
        status_code=200,
        headers={"content-type": "text/html"},
        content=b"baseline",
    )

    candidate = make_response(
        status_code=403,
        headers={
            "content-type": "application/xml",
            "x-test": "changed",
        },
        content=b"candidate response",
    )

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(
            issuer="idp",
            audience="sp",
            assertion="assertion",
        ),
    )

    assert result.status_changed
    assert result.content_changed
    assert result.content_length_changed
    assert result.headers_changed
    assert result.response_changed
    assert result.potential_saml_issue


@pytest.mark.parametrize(
    "status_code",
    [200, 201, 204, 301, 302, 400, 401, 403, 404, 500],
)
def test_same_status_is_not_changed(
    validator,
    analyzer,
    status_code,
):
    response = make_response(status_code=status_code)

    result = validator.compare(
        response,
        response,
        analyzer.analyze(issuer="idp"),
    )

    assert result.status_changed is False


def test_status_change_without_indicator(
    validator,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=403)

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(),
    )

    assert result.status_changed
    assert result.response_changed
    assert result.potential_saml_issue is False
    assert result.status == "no_indicator"


def test_behavior_change_without_indicator(
    validator,
    analyzer,
):
    response = make_response()

    result = validator.compare(
        response,
        response,
        analyzer.analyze(),
        behavior_changed=True,
    )

    assert result.behavior_changed
    assert result.potential_saml_issue is False
    assert result.status == "no_indicator"


def test_evidence_contains_detected_indicator(
    validator,
    analyzer,
):
    response = make_response()

    result = validator.compare(
        response,
        response,
        analyzer.analyze(
            signature_algorithm="rsa-sha1",
        ),
    )

    assert "SAML security indicators were detected" in result.evidence


def test_evidence_empty_without_changes_or_indicator(
    validator,
    analyzer,
):
    response = make_response()

    result = validator.compare(
        response,
        response,
        analyzer.analyze(),
    )

    assert result.evidence == ""


def test_result_preserves_status_codes(
    validator,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=401)

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(issuer="idp"),
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 401


def test_response_changed_is_aggregate(
    validator,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(),
    )

    assert result.content_changed
    assert result.response_changed


def test_headers_only_change(
    validator,
    analyzer,
):
    baseline = make_response(
        headers={"server": "one"}
    )
    candidate = make_response(
        headers={"server": "two"}
    )

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(issuer="idp"),
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_saml_issue


def test_empty_body_to_body(
    validator,
    analyzer,
):
    baseline = make_response(content=b"")
    candidate = make_response(content=b"<Response/>")

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(
            saml_response="response",
        ),
    )

    assert result.content_changed
    assert result.content_length_changed
    assert result.response_changed


def test_unsigned_assertion_indicator(
    validator,
    analyzer,
):
    response = make_response()

    result = validator.compare(
        response,
        response,
        analyzer.analyze(
            assertion="assertion",
            signed_assertion=False,
        ),
    )

    assert result.status == "indicator_detected"
    assert not result.potential_saml_issue


def test_weak_algorithm_indicator(
    validator,
    analyzer,
):
    response = make_response()

    result = validator.compare(
        response,
        response,
        analyzer.analyze(
            signature_algorithm="rsa-sha1",
        ),
    )

    assert result.status == "indicator_detected"
    assert "SAML security indicators were detected" in result.evidence


def test_all_response_dimensions_can_be_detected(
    validator,
    analyzer,
):
    baseline = make_response(
        status_code=200,
        headers={"a": "1"},
        content=b"a",
    )
    candidate = make_response(
        status_code=500,
        headers={"a": "2"},
        content=b"much longer",
    )

    result = validator.compare(
        baseline,
        candidate,
        analyzer.analyze(issuer="idp"),
        behavior_changed=True,
    )

    assert result.status_changed
    assert result.content_changed
    assert result.content_length_changed
    assert result.headers_changed
    assert result.response_changed
    assert result.behavior_changed
    assert result.potential_saml_issue
    assert result.status == "behavior_changed"


@pytest.mark.parametrize(
    "baseline,candidate",
    [
        (None, make_response()),
        (make_response(), None),
        ("invalid", make_response()),
        (make_response(), "invalid"),
    ],
)
def test_invalid_response_types(
    validator,
    analyzer,
    baseline,
    candidate,
):
    with pytest.raises(TypeError):
        validator.compare(
            baseline,
            candidate,
            analyzer.analyze(),
        )


def test_invalid_analysis_type(
    validator,
):
    response = make_response()

    with pytest.raises(TypeError):
        validator.compare(
            response,
            response,
            object(),
        )


@pytest.mark.parametrize(
    "value",
    [None, 1, "true", [], {}],
)
def test_invalid_behavior_changed(
    validator,
    analyzer,
    value,
):
    response = make_response()

    with pytest.raises(TypeError):
        validator.compare(
            response,
            response,
            analyzer.analyze(),
            behavior_changed=value,
        )
