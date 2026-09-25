from m_hunter.analyzers.csrf import (
    CSRFAnalysis,
    CSRFAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.csrf import (
    CSRFValidationResult,
    CSRFValidator,
)


def response(
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/account",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def test_no_indicator_status():
    result = CSRFValidator().validate(
        response(),
        response(),
        CSRFAnalysis(),
    )

    assert result.status == "no_indicator"
    assert not result.potential_csrf


def test_indicator_without_response_change():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    result = CSRFValidator().validate(
        response(),
        response(),
        analysis,
    )

    assert result.status == "indicator_detected"
    assert not result.potential_csrf


def test_response_change_creates_potential_csrf():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    result = CSRFValidator().validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.potential_csrf
    assert result.status == "potential_csrf"


def test_status_change_is_detected():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(status_code=200),
        response(status_code=302),
        analysis,
    )

    assert result.status_changed
    assert result.response_changed


def test_content_change_is_detected():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.content_changed
    assert result.response_changed


def test_content_length_change_is_detected():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(content=b"a"),
        response(content=b"abcdef"),
        analysis,
    )

    assert result.content_length_changed


def test_same_responses_have_no_change():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert not result.response_changed


def test_protection_change_is_recorded():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(),
        response(),
        analysis,
        protection_changed=True,
    )

    assert result.protection_changed
    assert any(
        "Protection changed: True" in item
        for item in result.evidence
    )


def test_protection_change_alone_does_not_confirm_csrf():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(),
        response(),
        analysis,
        protection_changed=True,
    )

    assert not result.potential_csrf


def test_response_change_without_indicator_is_not_potential_csrf():
    result = CSRFValidator().validate(
        response(content=b"before"),
        response(content=b"after"),
        CSRFAnalysis(),
    )

    assert result.response_changed
    assert not result.potential_csrf
    assert result.status == "no_indicator"


def test_status_change_without_indicator_is_not_potential_csrf():
    result = CSRFValidator().validate(
        response(status_code=200),
        response(status_code=403),
        CSRFAnalysis(),
    )

    assert result.status_changed
    assert not result.potential_csrf


def test_candidate_status_is_preserved():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(status_code=200),
        response(status_code=201),
        analysis,
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 201


def test_evidence_is_populated():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.evidence
    assert all(result.evidence)


def test_result_is_dataclass():
    result = CSRFValidator().validate(
        response(),
        response(),
        CSRFAnalysis(),
    )

    assert isinstance(result, CSRFValidationResult)


def test_invalid_baseline_type_is_rejected():
    try:
        CSRFValidator().validate(
            {},
            response(),
            CSRFAnalysis(),
        )
    except TypeError as exc:
        assert "HttpResponse" in str(exc)
    else:
        raise AssertionError("Expected TypeError")


def test_invalid_candidate_type_is_rejected():
    try:
        CSRFValidator().validate(
            response(),
            {},
            CSRFAnalysis(),
        )
    except TypeError as exc:
        assert "HttpResponse" in str(exc)
    else:
        raise AssertionError("Expected TypeError")


def test_invalid_analysis_type_is_rejected():
    try:
        CSRFValidator().validate(
            response(),
            response(),
            {},
        )
    except TypeError as exc:
        assert "CSRFAnalysis" in str(exc)
    else:
        raise AssertionError("Expected TypeError")


def test_multiple_response_changes_are_recorded():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(
            status_code=200,
            content=b"before",
        ),
        response(
            status_code=403,
            content=b"after",
        ),
        analysis,
    )

    assert result.status_changed
    assert result.content_changed
    assert result.content_length_changed
    assert result.response_changed


def test_potential_csrf_requires_indicator_and_response_change():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFValidator().validate(
        response(content=b"one"),
        response(content=b"two"),
        analysis,
    )

    assert analysis.detected
    assert result.response_changed
    assert result.potential_csrf


def test_indicator_detected_status_without_response_change():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFValidator().validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert result.status == "indicator_detected"
    assert not result.potential_csrf


def test_status_values_are_valid():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.status in {
        "no_indicator",
        "indicator_detected",
        "potential_csrf",
    }


def test_no_false_confirmation_language():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.potential_csrf
    assert result.status == "potential_csrf"
    assert "confirmed" not in " ".join(
        result.evidence
    ).lower()


def test_empty_body_response_comparison():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFValidator().validate(
        response(content=b""),
        response(content=b"changed"),
        analysis,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_csrf


def test_header_changes_are_not_used_as_confirmation():
    analysis = CSRFAnalyzer().analyze("POST")

    baseline = response(headers={"X-Test": "one"})
    candidate = response(headers={"X-Test": "two"})

    result = CSRFValidator().validate(
        baseline,
        candidate,
        analysis,
    )

    assert not result.response_changed
    assert not result.potential_csrf
