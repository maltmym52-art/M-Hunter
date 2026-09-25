import pytest

from m_hunter.analyzers.oauth import (
    OAuthAnalyzer,
    OAuthIndicatorType,
)
from m_hunter.validation.oauth import (
    OAuthValidationResult,
    OAuthValidator,
)


@pytest.fixture
def analyzer():
    return OAuthAnalyzer()


@pytest.fixture
def validator():
    return OAuthValidator()


def test_no_indicator(
    analyzer,
    validator,
):
    analysis = analyzer.analyze()

    result = validator.validate(analysis)

    assert isinstance(result, OAuthValidationResult)
    assert result.status == "no_indicator"
    assert result.potential_oauth_issue is False
    assert result.response_changed is False
    assert result.evidence == (
        ()
    )


def test_indicator_detected_without_behavior_change(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client-123",
    )

    result = validator.validate(analysis)

    assert result.status == "indicator_detected"
    assert result.potential_oauth_issue is False
    assert result.response_changed is False
    assert "OAuth security indicators" in result.evidence[-1]


def test_status_change(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        state="random-state-value",
    )

    result = validator.validate(
        analysis,
        baseline_status=302,
        candidate_status=200,
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_oauth_issue is True
    assert result.status == "potential_oauth_issue"


def test_same_status(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        baseline_status=302,
        candidate_status=302,
    )

    assert result.status_changed is False
    assert result.response_changed is False
    assert result.potential_oauth_issue is False


def test_content_change(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        redirect_uri="https://client.example/callback",
    )

    result = validator.validate(
        analysis,
        baseline_content="authorization page",
        candidate_content="different page",
    )

    assert result.content_changed is True
    assert result.response_changed is True
    assert result.potential_oauth_issue is True


def test_identical_content(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        baseline_content="same",
        candidate_content="same",
    )

    assert result.content_changed is False
    assert result.content_length_changed is False
    assert result.response_changed is False


def test_content_length_change(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        scope="openid",
    )

    result = validator.validate(
        analysis,
        baseline_content="short",
        candidate_content="much longer response",
    )

    assert result.content_length_changed is True
    assert result.response_changed is True


def test_header_change(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        response_type="code",
    )

    result = validator.validate(
        analysis,
        baseline_headers={
            "Location": "https://client.example/callback"
        },
        candidate_headers={
            "Location": "https://attacker.example/callback"
        },
    )

    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_oauth_issue is True


def test_header_name_comparison_is_case_insensitive(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        baseline_headers={
            "Content-Type": "application/json"
        },
        candidate_headers={
            "content-type": "application/json"
        },
    )

    assert result.headers_changed is False


def test_behavior_change(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        state="random-state",
    )

    result = validator.validate(
        analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed is True
    assert result.response_changed is False
    assert result.potential_oauth_issue is True
    assert result.status == "potential_oauth_issue"


def test_behavior_change_without_indicator(
    analyzer,
    validator,
):
    analysis = analyzer.analyze()

    result = validator.validate(
        analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed is True
    assert result.potential_oauth_issue is False
    assert result.status == "behavior_changed"


@pytest.mark.parametrize(
    "indicator",
    [
        {"state": "random-state"},
        {"nonce": "random-nonce"},
        {"client_id": "client"},
        {"scope": "openid"},
        {"response_type": "code"},
        {"grant_type": "authorization_code"},
        {"redirect_uri": "https://client.example/callback"},
    ],
)
def test_detected_indicator_is_preserved(
    analyzer,
    validator,
    indicator,
):
    analysis = analyzer.analyze(**indicator)

    assert analysis.detected is True

    result = validator.validate(analysis)

    assert result.status == "indicator_detected"
    assert result.potential_oauth_issue is False


def test_token_indicator_with_response_change(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        fragment="access_token=secret",
    )

    assert OAuthIndicatorType.TOKEN_IN_URL in analysis.types

    result = validator.validate(
        analysis,
        baseline_status=302,
        candidate_status=200,
    )

    assert result.potential_oauth_issue is True


def test_missing_nonce_with_behavior_change(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        response_type="id_token",
        expected_nonce=True,
    )

    assert analysis.has_missing_nonce_indicator

    result = validator.validate(
        analysis,
        behavior_changed=True,
    )

    assert result.potential_oauth_issue is True


def test_multiple_response_changes(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        baseline_status=302,
        candidate_status=200,
        baseline_content="old",
        candidate_content="new content",
        baseline_headers={"Location": "/old"},
        candidate_headers={"Location": "/new"},
    )

    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is True
    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_oauth_issue is True
    assert len(result.evidence) >= 4


@pytest.mark.parametrize(
    "baseline,candidate",
    [
        (None, None),
        (200, None),
        (None, 200),
    ],
)
def test_partial_status_information(
    analyzer,
    validator,
    baseline,
    candidate,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        baseline_status=baseline,
        candidate_status=candidate,
    )

    assert result.status_changed is False


@pytest.mark.parametrize(
    "baseline,candidate",
    [
        (None, None),
        (None, "candidate"),
        ("baseline", None),
    ],
)
def test_partial_content_information(
    analyzer,
    validator,
    baseline,
    candidate,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        baseline_content=baseline,
        candidate_content=candidate,
    )

    assert result.content_changed is False
    assert result.content_length_changed is False


def test_empty_headers_do_not_trigger_change(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        baseline_headers={},
        candidate_headers={},
    )

    assert result.headers_changed is False


def test_validation_result_is_immutable(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(analysis)

    with pytest.raises(AttributeError):
        result.status = "changed"


def test_invalid_analysis_type(validator):
    with pytest.raises(TypeError):
        validator.validate(object())


@pytest.mark.parametrize(
    "value",
    [
        [],
        "invalid",
        123,
    ],
)
def test_invalid_baseline_headers(
    analyzer,
    validator,
    value,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    with pytest.raises(TypeError):
        validator.validate(
            analysis,
            baseline_headers=value,
        )


@pytest.mark.parametrize(
    "value",
    [
        [],
        "invalid",
        123,
    ],
)
def test_invalid_candidate_headers(
    analyzer,
    validator,
    value,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    with pytest.raises(TypeError):
        validator.validate(
            analysis,
            candidate_headers=value,
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
    ],
)
def test_valid_behavior_change_values(
    analyzer,
    validator,
    value,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        behavior_changed=value if value is not None else False,
    )

    assert isinstance(result, OAuthValidationResult)


@pytest.mark.parametrize(
    "value",
    [
        1,
        0,
        "true",
        [],
    ],
)
def test_invalid_behavior_change_type(
    analyzer,
    validator,
    value,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    with pytest.raises(TypeError):
        validator.validate(
            analysis,
            behavior_changed=value,
        )


def test_evidence_contains_all_changed_dimensions(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        baseline_status=302,
        candidate_status=200,
        baseline_content="a",
        candidate_content="bb",
        baseline_headers={"A": "1"},
        candidate_headers={"A": "2"},
        behavior_changed=True,
    )

    evidence = "\n".join(result.evidence)

    assert "status codes differ" in evidence
    assert "response content differ" in evidence
    assert "content lengths differ" in evidence
    assert "response headers differ" in evidence
    assert "behavior changed" in evidence


def test_result_preserves_status_codes(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = validator.validate(
        analysis,
        baseline_status=302,
        candidate_status=200,
    )

    assert result.baseline_status == 302
    assert result.candidate_status == 200


def test_analysis_can_contain_multiple_indicators(
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        client_id="client",
        state="short",
        response_type="token",
        fragment="access_token=secret",
    )

    result = validator.validate(
        analysis,
        behavior_changed=True,
    )

    assert result.potential_oauth_issue is True
    assert result.status == "potential_oauth_issue"
