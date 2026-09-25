import pytest

from m_hunter.analyzers.oauth import (
    OAuthAnalysis,
    OAuthAnalyzer,
    OAuthIndicatorType,
)


@pytest.fixture
def analyzer():
    return OAuthAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()

    assert isinstance(result, OAuthAnalysis)
    assert result.detected is False
    assert result.count == 0
    assert result.types == ()
    assert result.names == ()
    assert result.indicators == ()


def test_oauth_authorization_url(analyzer):
    result = analyzer.analyze(
        "https://example.com/oauth/authorize"
    )

    assert result.detected is True
    assert result.has_redirect_uri


def test_query_parameters_are_detected(analyzer):
    result = analyzer.analyze(
        "https://example.com/authorize"
        "?client_id=abc"
        "&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback"
        "&response_type=code"
        "&scope=openid+profile"
        "&state=long-random-state"
    )

    assert result.has_client_id
    assert result.has_redirect_uri
    assert result.has_response_type
    assert result.has_scope
    assert result.has_state


@pytest.mark.parametrize(
    "indicator_type, kwargs",
    [
        (
            OAuthIndicatorType.RESPONSE_TYPE,
            {"response_type": "code"},
        ),
        (
            OAuthIndicatorType.GRANT_TYPE,
            {"grant_type": "authorization_code"},
        ),
        (
            OAuthIndicatorType.CLIENT_ID,
            {"client_id": "client-123"},
        ),
        (
            OAuthIndicatorType.SCOPE,
            {"scope": "openid profile"},
        ),
        (
            OAuthIndicatorType.STATE_PARAMETER,
            {"state": "random-state-value"},
        ),
        (
            OAuthIndicatorType.NONCE_PARAMETER,
            {"nonce": "random-nonce-value"},
        ),
        (
            OAuthIndicatorType.REDIRECT_URI,
            {"redirect_uri": "https://client.example/callback"},
        ),
    ],
)
def test_individual_oauth_indicators(
    analyzer,
    indicator_type,
    kwargs,
):
    result = analyzer.analyze(**kwargs)

    assert indicator_type in result.types


def test_short_state_is_flagged(analyzer):
    result = analyzer.analyze(state="abc")

    assert result.has_state
    assert result.has_weak_state_indicator


def test_normal_state_is_not_flagged_as_weak(analyzer):
    result = analyzer.analyze(
        state="a-long-random-state-value"
    )

    assert result.has_state
    assert not result.has_weak_state_indicator


def test_nonce_detected(analyzer):
    result = analyzer.analyze(
        nonce="random-nonce-value"
    )

    assert result.has_nonce
    assert not result.has_missing_nonce_indicator


def test_expected_nonce_missing(analyzer):
    result = analyzer.analyze(
        response_type="id_token",
        expected_nonce=True,
    )

    assert result.has_missing_nonce_indicator


def test_expected_nonce_present(analyzer):
    result = analyzer.analyze(
        response_type="id_token",
        expected_nonce=True,
        nonce="random-nonce-value",
    )

    assert result.has_nonce
    assert not result.has_missing_nonce_indicator


def test_token_in_query(analyzer):
    result = analyzer.analyze(
        "https://example.com/callback?access_token=secret"
    )

    assert result.has_token_in_url


def test_token_in_fragment(analyzer):
    result = analyzer.analyze(
        "https://example.com/callback",
        fragment="access_token=secret",
    )

    assert result.has_token_in_url


def test_token_response_type(analyzer):
    result = analyzer.analyze(
        response_type="token"
    )

    assert result.has_token_in_url


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://client.example/callback",
        "//client.example/callback",
    ],
)
def test_redirect_uri_requires_strict_validation(
    analyzer,
    redirect_uri,
):
    result = analyzer.analyze(
        redirect_uri=redirect_uri
    )

    assert result.has_open_redirect_indicator


def test_redirect_uri_userinfo_indicator(analyzer):
    result = analyzer.analyze(
        redirect_uri="https://user@example.com/callback"
    )

    assert result.has_open_redirect_indicator


def test_url_fragment_is_analyzed(analyzer):
    result = analyzer.analyze(
        "https://example.com/callback#access_token=value"
    )

    assert result.has_token_in_url


def test_headers_are_accepted(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        },
        client_id="abc",
    )

    assert result.has_client_id


def test_explicit_arguments_override_query_values(analyzer):
    result = analyzer.analyze(
        "https://example.com/authorize?client_id=query-client",
        client_id="explicit-client",
    )

    client_indicators = [
        item
        for item in result.indicators
        if item.type == OAuthIndicatorType.CLIENT_ID
    ]

    assert client_indicators
    assert client_indicators[0].value == "explicit-client"


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"client_id": "abc"},
    ],
)
def test_params_accept_valid_values(analyzer, value):
    result = analyzer.analyze(params=value)

    assert isinstance(result, OAuthAnalysis)


@pytest.mark.parametrize(
    "value",
    [
        [],
        "invalid",
        123,
    ],
)
def test_invalid_params_type(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(params=value)


@pytest.mark.parametrize(
    "value",
    [
        [],
        123,
        object(),
    ],
)
def test_invalid_url_type(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(url=value)


@pytest.mark.parametrize(
    "value",
    [
        [],
        123,
        object(),
    ],
)
def test_invalid_fragment_type(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(fragment=value)


@pytest.mark.parametrize(
    "value",
    [
        [],
        123,
        object(),
    ],
)
def test_invalid_headers_type(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(headers=value)


def test_unique_types_and_names(analyzer):
    result = analyzer.analyze(
        client_id="abc",
        state="abc",
        response_type="code",
    )

    assert result.types.count(
        OAuthIndicatorType.CLIENT_ID
    ) == 1

    assert result.names.count("client_id") == 1
    assert result.count >= 3


def test_analysis_is_immutable(analyzer):
    result = analyzer.analyze(client_id="abc")

    with pytest.raises(AttributeError):
        result.detected = False
