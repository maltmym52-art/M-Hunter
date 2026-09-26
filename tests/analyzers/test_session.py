import pytest

from m_hunter.analyzers.session import (
    SessionAnalyzer,
    SessionIndicatorType,
)


@pytest.fixture
def analyzer():
    return SessionAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()
    assert result.detected is False
    assert result.count == 0
    assert result.types == set()


def test_explicit_session_cookie(analyzer):
    result = analyzer.analyze(session_cookie=True)
    assert result.session_cookie
    assert result.count == 1


def test_explicit_session_token(analyzer):
    result = analyzer.analyze(session_token=True)
    assert result.session_token


def test_explicit_fixation_indicator(analyzer):
    result = analyzer.analyze(fixation_indicator=True)
    assert result.fixation_indicator


def test_explicit_rotation(analyzer):
    result = analyzer.analyze(rotation=True)
    assert result.rotation


def test_explicit_timeout(analyzer):
    result = analyzer.analyze(timeout=True)
    assert result.timeout


def test_explicit_logout(analyzer):
    result = analyzer.analyze(logout=True)
    assert result.logout


def test_explicit_invalidation(analyzer):
    result = analyzer.analyze(invalidation=True)
    assert result.invalidation


def test_explicit_long_lived(analyzer):
    result = analyzer.analyze(long_lived=True)
    assert result.long_lived_session


def test_explicit_concurrent(analyzer):
    result = analyzer.analyze(concurrent=True)
    assert result.concurrent_session


def test_explicit_token_exposure(analyzer):
    result = analyzer.analyze(token_exposure=True)
    assert result.token_exposure


def test_explicit_weak_cookie_name(analyzer):
    result = analyzer.analyze(weak_cookie_name=True)
    assert result.weak_session_cookie_name


def test_session_cookie_detected(analyzer):
    result = analyzer.analyze(
        cookies={"sessionid": "abc123"},
    )
    assert result.session_cookie
    assert "sessionid" in result.names


def test_jsessionid_detected(analyzer):
    result = analyzer.analyze(
        cookies={"JSESSIONID": "abc123"},
    )
    assert result.session_cookie


def test_connect_sid_detected(analyzer):
    result = analyzer.analyze(
        cookies={"connect.sid": "abc123"},
    )
    assert result.session_cookie


def test_generic_sid_is_weak_name(analyzer):
    result = analyzer.analyze(
        cookies={"sid": "abc123"},
    )
    assert result.session_cookie
    assert result.weak_session_cookie_name


def test_session_set_cookie_detected(analyzer):
    result = analyzer.analyze(
        headers={"Set-Cookie": "sessionid=abc123; Secure; HttpOnly"},
    )
    assert result.session_cookie


def test_cookie_lifetime_detected(analyzer):
    result = analyzer.analyze(
        headers={"Set-Cookie": "sessionid=abc123; Max-Age=3600"},
    )
    assert result.long_lived_session


def test_cookie_expires_detected(analyzer):
    result = analyzer.analyze(
        headers={"Set-Cookie": "sessionid=abc123; Expires=Wed, 21 Oct 2030 07:28:00 GMT"},
    )
    assert result.long_lived_session


def test_session_parameter_detected(analyzer):
    result = analyzer.analyze(
        params={"sessionid": "abc123"},
    )
    assert result.session_token
    assert result.session_id_in_url


def test_sid_parameter_detected(analyzer):
    result = analyzer.analyze(
        params={"sid": "abc123"},
    )
    assert result.session_id_in_url


def test_token_parameter_exposure(analyzer):
    result = analyzer.analyze(
        params={"access_token": "secret"},
    )
    assert result.session_token
    assert result.token_exposure


def test_session_id_in_url(analyzer):
    result = analyzer.analyze(
        url="https://example.com/account?sessionid=abc123",
    )
    assert result.session_id_in_url


def test_token_in_url(analyzer):
    result = analyzer.analyze(
        url="https://example.com/callback?access_token=secret",
    )
    assert result.token_exposure
    assert result.session_id_in_url


def test_bearer_header_detected(analyzer):
    result = analyzer.analyze(
        headers={"Authorization": "Bearer abc123"},
    )
    assert result.session_token


def test_basic_auth_header_detected(analyzer):
    result = analyzer.analyze(
        headers={"Authorization": "Basic YWJjOmRlZg=="},
    )
    assert result.session_token


def test_indicator_types_are_unique(analyzer):
    result = analyzer.analyze(
        session_cookie=True,
        session_token=True,
        timeout=True,
    )
    assert len(result.types) == 3


def test_duplicate_analysis_is_deduplicated(analyzer):
    result = analyzer.analyze(
        cookies={"sessionid": "abc123"},
        params={"sessionid": "abc123"},
    )
    assert result.count < 5


def test_invalid_cookie_values_do_not_crash(analyzer):
    result = analyzer.analyze(
        cookies={"sessionid": ""},
    )
    assert result.session_cookie


def test_multiple_cookies(analyzer):
    result = analyzer.analyze(
        cookies={
            "sessionid": "abc",
            "tracking": "xyz",
            "JSESSIONID": "def",
        },
    )
    assert result.session_cookie
    assert result.count >= 2


def test_analysis_exposes_all_indicators(analyzer):
    result = analyzer.analyze(
        session_cookie=True,
        session_token=True,
        fixation_indicator=True,
        rotation=True,
        timeout=True,
        logout=True,
        invalidation=True,
        long_lived=True,
        concurrent=True,
        token_exposure=True,
        weak_cookie_name=True,
    )

    expected = {
        SessionIndicatorType.SESSION_COOKIE,
        SessionIndicatorType.SESSION_TOKEN,
        SessionIndicatorType.SESSION_FIXATION_INDICATOR,
        SessionIndicatorType.SESSION_ROTATION,
        SessionIndicatorType.SESSION_TIMEOUT,
        SessionIndicatorType.SESSION_LOGOUT,
        SessionIndicatorType.SESSION_INVALIDATION,
        SessionIndicatorType.LONG_LIVED_SESSION,
        SessionIndicatorType.CONCURRENT_SESSION,
        SessionIndicatorType.TOKEN_EXPOSURE,
        SessionIndicatorType.WEAK_SESSION_COOKIE_NAME,
    }

    assert result.types == expected
    assert result.count == len(expected)


def test_none_inputs_are_supported(analyzer):
    result = analyzer.analyze(
        url=None,
        params=None,
        cookies=None,
        headers=None,
    )
    assert not result.detected


def test_header_names_are_case_insensitive(analyzer):
    result = analyzer.analyze(
        headers={"sEt-CoOkIe": "sessionid=abc; Max-Age=100"},
    )
    assert result.session_cookie
    assert result.long_lived_session
