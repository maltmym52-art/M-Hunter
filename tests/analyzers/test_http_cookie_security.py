from m_hunter.analyzers.http_cookie_security import (
    CookieSecurityIndicatorType,
    HttpCookieSecurityAnalyzer,
)


def test_cookie_present():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
    )

    assert result.has_type(CookieSecurityIndicatorType.COOKIE_PRESENT)


def test_secure_missing():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        secure=False,
    )

    assert result.has_type(CookieSecurityIndicatorType.SECURE_MISSING)


def test_httponly_missing():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        httponly=False,
    )

    assert result.has_type(CookieSecurityIndicatorType.HTTPONLY_MISSING)


def test_samesite_missing():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        samesite=None,
    )

    assert result.has_type(CookieSecurityIndicatorType.SAMESITE_MISSING)


def test_samesite_none():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        samesite="None",
    )

    assert result.has_type(CookieSecurityIndicatorType.SAMESITE_NONE)


def test_samesite_invalid():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        samesite="invalid",
    )

    assert result.has_type(CookieSecurityIndicatorType.SAMESITE_INVALID)


def test_domain_broad():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        domain=".example.com",
    )

    assert result.has_type(CookieSecurityIndicatorType.DOMAIN_BROAD)


def test_domain_missing():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        domain=None,
    )

    assert result.has_type(CookieSecurityIndicatorType.DOMAIN_MISSING)


def test_path_broad():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        path="/",
    )

    assert result.has_type(CookieSecurityIndicatorType.PATH_BROAD)


def test_path_missing():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        path=None,
    )

    assert result.has_type(CookieSecurityIndicatorType.PATH_MISSING)


def test_session_cookie():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        is_session_cookie=True,
    )

    assert result.has_type(CookieSecurityIndicatorType.SESSION_COOKIE)


def test_persistent_cookie():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="remember",
        is_session_cookie=False,
    )

    assert result.has_type(CookieSecurityIndicatorType.PERSISTENT_COOKIE)


def test_long_lived_max_age():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="remember",
        max_age=31536001,
    )

    assert result.has_type(CookieSecurityIndicatorType.LONG_LIVED_COOKIE)


def test_long_lived_expires():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="remember",
        expires_seconds=31536001,
    )

    assert result.has_type(CookieSecurityIndicatorType.LONG_LIVED_COOKIE)


def test_host_prefix_violation():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="__Host-session",
        secure=False,
        domain="example.com",
        path="/",
    )

    assert result.has_type(CookieSecurityIndicatorType.PREFIX_VIOLATION)


def test_host_prefix_valid():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="__Host-session",
        secure=True,
        domain=None,
        path="/",
    )

    assert not result.has_type(CookieSecurityIndicatorType.PREFIX_VIOLATION)


def test_secure_prefix_violation():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="__Secure-session",
        secure=False,
    )

    assert result.has_type(CookieSecurityIndicatorType.PREFIX_VIOLATION)


def test_secure_prefix_valid():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="__Secure-session",
        secure=True,
    )

    assert not result.has_type(CookieSecurityIndicatorType.PREFIX_VIOLATION)


def test_duplicate_cookie():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        duplicate_cookie=True,
    )

    assert result.has_type(CookieSecurityIndicatorType.DUPLICATE_COOKIE)


def test_multiple_cookies():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        cookie_count=3,
    )

    assert result.has_type(CookieSecurityIndicatorType.MULTIPLE_COOKIES)


def test_count():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        secure=False,
        httponly=False,
    )

    assert result.count == len(result.indicators)


def test_types():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
    )

    assert all(
        isinstance(item, CookieSecurityIndicatorType)
        for item in result.types
    )


def test_names():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
    )

    assert result.names
    assert all(isinstance(name, str) for name in result.names)


def test_has_type_false():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
    )

    assert not result.has_type(CookieSecurityIndicatorType.DUPLICATE_COOKIE)


def test_secure_cookie():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        secure=True,
        httponly=True,
        samesite="Strict",
        domain=None,
        path="/login",
    )

    assert not result.has_type(CookieSecurityIndicatorType.SECURE_MISSING)
    assert not result.has_type(CookieSecurityIndicatorType.HTTPONLY_MISSING)
    assert not result.has_type(CookieSecurityIndicatorType.SAMESITE_MISSING)


def test_multiple_security_properties():
    result = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        secure=False,
        httponly=False,
        samesite="None",
        domain=".example.com",
        path="/",
        max_age=40000000,
        duplicate_cookie=True,
        cookie_count=3,
    )

    assert result.has_type(CookieSecurityIndicatorType.SECURE_MISSING)
    assert result.has_type(CookieSecurityIndicatorType.HTTPONLY_MISSING)
    assert result.has_type(CookieSecurityIndicatorType.SAMESITE_NONE)
    assert result.has_type(CookieSecurityIndicatorType.DOMAIN_BROAD)
    assert result.has_type(CookieSecurityIndicatorType.PATH_BROAD)
    assert result.has_type(CookieSecurityIndicatorType.LONG_LIVED_COOKIE)
    assert result.has_type(CookieSecurityIndicatorType.DUPLICATE_COOKIE)
    assert result.has_type(CookieSecurityIndicatorType.MULTIPLE_COOKIES)
