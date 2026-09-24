import pytest

from m_hunter.analyzers.cookies import (
    CookieAnalysis,
    CookieAnalyzer,
    CookieSecurity,
)


def make_cookie(
    name="session",
    value="abc123",
    secure=True,
    httponly=True,
    samesite="Lax",
    domain=None,
    path="/",
    expires=None,
    max_age=None,
):
    return CookieSecurity(
        name=name,
        value=value,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        domain=domain,
        path=path,
        expires=expires,
        max_age=max_age,
    )


def test_cookie_security_fields():
    cookie = make_cookie()

    assert cookie.name == "session"
    assert cookie.value == "abc123"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "Lax"
    assert cookie.path == "/"


def test_session_cookie_detection():
    cookie = make_cookie(
        name="sessionid"
    )

    assert cookie.is_session_cookie is True


def test_non_session_cookie_detection():
    cookie = make_cookie(
        name="theme"
    )

    assert cookie.is_session_cookie is False


def test_session_detection_is_case_insensitive():
    cookie = make_cookie(
        name="JSESSIONID"
    )

    assert cookie.is_session_cookie is True


def test_secure_transport():
    secure = make_cookie(
        secure=True
    )

    insecure = make_cookie(
        secure=False
    )

    assert secure.has_secure_transport is True
    assert insecure.has_secure_transport is False


def test_httponly_protection():
    protected = make_cookie(
        httponly=True
    )

    unprotected = make_cookie(
        httponly=False
    )

    assert protected.protects_from_script_access is True
    assert unprotected.protects_from_script_access is False


def test_samesite_protection():
    protected = make_cookie(
        samesite="Lax"
    )

    missing = make_cookie(
        samesite=None
    )

    assert protected.has_samesite_protection is True
    assert missing.has_samesite_protection is False


def test_persistent_cookie_by_expires():
    cookie = make_cookie(
        expires="Wed, 21 Oct 2026 07:28:00 GMT"
    )

    assert cookie.persistent is True


def test_persistent_cookie_by_max_age():
    cookie = make_cookie(
        max_age="3600"
    )

    assert cookie.persistent is True


def test_session_cookie_without_expiry_is_not_persistent():
    cookie = make_cookie(
        expires=None,
        max_age=None,
    )

    assert cookie.persistent is False


def test_empty_cookie_analysis():
    analysis = CookieAnalysis()

    assert analysis.count == 0
    assert analysis.session_count == 0
    assert analysis.session_cookies == []
    assert analysis.insecure_cookies == []
    assert analysis.httponly_missing == []
    assert analysis.samesite_missing == []


def test_cookie_analysis_counts():
    analysis = CookieAnalysis(
        cookies=[
            make_cookie(
                name="session",
                secure=True,
                httponly=True,
                samesite="Lax",
            ),
            make_cookie(
                name="theme",
                secure=False,
                httponly=False,
                samesite=None,
            ),
        ]
    )

    assert analysis.count == 2
    assert analysis.session_count == 1


def test_insecure_cookies():
    analysis = CookieAnalysis(
        cookies=[
            make_cookie(
                name="session",
                secure=True,
            ),
            make_cookie(
                name="theme",
                secure=False,
            ),
        ]
    )

    assert [
        cookie.name
        for cookie in analysis.insecure_cookies
    ] == ["theme"]


def test_httponly_missing():
    analysis = CookieAnalysis(
        cookies=[
            make_cookie(
                name="session",
                httponly=True,
            ),
            make_cookie(
                name="theme",
                httponly=False,
            ),
        ]
    )

    assert [
        cookie.name
        for cookie in analysis.httponly_missing
    ] == ["theme"]


def test_samesite_missing():
    analysis = CookieAnalysis(
        cookies=[
            make_cookie(
                name="session",
                samesite="Strict",
            ),
            make_cookie(
                name="theme",
                samesite=None,
            ),
        ]
    )

    assert [
        cookie.name
        for cookie in analysis.samesite_missing
    ] == ["theme"]


def test_get_cookie():
    analysis = CookieAnalysis(
        cookies=[
            make_cookie(
                name="SessionID"
            )
        ]
    )

    assert analysis.get(
        "sessionid"
    ) is not None

    assert analysis.get(
        "missing"
    ) is None


def test_analyzer_requires_dictionary():
    with pytest.raises(TypeError):
        CookieAnalyzer().analyze(
            ["session=abc"]
        )


def test_analyzer_creates_cookie_analysis():
    result = CookieAnalyzer().analyze(
        {
            "session": "abc123",
            "theme": "dark",
        }
    )

    assert isinstance(
        result,
        CookieAnalysis,
    )

    assert result.count == 2


def test_analyzer_preserves_cookie_values():
    result = CookieAnalyzer().analyze(
        {
            "session": "abc123",
            "theme": "dark",
        }
    )

    assert result.get(
        "session"
    ).value == "abc123"

    assert result.get(
        "theme"
    ).value == "dark"


def test_analyzer_skips_empty_names():
    result = CookieAnalyzer().analyze(
        {
            "": "ignored",
            "session": "abc",
        }
    )

    assert result.count == 1


def test_analyzer_requires_string_names():
    with pytest.raises(TypeError):
        CookieAnalyzer().analyze(
            {
                123: "value",
            }
        )


def test_cookie_values_are_converted_to_strings():
    result = CookieAnalyzer().analyze(
        {
            "session": 12345,
        }
    )

    assert result.get(
        "session"
    ).value == "12345"
