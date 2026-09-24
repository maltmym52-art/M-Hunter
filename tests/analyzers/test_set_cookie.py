import pytest

from m_hunter.analyzers.set_cookie import (
    SetCookie,
    SetCookieParser,
)


def test_parse_basic_cookie():
    cookie = SetCookieParser().parse(
        "session=abc123"
    )

    assert cookie.name == "session"
    assert cookie.value == "abc123"
    assert cookie.secure is False
    assert cookie.httponly is False


def test_parse_secure_cookie():
    cookie = SetCookieParser().parse(
        "session=abc123; Secure"
    )

    assert cookie.secure is True


def test_parse_httponly_cookie():
    cookie = SetCookieParser().parse(
        "session=abc123; HttpOnly"
    )

    assert cookie.httponly is True


def test_parse_samesite():
    cookie = SetCookieParser().parse(
        "session=abc123; SameSite=Lax"
    )

    assert cookie.samesite == "Lax"


def test_parse_samesite_strict():
    cookie = SetCookieParser().parse(
        "session=abc123; SameSite=Strict"
    )

    assert cookie.samesite == "Strict"


def test_parse_samesite_none():
    cookie = SetCookieParser().parse(
        "session=abc123; SameSite=None"
    )

    assert cookie.samesite == "None"


def test_parse_domain():
    cookie = SetCookieParser().parse(
        "session=abc123; Domain=example.com"
    )

    assert cookie.domain == "example.com"


def test_parse_path():
    cookie = SetCookieParser().parse(
        "session=abc123; Path=/account"
    )

    assert cookie.path == "/account"


def test_parse_expires():
    cookie = SetCookieParser().parse(
        "session=abc123; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
    )

    assert cookie.expires == (
        "Wed, 21 Oct 2026 07:28:00 GMT"
    )


def test_parse_max_age():
    cookie = SetCookieParser().parse(
        "session=abc123; Max-Age=3600"
    )

    assert cookie.max_age == "3600"


def test_parse_full_cookie():
    cookie = SetCookieParser().parse(
        "session=abc123; "
        "Secure; "
        "HttpOnly; "
        "SameSite=Strict; "
        "Domain=example.com; "
        "Path=/; "
        "Max-Age=3600"
    )

    assert cookie.name == "session"
    assert cookie.value == "abc123"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "Strict"
    assert cookie.domain == "example.com"
    assert cookie.path == "/"
    assert cookie.max_age == "3600"


def test_attribute_names_are_case_insensitive():
    cookie = SetCookieParser().parse(
        "session=abc; "
        "SECURE; "
        "HTTPONLY; "
        "SAMESITE=Lax; "
        "DOMAIN=example.com; "
        "PATH=/"
    )

    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "Lax"
    assert cookie.domain == "example.com"
    assert cookie.path == "/"


def test_cookie_value_can_contain_equals():
    cookie = SetCookieParser().parse(
        "token=abc=def=123; Secure"
    )

    assert cookie.value == "abc=def=123"


def test_session_cookie_detection():
    cookie = SetCookieParser().parse(
        "JSESSIONID=abc"
    )

    assert cookie.is_session_cookie is True


def test_normal_cookie_is_not_session_cookie():
    cookie = SetCookieParser().parse(
        "theme=dark"
    )

    assert cookie.is_session_cookie is False


def test_persistent_cookie_with_expires():
    cookie = SetCookieParser().parse(
        "theme=dark; "
        "Expires=Wed, 21 Oct 2026 07:28:00 GMT"
    )

    assert cookie.persistent is True


def test_persistent_cookie_with_max_age():
    cookie = SetCookieParser().parse(
        "theme=dark; Max-Age=3600"
    )

    assert cookie.persistent is True


def test_session_cookie_without_expiry_is_not_persistent():
    cookie = SetCookieParser().parse(
        "session=abc"
    )

    assert cookie.persistent is False


def test_parse_many():
    headers = [
        "session=abc; Secure; HttpOnly",
        "theme=dark; Path=/",
        "token=xyz; SameSite=Lax",
    ]

    cookies = SetCookieParser().parse_many(
        headers
    )

    assert len(cookies) == 3
    assert cookies[0].name == "session"
    assert cookies[1].name == "theme"
    assert cookies[2].name == "token"


def test_parse_many_requires_list():
    with pytest.raises(TypeError):
        SetCookieParser().parse_many(
            "session=abc"
        )


def test_empty_header_rejected():
    with pytest.raises(ValueError):
        SetCookieParser().parse("")


def test_invalid_header_rejected():
    with pytest.raises(ValueError):
        SetCookieParser().parse(
            "invalid-cookie"
        )


def test_empty_cookie_name_rejected():
    with pytest.raises(ValueError):
        SetCookieParser().parse(
            "=abc; Secure"
        )


def test_non_string_header_rejected():
    with pytest.raises(TypeError):
        SetCookieParser().parse(123)


def test_cookie_dataclass():
    cookie = SetCookie(
        name="session",
        value="abc",
        secure=True,
        httponly=True,
        samesite="Lax",
        domain="example.com",
        path="/",
    )

    assert cookie.name == "session"
    assert cookie.secure is True
    assert cookie.httponly is True
