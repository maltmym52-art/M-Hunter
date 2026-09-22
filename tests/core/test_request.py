import pytest

from m_hunter.core.request import HttpRequest


def test_request_defaults():
    request = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    assert request.method == "GET"
    assert request.url == "https://example.com"
    assert request.headers == {}
    assert request.cookies == {}
    assert request.params == {}
    assert request.body is None


def test_request_normalizes_method():
    request = HttpRequest(
        method="post",
        url="https://example.com",
    )

    assert request.method == "POST"


def test_request_preserves_url():
    url = "https://example.com/login"

    request = HttpRequest(
        method="GET",
        url=url,
    )

    assert request.url == url


def test_request_accepts_headers():
    headers = {
        "Authorization": "Bearer test",
        "Content-Type": "application/json",
    }

    request = HttpRequest(
        method="POST",
        url="https://example.com/api",
        headers=headers,
    )

    assert request.headers == headers


def test_request_accepts_cookies():
    cookies = {
        "session": "abc123",
    }

    request = HttpRequest(
        method="GET",
        url="https://example.com",
        cookies=cookies,
    )

    assert request.cookies == cookies


def test_request_accepts_params():
    params = {
        "page": "1",
        "limit": "10",
    }

    request = HttpRequest(
        method="GET",
        url="https://example.com/users",
        params=params,
    )

    assert request.params == params


def test_request_accepts_body():
    body = {
        "username": "test",
        "password": "secret",
    }

    request = HttpRequest(
        method="POST",
        url="https://example.com/login",
        body=body,
    )

    assert request.body == body


def test_request_rejects_empty_method():
    with pytest.raises(
        ValueError,
        match="method must not be empty",
    ):
        HttpRequest(
            method="",
            url="https://example.com",
        )


def test_request_rejects_whitespace_method():
    with pytest.raises(
        ValueError,
        match="method must not be empty",
    ):
        HttpRequest(
            method="   ",
            url="https://example.com",
        )


def test_request_rejects_empty_url():
    with pytest.raises(
        ValueError,
        match="url must not be empty",
    ):
        HttpRequest(
            method="GET",
            url="",
        )


def test_request_rejects_whitespace_url():
    with pytest.raises(
        ValueError,
        match="url must not be empty",
    ):
        HttpRequest(
            method="GET",
            url="   ",
        )


def test_query_string():
    request = HttpRequest(
        method="GET",
        url="https://example.com/search",
        params={
            "q": "test",
            "page": "2",
        },
    )

    assert request.query_string == "q=test&page=2"


def test_query_string_is_empty_without_params():
    request = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    assert request.query_string == ""


def test_full_url_with_params():
    request = HttpRequest(
        method="GET",
        url="https://example.com/search",
        params={
            "q": "test",
            "page": "2",
        },
    )

    assert request.full_url == (
        "https://example.com/search?q=test&page=2"
    )


def test_full_url_with_existing_query():
    request = HttpRequest(
        method="GET",
        url="https://example.com/search?sort=latest",
        params={
            "page": "2",
        },
    )

    assert request.full_url == (
        "https://example.com/search?sort=latest&page=2"
    )


def test_full_url_without_params():
    request = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    assert request.full_url == "https://example.com"


def test_query_string_encodes_values():
    request = HttpRequest(
        method="GET",
        url="https://example.com/search",
        params={
            "q": "hello world",
        },
    )

    assert request.query_string == "q=hello+world"


def test_get_header():
    request = HttpRequest(
        method="GET",
        url="https://example.com",
        headers={
            "Content-Type": "application/json",
        },
    )

    assert request.get_header("Content-Type") == (
        "application/json"
    )


def test_get_header_is_case_insensitive():
    request = HttpRequest(
        method="GET",
        url="https://example.com",
        headers={
            "Content-Type": "application/json",
        },
    )

    assert request.get_header("content-type") == (
        "application/json"
    )


def test_get_header_returns_none_when_missing():
    request = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    assert request.get_header("Authorization") is None


def test_get_cookie():
    request = HttpRequest(
        method="GET",
        url="https://example.com",
        cookies={
            "session": "abc",
        },
    )

    assert request.get_cookie("session") == "abc"


def test_get_cookie_returns_none_when_missing():
    request = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    assert request.get_cookie("session") is None


def test_has_body_when_body_exists():
    request = HttpRequest(
        method="POST",
        url="https://example.com",
        body="test",
    )

    assert request.has_body() is True


def test_has_body_when_body_is_none():
    request = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    assert request.has_body() is False


def test_copy_creates_independent_request():
    request = HttpRequest(
        method="POST",
        url="https://example.com",
        headers={
            "X-Test": "true",
        },
        cookies={
            "session": "abc",
        },
        params={
            "page": "1",
        },
        body="test",
    )

    copied = request.copy()

    copied.headers["X-Test"] = "changed"
    copied.cookies["session"] = "changed"
    copied.params["page"] = "2"

    assert request.headers["X-Test"] == "true"
    assert request.cookies["session"] == "abc"
    assert request.params["page"] == "1"


def test_copy_preserves_request_data():
    request = HttpRequest(
        method="POST",
        url="https://example.com",
        headers={
            "X-Test": "true",
        },
        cookies={
            "session": "abc",
        },
        params={
            "page": "1",
        },
        body="test",
    )

    copied = request.copy()

    assert copied is not request
    assert copied.method == request.method
    assert copied.url == request.url
    assert copied.headers == request.headers
    assert copied.cookies == request.cookies
    assert copied.params == request.params
    assert copied.body == request.body


def test_request_instances_are_independent():
    first = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    second = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    first.headers["X-Test"] = "true"
    first.cookies["session"] = "abc"
    first.params["page"] = "1"

    assert second.headers == {}
    assert second.cookies == {}
    assert second.params == {}
