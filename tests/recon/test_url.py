import pytest

from m_hunter.recon.url import URL


def test_url_accepts_https():
    url = URL(
        "https://example.com"
    )

    assert url.value == "https://example.com"


def test_url_accepts_http():
    url = URL(
        "http://example.com"
    )

    assert url.scheme == "http"


def test_url_trims_whitespace():
    url = URL(
        "  https://example.com  "
    )

    assert url.value == (
        "https://example.com"
    )


def test_empty_url_is_rejected():
    with pytest.raises(
        ValueError,
        match="url must not be empty",
    ):
        URL("")


def test_whitespace_url_is_rejected():
    with pytest.raises(
        ValueError,
        match="url must not be empty",
    ):
        URL("   ")


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com",
        "javascript:alert(1)",
        "mailto:test@example.com",
        "example.com",
    ],
)
def test_invalid_url_scheme_is_rejected(value):
    with pytest.raises(
        ValueError,
        match="url must use http or https",
    ):
        URL(value)


def test_missing_host_is_rejected():
    with pytest.raises(
        ValueError,
        match="url must include a host",
    ):
        URL("https:///path")


def test_scheme_is_lowercase():
    url = URL(
        "HTTPS://example.com"
    )

    assert url.scheme == "https"


def test_host():
    url = URL(
        "https://www.example.com/path"
    )

    assert url.host == "www.example.com"


def test_port():
    url = URL(
        "https://example.com:8443/path"
    )

    assert url.port == 8443


def test_port_is_none_when_not_present():
    url = URL(
        "https://example.com/path"
    )

    assert url.port is None


def test_path():
    url = URL(
        "https://example.com/api/users"
    )

    assert url.path == "/api/users"


def test_empty_path_becomes_root():
    url = URL(
        "https://example.com"
    )

    assert url.path == "/"


def test_query():
    url = URL(
        "https://example.com/search?q=test&page=2"
    )

    assert url.query == "q=test&page=2"


def test_fragment():
    url = URL(
        "https://example.com/page#section"
    )

    assert url.fragment == "section"


def test_parameters():
    url = URL(
        "https://example.com/search?q=test&page=2"
    )

    assert url.parameters == {
        "q": "test",
        "page": "2",
    }


def test_blank_parameter_is_preserved():
    url = URL(
        "https://example.com/search?q=&page=2"
    )

    assert url.parameters == {
        "q": "",
        "page": "2",
    }


def test_parameter_names():
    url = URL(
        "https://example.com/search?q=test&page=2"
    )

    assert url.parameter_names == (
        "q",
        "page",
    )


def test_duplicate_parameter_names_are_preserved():
    url = URL(
        "https://example.com/search?id=1&id=2"
    )

    assert url.parameter_names == (
        "id",
        "id",
    )


def test_origin_without_port():
    url = URL(
        "https://example.com/path"
    )

    assert url.origin == (
        "https://example.com"
    )


def test_origin_with_port():
    url = URL(
        "https://example.com:8443/path"
    )

    assert url.origin == (
        "https://example.com:8443"
    )


def test_normalized_url_lowercases_scheme():
    url = URL(
        "HTTPS://Example.com/path"
    )

    assert url.normalized == (
        "https://Example.com/path"
    )


def test_normalized_url_removes_fragment():
    url = URL(
        "https://example.com/page#section"
    )

    assert url.normalized == (
        "https://example.com/page"
    )


def test_normalized_query():
    url = URL(
        "https://example.com/search?b=2&a=1"
    )

    assert url.normalized == (
        "https://example.com/search?b=2&a=1"
    )


def test_without_query():
    url = URL(
        "https://example.com/search?q=test"
    )

    assert url.without_query() == (
        "https://example.com/search"
    )


def test_without_fragment():
    url = URL(
        "https://example.com/page#section"
    )

    assert url.without_fragment() == (
        "https://example.com/page"
    )


def test_resolve_absolute_url():
    base = URL(
        "https://example.com/base/"
    )

    resolved = base.resolve(
        "https://other.example.com/page"
    )

    assert resolved.value == (
        "https://other.example.com/page"
    )


def test_resolve_relative_path():
    base = URL(
        "https://example.com/base/"
    )

    resolved = base.resolve(
        "users"
    )

    assert resolved.value == (
        "https://example.com/base/users"
    )


def test_resolve_root_relative_path():
    base = URL(
        "https://example.com/base/page"
    )

    resolved = base.resolve(
        "/api/users"
    )

    assert resolved.value == (
        "https://example.com/api/users"
    )


def test_same_origin():
    first = URL(
        "https://example.com/one"
    )

    second = URL(
        "https://example.com/two"
    )

    assert first.is_same_origin(second) is True


def test_different_origin():
    first = URL(
        "https://example.com"
    )

    second = URL(
        "https://other.example.com"
    )

    assert first.is_same_origin(second) is False


def test_different_port_is_different_origin():
    first = URL(
        "https://example.com:443"
    )

    second = URL(
        "https://example.com:8443"
    )

    assert first.is_same_origin(second) is False


def test_str_returns_url():
    url = URL(
        "https://example.com"
    )

    assert str(url) == (
        "https://example.com"
    )
