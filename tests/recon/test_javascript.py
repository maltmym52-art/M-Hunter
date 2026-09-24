import pytest

from m_hunter.recon.javascript import (
    JavaScriptEndpointDiscovery,
    JavaScriptURL,
)
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL


def make_discovery(
    base="https://example.com/",
):
    base_url = URL(base)
    scope = ScopeManager(base_url)
    return JavaScriptEndpointDiscovery(scope)


def test_javascript_url_requires_url_object():
    with pytest.raises(TypeError):
        JavaScriptURL(
            "https://example.com/"
        )


def test_javascript_url_default_source():
    item = JavaScriptURL(
        URL("https://example.com/api")
    )

    assert item.source == "javascript"
    assert item.value == (
        "https://example.com/api"
    )


def test_javascript_url_rejects_empty_source():
    with pytest.raises(ValueError):
        JavaScriptURL(
            URL("https://example.com/"),
            source=" ",
        )


def test_extracts_absolute_http_url():
    discovery = make_discovery()

    javascript = """
    const api = "https://example.com/api/users";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 1
    assert result.values == [
        "https://example.com/api/users"
    ]


def test_extracts_absolute_https_url():
    discovery = make_discovery()

    javascript = """
    const api = 'https://example.com/v1/users';
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 1


def test_extracts_single_quoted_url():
    discovery = make_discovery()

    javascript = """
    fetch('/api/users');
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.values == [
        "https://example.com/api/users"
    ]


def test_extracts_double_quoted_url():
    discovery = make_discovery()

    javascript = """
    fetch("/api/users");
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.values == [
        "https://example.com/api/users"
    ]


def test_extracts_template_literal_without_placeholder():
    discovery = make_discovery()

    javascript = """
    const endpoint = `/api/users`;
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.values == [
        "https://example.com/api/users"
    ]


def test_extracts_relative_path():
    discovery = make_discovery()

    javascript = """
    const endpoint = "/users/profile";
    """

    result = discovery.discover(
        URL("https://example.com/app/"),
        javascript,
    )

    assert result.values == [
        "https://example.com/users/profile"
    ]


def test_extracts_dot_relative_path():
    discovery = make_discovery()

    javascript = """
    const endpoint = "./details";
    """

    result = discovery.discover(
        URL("https://example.com/app/index.html"),
        javascript,
    )

    assert result.values == [
        "https://example.com/app/details"
    ]


def test_extracts_parent_relative_path():
    discovery = make_discovery()

    javascript = """
    const endpoint = "../api/users";
    """

    result = discovery.discover(
        URL("https://example.com/app/index.html"),
        javascript,
    )

    assert result.values == [
        "https://example.com/api/users"
    ]


def test_extracts_api_path():
    discovery = make_discovery()

    javascript = """
    const endpoint = "/api/v1/users";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 1
    assert result.values[0] == (
        "https://example.com/api/v1/users"
    )


def test_extracts_graphql_path():
    discovery = make_discovery()

    javascript = """
    const endpoint = "/graphql";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.values == [
        "https://example.com/graphql"
    ]


def test_extracts_versioned_api_path():
    discovery = make_discovery()

    javascript = """
    const endpoint = "/v2/accounts";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.values == [
        "https://example.com/v2/accounts"
    ]


def test_extracts_query_parameters():
    discovery = make_discovery()

    javascript = """
    const endpoint = "/search?q=test&page=2";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 1

    url = result.urls[0].url

    assert url.parameters == {
        "q": "test",
        "page": "2",
    }


def test_duplicate_urls_are_removed():
    discovery = make_discovery()

    javascript = """
    fetch("/api/users");
    fetch("/api/users");
    const url = "/api/users#section";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 1


def test_absolute_external_url_is_filtered():
    discovery = make_discovery()

    javascript = """
    const internal = "https://example.com/api";
    const external = "https://other.com/api";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.values == [
        "https://example.com/api"
    ]


def test_external_relative_origin_is_filtered():
    discovery = JavaScriptEndpointDiscovery(
        ScopeManager(
            URL("https://example.com/"),
            allowed_hosts={"example.com"},
        )
    )

    javascript = """
    const endpoint = "https://evil.example.net/api";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 0


def test_websocket_urls_are_not_converted_to_http_urls():
    discovery = make_discovery()

    javascript = """
    const socket = "wss://example.com/socket";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 0


def test_ws_urls_are_not_converted_to_http_urls():
    discovery = make_discovery()

    javascript = """
    const socket = "ws://example.com/socket";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 0


def test_template_placeholder_is_ignored():
    discovery = make_discovery()

    javascript = """
    const endpoint = `/api/users/${userId}`;
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 0


def test_empty_javascript():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        "",
    )

    assert result.count == 0


def test_whitespace_javascript():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        "   ",
    )

    assert result.count == 0


def test_invalid_javascript_does_not_crash():
    discovery = make_discovery()

    javascript = """
    const endpoint = "/api/users"
    function broken( {
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 1


def test_non_string_javascript_is_rejected():
    discovery = make_discovery()

    with pytest.raises(TypeError):
        discovery.discover(
            URL("https://example.com/"),
            None,
        )


def test_base_url_type_is_required():
    discovery = make_discovery()

    with pytest.raises(TypeError):
        discovery.discover(
            "https://example.com/",
            '"/api/users"',
        )


def test_query_fragment_url_is_supported():
    discovery = make_discovery()

    javascript = """
    const endpoint = "/search?q=test#results";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 1

    url = result.urls[0].url

    assert url.query == "q=test"
    assert url.fragment == "results"


def test_multiple_endpoints_are_discovered():
    discovery = make_discovery()

    javascript = """
    const a = "/api/users";
    const b = "/api/products";
    const c = "/graphql";
    const d = "/login";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 4

    assert set(result.values) == {
        "https://example.com/api/users",
        "https://example.com/api/products",
        "https://example.com/graphql",
        "https://example.com/login",
    }


def test_mixed_quote_styles_are_supported():
    discovery = make_discovery()

    javascript = """
    const a = "/api/users";
    const b = '/api/products';
    const c = `/graphql`;
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 3


def test_scope_excluded_path_is_filtered():
    scope = ScopeManager(
        URL("https://example.com/"),
        excluded_paths={"/admin/*"},
    )

    discovery = JavaScriptEndpointDiscovery(scope)

    javascript = """
    const a = "/admin/users";
    const b = "/api/users";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.values == [
        "https://example.com/api/users"
    ]


def test_result_values_returns_copy():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '"/api/users"',
    )

    values = result.values
    values.clear()

    assert result.count == 1


def test_absolute_url_with_port():
    discovery = make_discovery()

    javascript = """
    const endpoint = "https://example.com:8443/api";
    """

    result = discovery.discover(
        URL("https://example.com/"),
        javascript,
    )

    assert result.count == 1
    assert result.urls[0].url.port == 8443
