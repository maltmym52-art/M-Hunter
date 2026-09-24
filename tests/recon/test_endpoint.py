import pytest

from m_hunter.recon.endpoint import (
    Endpoint,
    EndpointDiscovery,
)
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL


def make_discovery(
    base="https://example.com/",
):
    base_url = URL(base)
    scope = ScopeManager(base_url)
    return EndpointDiscovery(scope)


def test_endpoint_defaults_to_get():
    endpoint = Endpoint(
        URL("https://example.com/login")
    )

    assert endpoint.method == "GET"
    assert endpoint.parameters == ()
    assert endpoint.source == "discovered"


def test_endpoint_normalizes_method():
    endpoint = Endpoint(
        URL("https://example.com/login"),
        method="post",
    )

    assert endpoint.method == "POST"


def test_endpoint_rejects_invalid_method():
    with pytest.raises(ValueError):
        Endpoint(
            URL("https://example.com/"),
            method="TRACE",
        )


def test_endpoint_requires_url():
    with pytest.raises(TypeError):
        Endpoint("https://example.com/")


def test_endpoint_rejects_empty_source():
    with pytest.raises(ValueError):
        Endpoint(
            URL("https://example.com/"),
            source=" ",
        )


def test_endpoint_normalizes_parameters():
    endpoint = Endpoint(
        URL("https://example.com/"),
        parameters=(
            " id ",
            "",
            "name",
        ),
    )

    assert endpoint.parameters == (
        "id",
        "name",
    )


def test_endpoint_parameter_names_alias():
    endpoint = Endpoint(
        URL("https://example.com/"),
        parameters=("id", "name"),
    )

    assert endpoint.parameter_names == (
        "id",
        "name",
    )


def test_endpoint_key_contains_identity():
    endpoint = Endpoint(
        URL("https://example.com/user?id=1"),
        method="GET",
        parameters=("id",),
    )

    assert endpoint.key == (
        "https://example.com/user?id=1",
        "GET",
        ("id",),
    )


def test_discovers_anchor_endpoint():
    discovery = make_discovery()

    html = """
    <a href="/login">Login</a>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 1
    assert str(endpoints[0].url) == (
        "https://example.com/login"
    )
    assert endpoints[0].method == "GET"
    assert endpoints[0].source == "link"


def test_discovers_query_parameters():
    discovery = make_discovery()

    html = """
    <a href="/search?q=test&page=2">
        Search
    </a>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 1
    assert endpoints[0].parameters == (
        "q",
        "page",
    )


def test_duplicate_parameter_names_are_preserved_for_links():
    discovery = make_discovery()

    html = """
    <a href="/search?id=1&id=2&name=test">
        Search
    </a>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert endpoints[0].parameters == (
        "id",
        "id",
        "name",
    )


def test_discovers_get_form():
    discovery = make_discovery()

    html = """
    <form action="/search" method="GET">
        <input name="q">
        <input name="page">
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 1
    assert str(endpoints[0].url) == (
        "https://example.com/search"
    )
    assert endpoints[0].method == "GET"
    assert endpoints[0].parameters == (
        "q",
        "page",
    )
    assert endpoints[0].source == "form"


def test_form_defaults_to_get():
    discovery = make_discovery()

    html = """
    <form action="/search">
        <input name="q">
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert endpoints[0].method == "GET"


def test_discovers_post_form():
    discovery = make_discovery()

    html = """
    <form action="/login" method="POST">
        <input name="username">
        <input name="password">
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 1
    assert endpoints[0].method == "POST"
    assert endpoints[0].parameters == (
        "username",
        "password",
    )


def test_discovers_textarea_parameter():
    discovery = make_discovery()

    html = """
    <form action="/comment">
        <textarea name="body"></textarea>
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert endpoints[0].parameters == (
        "body",
    )


def test_discovers_select_parameter():
    discovery = make_discovery()

    html = """
    <form action="/search">
        <select name="category">
            <option>one</option>
        </select>
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert endpoints[0].parameters == (
        "category",
    )


def test_form_parameters_are_deduplicated():
    discovery = make_discovery()

    html = """
    <form action="/test">
        <input name="id">
        <input name="id">
        <input name="name">
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert endpoints[0].parameters == (
        "id",
        "name",
    )


def test_external_link_is_filtered():
    discovery = make_discovery()

    html = """
    <a href="https://other.com/login">
        External
    </a>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert endpoints == []


def test_external_form_is_filtered():
    discovery = make_discovery()

    html = """
    <form action="https://other.com/login">
        <input name="user">
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert endpoints == []


def test_relative_endpoint_is_resolved():
    discovery = EndpointDiscovery(
        ScopeManager(
            URL("https://example.com/products/")
        )
    )

    html = """
    <a href="details?id=1">Details</a>
    """

    endpoints = discovery.discover(
        URL("https://example.com/products/index.html"),
        html,
    )

    assert str(endpoints[0].url) == (
        "https://example.com/products/details?id=1"
    )


def test_absolute_endpoint_is_supported():
    discovery = make_discovery()

    html = """
    <a href="https://example.com/api">
        API
    </a>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 1


def test_fragment_does_not_create_duplicate_endpoint():
    discovery = make_discovery()

    html = """
    <a href="/login#one">One</a>
    <a href="/login#two">Two</a>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 1


def test_different_methods_are_distinct():
    discovery = make_discovery()

    html = """
    <a href="/user">User</a>

    <form action="/user" method="POST">
        <input name="id">
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 2
    assert {
        endpoint.method
        for endpoint in endpoints
    } == {
        "GET",
        "POST",
    }


def test_same_url_different_parameters_are_distinct():
    discovery = make_discovery()

    html = """
    <a href="/search?q=test">One</a>
    <a href="/search?page=2">Two</a>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 2


def test_empty_html_returns_no_endpoints():
    discovery = make_discovery()

    assert discovery.discover(
        URL("https://example.com/"),
        "",
    ) == []


def test_invalid_html_does_not_crash():
    discovery = make_discovery()

    html = """
    <html>
        <a href="/one">
        <form action="/two">
        <input name="id">
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 2


def test_invalid_method_form_is_ignored():
    discovery = make_discovery()

    html = """
    <form action="/test" method="TRACE">
        <input name="id">
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert endpoints == []


def test_empty_form_action_uses_base_path():
    discovery = make_discovery()

    html = """
    <form method="POST">
        <input name="data">
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/account"),
        html,
    )

    assert len(endpoints) == 1
    assert str(endpoints[0].url) == (
        "https://example.com/account"
    )
    assert endpoints[0].method == "POST"


def test_missing_form_parameter_names_are_ignored():
    discovery = make_discovery()

    html = """
    <form action="/test">
        <input type="text">
        <input name="">
        <textarea></textarea>
        <select></select>
    </form>
    """

    endpoints = discovery.discover(
        URL("https://example.com/"),
        html,
    )

    assert len(endpoints) == 1
    assert endpoints[0].parameters == ()


def test_base_url_type_is_required():
    discovery = make_discovery()

    with pytest.raises(TypeError):
        discovery.discover(
            "https://example.com/",
            "<a href='/test'>test</a>",
        )


def test_html_type_is_required():
    discovery = make_discovery()

    with pytest.raises(TypeError):
        discovery.discover(
            URL("https://example.com/"),
            None,
        )


def test_scope_type_is_required():
    with pytest.raises(TypeError):
        EndpointDiscovery(
            URL("https://example.com/")
        )
