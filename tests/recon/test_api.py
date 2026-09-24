import pytest

from m_hunter.recon.api import (
    APIEndpoint,
    APIDiscovery,
    APIDiscoveryResult,
)
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL


def make_scope():
    return ScopeManager(
        base_url=URL("https://example.com/")
    )


def make_discovery():
    return APIDiscovery(make_scope())


def test_api_endpoint_defaults():
    endpoint = APIEndpoint(
        url=URL("https://example.com/api/users")
    )

    assert endpoint.method == "GET"
    assert endpoint.source == "discovered"
    assert endpoint.is_graphql is False
    assert endpoint.parameters == ()


def test_api_endpoint_normalizes_method():
    endpoint = APIEndpoint(
        url=URL("https://example.com/api/users"),
        method=" post ",
    )

    assert endpoint.method == "POST"


def test_api_endpoint_normalizes_parameters():
    endpoint = APIEndpoint(
        url=URL("https://example.com/api/users"),
        parameters=(" id ", "", "name"),
    )

    assert endpoint.parameters == (
        "id",
        "name",
    )


def test_api_endpoint_rejects_invalid_url():
    with pytest.raises(TypeError):
        APIEndpoint(
            url="https://example.com/api"
        )


def test_api_endpoint_rejects_empty_method():
    with pytest.raises(ValueError):
        APIEndpoint(
            url=URL("https://example.com/api"),
            method=" ",
        )


def test_api_endpoint_rejects_empty_source():
    with pytest.raises(ValueError):
        APIEndpoint(
            url=URL("https://example.com/api"),
            source=" ",
        )


def test_api_endpoint_key():
    endpoint = APIEndpoint(
        url=URL(
            "https://example.com/api/users?id=1"
        ),
        method="GET",
        parameters=("id",),
    )

    assert endpoint.key == (
        "https://example.com/api/users?id=1",
        "GET",
        ("id",),
    )


def test_empty_discovery_result():
    result = APIDiscoveryResult()

    assert result.count == 0
    assert result.graphql_count == 0
    assert result.endpoints == []


def test_result_add_endpoint():
    result = APIDiscoveryResult()

    endpoint = APIEndpoint(
        url=URL(
            "https://example.com/api/users"
        )
    )

    assert result.add(endpoint) is True
    assert result.count == 1


def test_result_rejects_duplicate_endpoint():
    result = APIDiscoveryResult()

    first = APIEndpoint(
        url=URL(
            "https://example.com/api/users"
        )
    )

    duplicate = APIEndpoint(
        url=URL(
            "https://example.com/api/users"
        )
    )

    assert result.add(first) is True
    assert result.add(duplicate) is False
    assert result.count == 1


def test_result_rejects_invalid_endpoint():
    result = APIDiscoveryResult()

    with pytest.raises(TypeError):
        result.add("not-an-endpoint")


def test_discovery_requires_scope():
    with pytest.raises(TypeError):
        APIDiscovery("not-a-scope")


def test_discover_api_path():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '<script>fetch("/api/users")</script>',
    )

    assert result.count == 1
    assert (
        result.endpoints[0].url.normalized
        == "https://example.com/api/users"
    )


def test_discover_apis_path():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        'const x = "/apis/users";',
    )

    assert result.count == 1
    assert result.endpoints[0].url.path == "/apis/users"


def test_discover_versioned_api():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        'fetch("/v1/users"); fetch("/v2/accounts");',
    )

    assert result.count == 2

    paths = {
        endpoint.url.path
        for endpoint in result.endpoints
    }

    assert paths == {
        "/v1/users",
        "/v2/accounts",
    }


def test_discover_rest_endpoint():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        'const endpoint = "/rest/users";',
    )

    assert result.count == 1
    assert result.endpoints[0].url.path == "/rest/users"


def test_discover_graphql():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        'fetch("/graphql");',
    )

    assert result.count == 1
    assert result.graphql_count == 1
    assert result.graphql_endpoints[0].is_graphql is True


def test_discover_graphiql():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        'const ui = "/graphiql";',
    )

    assert result.count == 1
    assert result.graphql_count == 1


def test_graphql_endpoint_is_marked():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '"/graphql/api";',
    )

    assert result.count == 1
    assert result.endpoints[0].is_graphql is True


def test_query_parameters_are_preserved():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '"/api/users?id=1&limit=10";',
    )

    endpoint = result.endpoints[0]

    assert endpoint.url.query == (
        "id=1&limit=10"
    )

    assert endpoint.parameters == (
        "id",
        "limit",
    )


def test_duplicate_api_urls_are_removed():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '''
        "/api/users";
        "/api/users";
        "/api/users";
        ''',
    )

    assert result.count == 1


def test_external_api_urls_are_filtered():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '''
        "/api/users";
        "https://evil.example/api/users";
        ''',
    )

    assert result.count == 1
    assert result.endpoints[0].url.host == "example.com"


def test_relative_base_url_is_resolved():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/app/"),
        '"../api/users";',
    )

    assert result.count == 1
    assert (
        result.endpoints[0].url.normalized
        == "https://example.com/api/users"
    )


def test_custom_source_is_preserved():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '"/api/users";',
        source="javascript",
    )

    assert result.endpoints[0].source == "javascript"


def test_empty_content_returns_empty_result():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        "",
    )

    assert result.count == 0


def test_invalid_content_type_raises():
    discovery = make_discovery()

    with pytest.raises(TypeError):
        discovery.discover(
            URL("https://example.com/"),
            None,
        )


def test_invalid_base_url_type_raises():
    discovery = make_discovery()

    with pytest.raises(TypeError):
        discovery.discover(
            "https://example.com/",
            '"/api/users";',
        )


def test_empty_source_raises():
    discovery = make_discovery()

    with pytest.raises(ValueError):
        discovery.discover(
            URL("https://example.com/"),
            '"/api/users";',
            source=" ",
        )


def test_excluded_api_path_is_filtered():
    scope = ScopeManager(
        base_url=URL("https://example.com/"),
        excluded_paths={"/api/admin/*"},
    )

    discovery = APIDiscovery(scope)

    result = discovery.discover(
        URL("https://example.com/"),
        '''
        "/api/users";
        "/api/admin/users";
        ''',
    )

    assert result.count == 1
    assert (
        result.endpoints[0].url.path
        == "/api/users"
    )


def test_non_api_paths_are_ignored():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '''
        "/login";
        "/dashboard";
        "/static/app.js";
        ''',
    )

    assert result.count == 0


def test_template_placeholders_are_ignored():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '`${"/api/${version}/users"}`;',
    )

    assert result.count == 0


def test_mixed_api_and_graphql_content():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '''
        fetch("/api/users");
        fetch("/v1/accounts");
        fetch("/graphql");
        ''',
    )

    assert result.count == 3
    assert result.graphql_count == 1


def test_values_are_independent():
    discovery = make_discovery()

    result = discovery.discover(
        URL("https://example.com/"),
        '"/api/users";',
    )

    first = result.endpoints
    first.clear()

    assert result.count == 1
