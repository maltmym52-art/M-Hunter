import pytest

from m_hunter.recon.asset import Asset
from m_hunter.recon.attack_surface import AttackSurface
from m_hunter.recon.endpoint import Endpoint
from m_hunter.recon.javascript import JavaScriptURL
from m_hunter.recon.parameter import Parameter
from m_hunter.recon.url import URL


def make_asset(
    value="example.com",
    asset_type="domain",
    alive=False,
):
    return Asset(
        value=value,
        asset_type=asset_type,
        alive=alive,
    )


def make_endpoint(
    value="https://example.com/users?id=1",
    method="GET",
    parameters=("id",),
):
    return Endpoint(
        url=URL(value),
        method=method,
        parameters=parameters,
    )


def make_js_endpoint(
    value="https://example.com/api/users",
):
    return JavaScriptURL(
        url=URL(value),
    )


def make_parameter(
    name="id",
    source="query",
    value="1",
):
    return Parameter(
        name=name,
        source=source,
        value=value,
    )


def test_initial_surface_is_empty():
    surface = AttackSurface()

    assert surface.assets == []
    assert surface.endpoints == []
    assert surface.javascript_endpoints == []
    assert surface.parameters == []

    assert surface.asset_count == 0
    assert surface.endpoint_count == 0
    assert surface.javascript_endpoint_count == 0
    assert surface.parameter_count == 0
    assert surface.live_asset_count == 0
    assert surface.url_count == 0


def test_add_asset():
    surface = AttackSurface()
    asset = make_asset()

    assert surface.add_asset(asset) is True
    assert surface.assets == [asset]
    assert surface.asset_count == 1


def test_duplicate_asset_is_rejected():
    surface = AttackSurface()

    first = make_asset()
    duplicate = make_asset()

    assert surface.add_asset(first) is True
    assert surface.add_asset(duplicate) is False
    assert surface.asset_count == 1


def test_add_assets_returns_number_added():
    surface = AttackSurface()

    assets = [
        make_asset("example.com"),
        make_asset("api.example.com", "subdomain"),
        make_asset("example.com"),
    ]

    assert surface.add_assets(assets) == 2
    assert surface.asset_count == 2


def test_add_endpoint():
    surface = AttackSurface()
    endpoint = make_endpoint()

    assert surface.add_endpoint(endpoint) is True
    assert surface.endpoints == [endpoint]
    assert surface.endpoint_count == 1


def test_duplicate_endpoint_is_rejected():
    surface = AttackSurface()

    first = make_endpoint()
    duplicate = make_endpoint()

    assert surface.add_endpoint(first) is True
    assert surface.add_endpoint(duplicate) is False
    assert surface.endpoint_count == 1


def test_add_endpoints_returns_number_added():
    surface = AttackSurface()

    endpoints = [
        make_endpoint(
            "https://example.com/users?id=1"
        ),
        make_endpoint(
            "https://example.com/profile"
        ),
        make_endpoint(
            "https://example.com/users?id=1"
        ),
    ]

    assert surface.add_endpoints(endpoints) == 2
    assert surface.endpoint_count == 2


def test_add_javascript_endpoint():
    surface = AttackSurface()
    endpoint = make_js_endpoint()

    assert surface.add_javascript_endpoint(endpoint) is True
    assert surface.javascript_endpoints == [endpoint]
    assert surface.javascript_endpoint_count == 1


def test_duplicate_javascript_endpoint_is_rejected():
    surface = AttackSurface()

    first = make_js_endpoint()
    duplicate = make_js_endpoint()

    assert surface.add_javascript_endpoint(first) is True
    assert surface.add_javascript_endpoint(duplicate) is False
    assert surface.javascript_endpoint_count == 1


def test_add_javascript_endpoints_returns_number_added():
    surface = AttackSurface()

    endpoints = [
        make_js_endpoint(
            "https://example.com/api/users"
        ),
        make_js_endpoint(
            "https://example.com/api/login"
        ),
        make_js_endpoint(
            "https://example.com/api/users"
        ),
    ]

    assert surface.add_javascript_endpoints(endpoints) == 2
    assert surface.javascript_endpoint_count == 2


def test_add_parameter():
    surface = AttackSurface()
    parameter = make_parameter()

    assert surface.add_parameter(parameter) is True
    assert surface.parameters == [parameter]
    assert surface.parameter_count == 1


def test_duplicate_parameter_is_rejected():
    surface = AttackSurface()

    first = make_parameter()
    duplicate = make_parameter()

    assert surface.add_parameter(first) is True
    assert surface.add_parameter(duplicate) is False
    assert surface.parameter_count == 1


def test_parameter_same_name_different_value_is_allowed():
    surface = AttackSurface()

    first = make_parameter(value="1")
    second = make_parameter(value="2")

    assert surface.add_parameter(first) is True
    assert surface.add_parameter(second) is True
    assert surface.parameter_count == 2


def test_add_parameters_returns_number_added():
    surface = AttackSurface()

    parameters = [
        make_parameter("id", value="1"),
        make_parameter("name", value="john"),
        make_parameter("id", value="1"),
    ]

    assert surface.add_parameters(parameters) == 2
    assert surface.parameter_count == 2


def test_live_assets_returns_only_alive_assets():
    surface = AttackSurface()

    alive = make_asset(
        "example.com",
        alive=True,
    )
    dead = make_asset(
        "dead.example.com",
        "subdomain",
        alive=False,
    )

    surface.add_assets([alive, dead])

    assert surface.live_assets == [alive]
    assert surface.live_asset_count == 1


def test_all_urls_combines_endpoint_sources():
    surface = AttackSurface()

    endpoint = make_endpoint(
        "https://example.com/users"
    )

    js_endpoint = make_js_endpoint(
        "https://example.com/api/users"
    )

    surface.add_endpoint(endpoint)
    surface.add_javascript_endpoint(js_endpoint)

    assert surface.all_urls() == [
        "https://example.com/users",
        "https://example.com/api/users",
    ]


def test_all_urls_removes_duplicates():
    surface = AttackSurface()

    surface.add_endpoint(
        make_endpoint(
            "https://example.com/users"
        )
    )

    surface.add_javascript_endpoint(
        make_js_endpoint(
            "https://example.com/users"
        )
    )

    assert surface.all_urls() == [
        "https://example.com/users"
    ]

    assert surface.url_count == 1


def test_invalid_asset_type_raises_type_error():
    surface = AttackSurface()

    with pytest.raises(TypeError):
        surface.add_asset("not-an-asset")


def test_invalid_endpoint_type_raises_type_error():
    surface = AttackSurface()

    with pytest.raises(TypeError):
        surface.add_endpoint("not-an-endpoint")


def test_invalid_javascript_endpoint_type_raises_type_error():
    surface = AttackSurface()

    with pytest.raises(TypeError):
        surface.add_javascript_endpoint(
            "not-a-javascript-url"
        )


def test_invalid_parameter_type_raises_type_error():
    surface = AttackSurface()

    with pytest.raises(TypeError):
        surface.add_parameter("not-a-parameter")


def test_clear_removes_everything():
    surface = AttackSurface()

    surface.add_asset(make_asset())
    surface.add_endpoint(make_endpoint())
    surface.add_javascript_endpoint(
        make_js_endpoint()
    )
    surface.add_parameter(make_parameter())

    surface.clear()

    assert surface.asset_count == 0
    assert surface.endpoint_count == 0
    assert surface.javascript_endpoint_count == 0
    assert surface.parameter_count == 0
    assert surface.url_count == 0


def test_surface_can_hold_complete_attack_surface():
    surface = AttackSurface()

    surface.add_asset(
        make_asset(
            "example.com",
            alive=True,
        )
    )

    surface.add_asset(
        make_asset(
            "api.example.com",
            "subdomain",
            alive=True,
        )
    )

    surface.add_endpoint(
        make_endpoint(
            "https://example.com/login"
        )
    )

    surface.add_endpoint(
        make_endpoint(
            "https://example.com/users?id=1"
        )
    )

    surface.add_javascript_endpoint(
        make_js_endpoint(
            "https://example.com/api/users"
        )
    )

    surface.add_parameter(
        make_parameter(
            "id",
            "query",
            "1",
        )
    )

    assert surface.asset_count == 2
    assert surface.live_asset_count == 2
    assert surface.endpoint_count == 2
    assert surface.javascript_endpoint_count == 1
    assert surface.parameter_count == 1
    assert surface.url_count == 3
