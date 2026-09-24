import pytest

from m_hunter.recon.endpoint import Endpoint
from m_hunter.recon.parameter import (
    Parameter,
    ParameterDiscovery,
    ParameterInventory,
)
from m_hunter.recon.url import URL


def make_endpoint(
    url="https://example.com/search?q=test&page=2",
    method="GET",
    parameters=(),
    source="link",
):
    return Endpoint(
        URL(url),
        method=method,
        parameters=parameters,
        source=source,
    )


def test_parameter_normalizes_name_and_source():
    parameter = Parameter(
        name=" id ",
        source=" QUERY ",
    )

    assert parameter.name == "id"
    assert parameter.source == "query"


def test_parameter_rejects_empty_name():
    with pytest.raises(ValueError):
        Parameter(
            name=" ",
            source="query",
        )


def test_parameter_rejects_invalid_source():
    with pytest.raises(ValueError):
        Parameter(
            name="id",
            source="unknown",
        )


def test_parameter_key():
    parameter = Parameter(
        name="id",
        source="query",
        location="/search",
    )

    assert parameter.key == (
        "id",
        "query",
        "/search",
    )


def test_parameter_inventory_adds_parameter():
    inventory = ParameterInventory()

    parameter = Parameter(
        name="id",
        source="query",
    )

    assert inventory.add(parameter)
    assert inventory.count() == 1


def test_parameter_inventory_rejects_duplicate():
    inventory = ParameterInventory()

    parameter = Parameter(
        name="id",
        source="query",
    )

    assert inventory.add(parameter)
    assert not inventory.add(parameter)
    assert inventory.count() == 1


def test_parameter_inventory_allows_same_name_different_source():
    inventory = ParameterInventory()

    assert inventory.add(
        Parameter("id", "query")
    )

    assert inventory.add(
        Parameter("id", "form")
    )

    assert inventory.count() == 2


def test_inventory_add_many():
    inventory = ParameterInventory()

    parameters = [
        Parameter("id", "query"),
        Parameter("name", "query"),
        Parameter("id", "query"),
    ]

    assert inventory.add_many(parameters) == 2
    assert inventory.count() == 2


def test_inventory_by_source():
    inventory = ParameterInventory()

    inventory.add(
        Parameter("id", "query")
    )
    inventory.add(
        Parameter("username", "form")
    )

    assert inventory.by_source("query") == [
        inventory.parameters[0]
    ]


def test_inventory_by_source_is_case_insensitive():
    inventory = ParameterInventory()

    inventory.add(
        Parameter("id", "query")
    )

    assert len(
        inventory.by_source(" QUERY ")
    ) == 1


def test_inventory_names():
    inventory = ParameterInventory()

    inventory.add(
        Parameter("id", "query")
    )
    inventory.add(
        Parameter("name", "form")
    )

    assert inventory.names() == [
        "id",
        "name",
    ]


def test_inventory_clear():
    inventory = ParameterInventory()

    inventory.add(
        Parameter("id", "query")
    )

    inventory.clear()

    assert inventory.count() == 0


def test_discover_endpoint_query_parameters():
    discovery = ParameterDiscovery()

    endpoint = make_endpoint()

    inventory = discovery.discover_endpoint(
        endpoint
    )

    assert inventory.names() == [
        "q",
        "page",
    ]

    assert [
        parameter.source
        for parameter in inventory.parameters
    ] == [
        "query",
        "query",
    ]


def test_discover_endpoint_query_values():
    discovery = ParameterDiscovery()

    endpoint = make_endpoint(
        "https://example.com/search?q=hello&page=2"
    )

    inventory = discovery.discover_endpoint(
        endpoint
    )

    assert [
        parameter.value
        for parameter in inventory.parameters
    ] == [
        "hello",
        "2",
    ]


def test_discover_endpoint_form_parameters():
    discovery = ParameterDiscovery()

    endpoint = make_endpoint(
        "https://example.com/login",
        method="POST",
        parameters=(
            "username",
            "password",
        ),
        source="form",
    )

    inventory = discovery.discover_endpoint(
        endpoint
    )

    assert inventory.names() == [
        "username",
        "password",
    ]

    assert all(
        parameter.source == "form"
        for parameter in inventory.parameters
    )


def test_discover_endpoint_link_parameters_are_query():
    discovery = ParameterDiscovery()

    endpoint = make_endpoint(
        "https://example.com/user",
        parameters=("id",),
        source="link",
    )

    inventory = discovery.discover_endpoint(
        endpoint
    )

    assert inventory.parameters[0].source == "query"


def test_discover_endpoint_deduplicates_parameters():
    discovery = ParameterDiscovery()

    endpoint = make_endpoint(
        "https://example.com/search?id=1",
        parameters=("id",),
        source="link",
    )

    inventory = discovery.discover_endpoint(
        endpoint
    )

    assert inventory.count() == 1


def test_discover_query():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_query(
        "https://example.com/search?q=test&page=2"
    )

    assert inventory.names() == [
        "q",
        "page",
    ]


def test_discover_query_preserves_blank_values():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_query(
        "https://example.com/search?q=&page=2"
    )

    assert inventory.parameters[0].name == "q"
    assert inventory.parameters[0].value == ""


def test_discover_query_duplicate_names():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_query(
        "https://example.com/search?id=1&id=2"
    )

    assert [
        parameter.value
        for parameter in inventory.parameters
    ] == [
        "1",
        "2",
    ]


def test_discover_query_without_query():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_query(
        "https://example.com/search"
    )

    assert inventory.count() == 0


def test_discover_query_rejects_non_string():
    discovery = ParameterDiscovery()

    with pytest.raises(TypeError):
        discovery.discover_query(None)


def test_discover_query_rejects_empty_string():
    discovery = ParameterDiscovery()

    with pytest.raises(ValueError):
        discovery.discover_query(" ")


def test_discover_form():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_form(
        {
            "username": "alice",
            "password": "secret",
        },
        location="/login",
    )

    assert inventory.names() == [
        "username",
        "password",
    ]

    assert inventory.parameters[0].location == "/login"


def test_discover_form_preserves_none_value():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_form(
        {"token": None}
    )

    assert inventory.parameters[0].value is None


def test_discover_form_ignores_empty_names():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_form(
        {
            "": "ignored",
            "id": "1",
        }
    )

    assert inventory.names() == ["id"]


def test_discover_form_requires_dict():
    discovery = ParameterDiscovery()

    with pytest.raises(TypeError):
        discovery.discover_form([])


def test_discover_form_requires_string_names():
    discovery = ParameterDiscovery()

    with pytest.raises(TypeError):
        discovery.discover_form(
            {1: "value"}
        )


def test_discover_json_flat_object():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_json(
        {
            "username": "alice",
            "age": 20,
            "active": True,
        }
    )

    assert inventory.names() == [
        "username",
        "age",
        "active",
    ]

    assert all(
        parameter.source == "json"
        for parameter in inventory.parameters
    )


def test_discover_json_nested_object():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_json(
        {
            "user": {
                "id": 10,
                "name": "alice",
            }
        }
    )

    assert inventory.names() == [
        "id",
        "name",
    ]

    assert [
        parameter.location
        for parameter in inventory.parameters
    ] == [
        "user.id",
        "user.name",
    ]


def test_discover_json_nested_list():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_json(
        {
            "items": [
                {"id": 1},
                {"id": 2},
            ]
        }
    )

    assert [
        parameter.name
        for parameter in inventory.parameters
    ] == [
        "id",
        "id",
    ]

    assert [
        parameter.location
        for parameter in inventory.parameters
    ] == [
        "items[0].id",
        "items[1].id",
    ]


def test_discover_json_top_level_list():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_json(
        [
            {"id": 1},
            {"name": "alice"},
        ]
    )

    assert inventory.names() == [
        "id",
        "name",
    ]


def test_discover_json_none_value():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_json(
        {"token": None}
    )

    assert inventory.parameters[0].value is None


def test_discover_json_rejects_scalar():
    discovery = ParameterDiscovery()

    with pytest.raises(TypeError):
        discovery.discover_json("hello")


def test_discover_path():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_path(
        ["id", "slug"],
        ["123", "admin"],
        location="/users/{id}/{slug}",
    )

    assert inventory.names() == [
        "id",
        "slug",
    ]

    assert [
        parameter.value
        for parameter in inventory.parameters
    ] == [
        "123",
        "admin",
    ]


def test_discover_path_rejects_mismatched_lengths():
    discovery = ParameterDiscovery()

    with pytest.raises(ValueError):
        discovery.discover_path(
            ["id"],
            ["1", "2"],
        )


def test_discover_headers():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_headers(
        {
            "Authorization": "Bearer token",
            "X-Test": "value",
        }
    )

    assert inventory.names() == [
        "Authorization",
        "X-Test",
    ]

    assert all(
        parameter.source == "header"
        for parameter in inventory.parameters
    )


def test_discover_headers_ignores_empty_names():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_headers(
        {
            "": "ignored",
            "X-Test": "value",
        }
    )

    assert inventory.names() == ["X-Test"]


def test_discover_headers_requires_dict():
    discovery = ParameterDiscovery()

    with pytest.raises(TypeError):
        discovery.discover_headers([])


def test_discover_cookies():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_cookies(
        {
            "session": "abc",
            "theme": "dark",
        }
    )

    assert inventory.names() == [
        "session",
        "theme",
    ]

    assert all(
        parameter.source == "cookie"
        for parameter in inventory.parameters
    )


def test_discover_cookies_ignores_empty_names():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_cookies(
        {
            "": "ignored",
            "session": "abc",
        }
    )

    assert inventory.names() == ["session"]


def test_discover_cookies_requires_dict():
    discovery = ParameterDiscovery()

    with pytest.raises(TypeError):
        discovery.discover_cookies([])


def test_parameter_sources_are_distinct():
    discovery = ParameterDiscovery()

    inventory = ParameterInventory()

    inventory.add(
        Parameter("id", "query")
    )
    inventory.add(
        Parameter("id", "form")
    )
    inventory.add(
        Parameter("id", "json")
    )
    inventory.add(
        Parameter("id", "path")
    )
    inventory.add(
        Parameter("id", "header")
    )
    inventory.add(
        Parameter("id", "cookie")
    )

    assert inventory.count() == 6


def test_parameter_inventory_rejects_wrong_type():
    inventory = ParameterInventory()

    with pytest.raises(TypeError):
        inventory.add("id")


def test_json_location_override():
    discovery = ParameterDiscovery()

    inventory = discovery.discover_json(
        {"id": 1},
        location="/api/users",
    )

    assert inventory.parameters[0].location == (
        "/api/users"
    )
