import pytest

from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import (
    DiscoveryEngine,
    DiscoverySource,
    StaticDiscoverySource,
)
from m_hunter.recon.inventory import AssetInventory


class CustomDiscoverySource(DiscoverySource):
    name = "custom"

    def __init__(self, assets):
        self.assets = assets

    def discover(self, target):
        return list(self.assets)


def make_asset(
    value="example.com",
    asset_type="domain",
):
    return Asset(
        value=value,
        asset_type=asset_type,
    )


def test_discovery_source_requires_discover():
    assert DiscoverySource.name == "base"

    with pytest.raises(TypeError):
        DiscoverySource()


def test_static_source_defaults_to_empty():
    source = StaticDiscoverySource()

    assert source.name == "static"
    assert source.discover("example.com") == []


def test_static_source_returns_assets():
    assets = [
        make_asset("example.com", "domain"),
        make_asset("api.example.com", "subdomain"),
    ]

    source = StaticDiscoverySource(assets)

    result = source.discover("example.com")

    assert result == assets


def test_static_source_returns_copy():
    assets = [
        make_asset(),
    ]

    source = StaticDiscoverySource(assets)

    result = source.discover("example.com")
    result.clear()

    assert source.discover("example.com") == assets


def test_engine_starts_empty():
    engine = DiscoveryEngine()

    assert engine.count_sources() == 0
    assert engine.source_names() == []
    assert engine.get_sources() == []
    assert engine.inventory.count() == 0


def test_engine_accepts_initial_sources():
    source = StaticDiscoverySource(
        [make_asset()]
    )

    engine = DiscoveryEngine(
        sources=[source]
    )

    assert engine.count_sources() == 1
    assert engine.source_names() == ["static"]


def test_engine_accepts_custom_inventory():
    inventory = AssetInventory()

    engine = DiscoveryEngine(
        inventory=inventory
    )

    assert engine.inventory is inventory


def test_add_source():
    engine = DiscoveryEngine()
    source = StaticDiscoverySource()

    engine.add_source(source)

    assert engine.count_sources() == 1
    assert engine.get_sources() == [source]


def test_add_custom_source():
    engine = DiscoveryEngine()
    source = CustomDiscoverySource([])

    engine.add_source(source)

    assert engine.source_names() == ["custom"]


def test_invalid_source_raises():
    engine = DiscoveryEngine()

    with pytest.raises(
        TypeError,
        match="source must be an instance of DiscoverySource",
    ):
        engine.add_source(object())


def test_duplicate_source_name_raises():
    engine = DiscoveryEngine()

    engine.add_source(
        StaticDiscoverySource()
    )

    with pytest.raises(
        ValueError,
        match="Discovery source already registered: static",
    ):
        engine.add_source(
            StaticDiscoverySource()
        )


def test_get_sources_returns_copy():
    source = StaticDiscoverySource()
    engine = DiscoveryEngine(
        sources=[source]
    )

    sources = engine.get_sources()
    sources.clear()

    assert engine.count_sources() == 1


def test_discover_collects_assets():
    assets = [
        make_asset("example.com", "domain"),
        make_asset("api.example.com", "subdomain"),
    ]

    engine = DiscoveryEngine(
        sources=[
            StaticDiscoverySource(assets)
        ]
    )

    discovered = engine.discover("example.com")

    assert discovered == assets
    assert engine.inventory.count() == 2


def test_discover_deduplicates_assets():
    first = make_asset(
        "example.com",
        "domain",
    )

    duplicate = make_asset(
        "example.com",
        "domain",
    )

    second = make_asset(
        "api.example.com",
        "subdomain",
    )

    engine = DiscoveryEngine(
        sources=[
            StaticDiscoverySource(
                [first, duplicate]
            ),
            StaticDiscoverySource(
                [duplicate, second]
            ),
        ]
    )

    discovered = engine.discover("example.com")

    assert [
        asset.value
        for asset in discovered
    ] == [
        "example.com",
        "api.example.com",
    ]

    assert engine.inventory.count() == 2


def test_discover_uses_existing_inventory():
    existing = make_asset(
        "example.com",
        "domain",
    )

    inventory = AssetInventory()
    inventory.add(existing)

    new_asset = make_asset(
        "api.example.com",
        "subdomain",
    )

    engine = DiscoveryEngine(
        sources=[
            StaticDiscoverySource(
                [existing, new_asset]
            )
        ],
        inventory=inventory,
    )

    discovered = engine.discover("example.com")

    assert discovered == [new_asset]
    assert engine.inventory.count() == 2


def test_discover_with_multiple_sources():
    first = StaticDiscoverySource(
        [
            make_asset(
                "example.com",
                "domain",
            )
        ]
    )

    second = StaticDiscoverySource(
        [
            make_asset(
                "api.example.com",
                "subdomain",
            )
        ]
    )

    engine = DiscoveryEngine(
        sources=[first, second]
    )

    discovered = engine.discover("example.com")

    assert len(discovered) == 2
    assert engine.inventory.count() == 2


def test_discover_empty_sources():
    engine = DiscoveryEngine(
        sources=[
            StaticDiscoverySource()
        ]
    )

    assert engine.discover("example.com") == []
    assert engine.inventory.count() == 0


def test_clear_sources():
    engine = DiscoveryEngine(
        sources=[
            StaticDiscoverySource()
        ]
    )

    engine.clear_sources()

    assert engine.count_sources() == 0
    assert engine.source_names() == []
