import pytest

from m_hunter.recon.asset import Asset
from m_hunter.recon.inventory import AssetInventory


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


def test_inventory_starts_empty():
    inventory = AssetInventory()

    assert inventory.count() == 0
    assert len(inventory) == 0
    assert inventory.get_all() == []


def test_add_asset():
    inventory = AssetInventory()
    asset = make_asset()

    assert inventory.add(asset) is True
    assert inventory.count() == 1
    assert inventory.get_all() == [asset]


def test_duplicate_asset_is_not_added():
    inventory = AssetInventory()

    first = make_asset()
    second = make_asset()

    assert inventory.add(first) is True
    assert inventory.add(second) is False

    assert inventory.count() == 1
    assert inventory.get_all() == [first]


def test_same_value_with_different_type_is_allowed():
    inventory = AssetInventory()

    domain = make_asset(
        value="example.com",
        asset_type="domain",
    )

    url = make_asset(
        value="example.com",
        asset_type="url",
    )

    assert inventory.add(domain) is True
    assert inventory.add(url) is True

    assert inventory.count() == 2


def test_invalid_asset_raises():
    inventory = AssetInventory()

    with pytest.raises(
        TypeError,
        match="asset must be an instance of Asset",
    ):
        inventory.add(object())


def test_add_many():
    inventory = AssetInventory()

    assets = [
        make_asset("example.com", "domain"),
        make_asset("api.example.com", "subdomain"),
        make_asset("https://example.com", "url"),
    ]

    assert inventory.add_many(assets) == 3
    assert inventory.count() == 3


def test_add_many_deduplicates():
    inventory = AssetInventory()

    assets = [
        make_asset("example.com", "domain"),
        make_asset("example.com", "domain"),
        make_asset("api.example.com", "subdomain"),
    ]

    assert inventory.add_many(assets) == 2
    assert inventory.count() == 2


def test_get_by_id():
    inventory = AssetInventory()
    asset = make_asset()

    inventory.add(asset)

    assert inventory.get(asset.id) is asset


def test_get_missing_asset_raises():
    inventory = AssetInventory()

    with pytest.raises(
        KeyError,
        match="Asset not found: missing",
    ):
        inventory.get("missing")


def test_get_all_returns_copy():
    inventory = AssetInventory()
    inventory.add(make_asset())

    assets = inventory.get_all()
    assets.clear()

    assert inventory.count() == 1


def test_by_type():
    inventory = AssetInventory()

    inventory.add(make_asset("example.com", "domain"))
    inventory.add(make_asset("api.example.com", "subdomain"))
    inventory.add(make_asset("www.example.com", "subdomain"))
    inventory.add(make_asset("https://example.com", "url"))

    subdomains = inventory.by_type("subdomain")

    assert [
        asset.value
        for asset in subdomains
    ] == [
        "api.example.com",
        "www.example.com",
    ]


def test_by_type_returns_empty_for_unknown_type():
    inventory = AssetInventory()

    inventory.add(make_asset())

    assert inventory.by_type("unknown") == []


def test_alive_returns_only_alive_assets():
    inventory = AssetInventory()

    inventory.add(
        make_asset(
            "example.com",
            "domain",
            alive=True,
        )
    )

    inventory.add(
        make_asset(
            "dead.example.com",
            "subdomain",
            alive=False,
        )
    )

    inventory.add(
        make_asset(
            "api.example.com",
            "subdomain",
            alive=True,
        )
    )

    assert [
        asset.value
        for asset in inventory.alive()
    ] == [
        "example.com",
        "api.example.com",
    ]


def test_find_by_value():
    inventory = AssetInventory()

    asset = make_asset(
        "api.example.com",
        "subdomain",
    )

    inventory.add(asset)

    assert inventory.find("api.example.com") is asset


def test_find_missing_value_returns_none():
    inventory = AssetInventory()

    assert inventory.find("missing.example.com") is None


def test_remove_asset():
    inventory = AssetInventory()
    asset = make_asset()

    inventory.add(asset)

    assert inventory.remove(asset) is True
    assert inventory.count() == 0
    assert inventory.find(asset.value) is None


def test_remove_missing_asset_returns_false():
    inventory = AssetInventory()

    asset = make_asset()

    assert inventory.remove(asset) is False


def test_remove_invalid_asset_raises():
    inventory = AssetInventory()

    with pytest.raises(
        TypeError,
        match="asset must be an instance of Asset",
    ):
        inventory.remove(object())


def test_clear():
    inventory = AssetInventory()

    inventory.add(make_asset("one.example.com", "subdomain"))
    inventory.add(make_asset("two.example.com", "subdomain"))

    inventory.clear()

    assert inventory.count() == 0
    assert inventory.get_all() == []


def test_inventory_instances_are_independent():
    first = AssetInventory()
    second = AssetInventory()

    first.add(make_asset())

    assert first.count() == 1
    assert second.count() == 0


def test_len_matches_count():
    inventory = AssetInventory()

    inventory.add(make_asset())
    inventory.add(make_asset("api.example.com", "subdomain"))

    assert len(inventory) == inventory.count()
    assert len(inventory) == 2
