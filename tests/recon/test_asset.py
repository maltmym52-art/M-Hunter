from datetime import datetime

import pytest

from m_hunter.recon.asset import Asset, VALID_ASSET_TYPES


def test_asset_defaults():
    asset = Asset(
        value="example.com",
        asset_type="domain",
    )

    assert asset.value == "example.com"
    assert asset.asset_type == "domain"
    assert asset.id
    assert asset.alive is False
    assert asset.source is None
    assert isinstance(asset.discovered_at, datetime)
    assert asset.metadata == {}


def test_all_asset_types_are_supported():
    for asset_type in VALID_ASSET_TYPES:
        asset = Asset(
            value="example",
            asset_type=asset_type,
        )

        assert asset.asset_type == asset_type


def test_value_is_trimmed():
    asset = Asset(
        value="  example.com  ",
        asset_type="domain",
    )

    assert asset.value == "example.com"


def test_empty_value_is_rejected():
    with pytest.raises(
        ValueError,
        match="value must not be empty",
    ):
        Asset(
            value="",
            asset_type="domain",
        )


def test_whitespace_value_is_rejected():
    with pytest.raises(
        ValueError,
        match="value must not be empty",
    ):
        Asset(
            value="   ",
            asset_type="domain",
        )


def test_invalid_asset_type_is_rejected():
    with pytest.raises(
        ValueError,
        match="invalid asset type",
    ):
        Asset(
            value="example.com",
            asset_type="unknown",
        )


def test_mark_alive():
    asset = Asset(
        value="https://example.com",
        asset_type="url",
    )

    asset.mark_alive()

    assert asset.alive is True


def test_mark_dead():
    asset = Asset(
        value="https://example.com",
        asset_type="url",
        alive=True,
    )

    asset.mark_dead()

    assert asset.alive is False


def test_add_metadata():
    asset = Asset(
        value="example.com",
        asset_type="domain",
    )

    asset.add_metadata("source", "subfinder")

    assert asset.metadata == {
        "source": "subfinder",
    }


def test_has_metadata():
    asset = Asset(
        value="example.com",
        asset_type="domain",
    )

    asset.add_metadata("source", "subfinder")

    assert asset.has_metadata("source") is True
    assert asset.has_metadata("missing") is False


def test_empty_metadata_key_is_rejected():
    asset = Asset(
        value="example.com",
        asset_type="domain",
    )

    with pytest.raises(
        ValueError,
        match="metadata key must not be empty",
    ):
        asset.add_metadata("", "value")


def test_assets_with_same_type_and_value_are_equal():
    first = Asset(
        value="example.com",
        asset_type="domain",
    )

    second = Asset(
        value="example.com",
        asset_type="domain",
    )

    assert first == second


def test_assets_with_different_type_are_not_equal():
    first = Asset(
        value="example.com",
        asset_type="domain",
    )

    second = Asset(
        value="example.com",
        asset_type="subdomain",
    )

    assert first != second


def test_assets_with_different_value_are_not_equal():
    first = Asset(
        value="one.example.com",
        asset_type="subdomain",
    )

    second = Asset(
        value="two.example.com",
        asset_type="subdomain",
    )

    assert first != second


def test_asset_can_be_used_in_a_set():
    first = Asset(
        value="example.com",
        asset_type="domain",
    )

    second = Asset(
        value="example.com",
        asset_type="domain",
    )

    assets = {first, second}

    assert len(assets) == 1
