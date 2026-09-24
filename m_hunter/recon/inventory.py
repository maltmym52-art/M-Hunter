from m_hunter.recon.asset import Asset


class AssetInventory:
    """Stores, deduplicates, searches, and filters discovered assets."""

    def __init__(self):
        self._assets: dict[tuple[str, str], Asset] = {}

    @staticmethod
    def _key(asset: Asset) -> tuple[str, str]:
        return asset.asset_type, asset.value

    def add(self, asset: Asset) -> bool:
        if not isinstance(asset, Asset):
            raise TypeError("asset must be an instance of Asset")

        key = self._key(asset)

        if key in self._assets:
            return False

        self._assets[key] = asset
        return True

    def add_many(self, assets: list[Asset]) -> int:
        added = 0

        for asset in assets:
            if self.add(asset):
                added += 1

        return added

    def get(self, asset_id: str) -> Asset:
        for asset in self._assets.values():
            if asset.id == asset_id:
                return asset

        raise KeyError(f"Asset not found: {asset_id}")

    def get_all(self) -> list[Asset]:
        return list(self._assets.values())

    def by_type(self, asset_type: str) -> list[Asset]:
        return [
            asset
            for asset in self._assets.values()
            if asset.asset_type == asset_type
        ]

    def alive(self) -> list[Asset]:
        return [
            asset
            for asset in self._assets.values()
            if asset.alive
        ]

    def find(self, value: str) -> Asset | None:
        for asset in self._assets.values():
            if asset.value == value:
                return asset

        return None

    def remove(self, asset: Asset) -> bool:
        if not isinstance(asset, Asset):
            raise TypeError("asset must be an instance of Asset")

        key = self._key(asset)

        if key not in self._assets:
            return False

        del self._assets[key]
        return True

    def count(self) -> int:
        return len(self._assets)

    def clear(self) -> None:
        self._assets.clear()

    def __len__(self) -> int:
        return self.count()
