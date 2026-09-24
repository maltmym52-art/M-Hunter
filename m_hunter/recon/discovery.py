from abc import ABC, abstractmethod

from m_hunter.recon.asset import Asset
from m_hunter.recon.inventory import AssetInventory


class DiscoverySource(ABC):
    """Base interface for a Recon asset discovery source."""

    name: str = "base"

    @abstractmethod
    def discover(self, target: str) -> list[Asset]:
        """Discover assets for a target."""
        raise NotImplementedError


class StaticDiscoverySource(DiscoverySource):
    """Simple discovery source useful for testing and local workflows."""

    name = "static"

    def __init__(self, assets: list[Asset] | None = None):
        self.assets = list(assets or [])

    def discover(self, target: str) -> list[Asset]:
        return list(self.assets)


class DiscoveryEngine:
    """Runs discovery sources and stores results in an AssetInventory."""

    def __init__(
        self,
        sources: list[DiscoverySource] | None = None,
        inventory: AssetInventory | None = None,
    ):
        self.sources: list[DiscoverySource] = list(sources or [])
        self.inventory = (inventory if inventory is not None else AssetInventory())

    def add_source(self, source: DiscoverySource) -> None:
        if not isinstance(source, DiscoverySource):
            raise TypeError(
                "source must be an instance of DiscoverySource"
            )

        if any(
            existing.name == source.name
            for existing in self.sources
        ):
            raise ValueError(
                f"Discovery source already registered: {source.name}"
            )

        self.sources.append(source)

    def get_sources(self) -> list[DiscoverySource]:
        return list(self.sources)

    def source_names(self) -> list[str]:
        return [
            source.name
            for source in self.sources
        ]

    def discover(self, target: str) -> list[Asset]:
        discovered: list[Asset] = []

        for source in self.sources:
            assets = source.discover(target)

            for asset in assets:
                if self.inventory.add(asset):
                    discovered.append(asset)

        return discovered

    def count_sources(self) -> int:
        return len(self.sources)

    def clear_sources(self) -> None:
        self.sources.clear()
