from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from m_hunter.recon.asset import Asset
from m_hunter.recon.inventory import AssetInventory


@dataclass(frozen=True)
class ReconCapabilities:
    """Declared execution and input requirements for a Recon source."""

    mode: Literal["passive", "active"]
    requires_authorization: bool
    supported_target_types: tuple[str, ...]
    required_binary: str | None
    timeout: float | None
    description: str

    def __post_init__(self) -> None:
        if self.mode not in {"passive", "active"}:
            raise ValueError("Recon mode must be passive or active")
        if self.mode == "active" and not self.requires_authorization:
            raise ValueError("active Recon sources must require authorization")


class DiscoverySource(ABC):
    """Base interface for a Recon asset discovery source."""

    name: str = "base"
    passive: bool = False
    scope_aware: bool = False

    @property
    def capabilities(self) -> ReconCapabilities:
        """Backward-compatible inferred capability for legacy discovery sources."""
        passive = bool(getattr(self, "passive", False))
        return ReconCapabilities(
            mode="passive" if passive else "active",
            requires_authorization=not passive,
            supported_target_types=("domain", "url"),
            required_binary=None,
            timeout=None,
            description=getattr(self, "description", self.__class__.__name__),
        )

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
