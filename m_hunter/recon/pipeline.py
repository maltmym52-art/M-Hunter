from dataclasses import dataclass, field

from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import DiscoveryEngine
from m_hunter.recon.probe import HTTPProbe, ProbeResult


@dataclass
class ReconResult:
    target: str
    discovered: list[Asset] = field(default_factory=list)
    probes: list[ProbeResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def asset_count(self) -> int:
        return len(self.discovered)

    @property
    def live_assets(self) -> list[Asset]:
        return [
            asset
            for asset in self.discovered
            if asset.alive
        ]

    @property
    def live_count(self) -> int:
        return len(self.live_assets)

    @property
    def probe_count(self) -> int:
        return len(self.probes)


class ReconPipeline:
    """Coordinates discovery and HTTP probing."""

    def __init__(
        self,
        discovery: DiscoveryEngine,
        probe: HTTPProbe | None = None,
    ):
        if not isinstance(discovery, DiscoveryEngine):
            raise TypeError(
                "discovery must be an instance of DiscoveryEngine"
            )

        self.discovery = discovery
        self.probe = probe

    def run(
        self,
        target: str,
        *,
        probe_assets: bool = True,
    ) -> ReconResult:
        target = target.strip()

        if not target:
            raise ValueError(
                "target must not be empty"
            )

        result = ReconResult(
            target=target
        )

        try:
            result.discovered = self.discovery.discover(
                target
            )
        except Exception as exc:
            result.errors.append(
                f"discovery failed: {exc}"
            )
            return result

        if not probe_assets:
            return result

        if self.probe is None:
            return result

        for asset in result.discovered:
            try:
                probe_result = self.probe.probe(
                    asset
                )
                result.probes.append(
                    probe_result
                )
            except Exception as exc:
                result.errors.append(
                    f"probe failed for "
                    f"{asset.value}: {exc}"
                )

        return result
