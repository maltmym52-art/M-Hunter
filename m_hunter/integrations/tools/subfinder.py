from m_hunter.integrations.tools.runner import ToolResult, ToolRunner
from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import DiscoverySource


class SubfinderSource(DiscoverySource):
    """Discovers subdomains using ProjectDiscovery Subfinder."""

    name = "subfinder"

    def __init__(
        self,
        runner: ToolRunner | None = None,
        timeout: float | None = None,
    ):
        self.runner = runner or ToolRunner()
        self.timeout = timeout

    def discover(self, target: str) -> list[Asset]:
        target = target.strip()

        if not target:
            raise ValueError(
                "target must not be empty"
            )

        result = self.runner.run_if_available(
            "subfinder",
            [
                "-d",
                target,
                "-silent",
            ],
            timeout=self.timeout,
        )

        if result is None:
            return []

        return self._parse_result(result)

    def _parse_result(
        self,
        result: ToolResult,
    ) -> list[Asset]:
        if result.timed_out:
            return []

        if result.return_code != 0:
            return []

        assets: list[Asset] = []
        seen: set[str] = set()

        for line in result.stdout.splitlines():
            value = line.strip()

            if not value:
                continue

            value = value.rstrip(".")

            if not value or value in seen:
                continue

            seen.add(value)

            assets.append(
                Asset(
                    value=value,
                    asset_type="subdomain",
                    source=self.name,
                )
            )

        return assets
