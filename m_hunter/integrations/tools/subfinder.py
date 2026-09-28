from datetime import datetime, timezone
import json
import re
from urllib.parse import urlparse

from m_hunter.integrations.tools.runner import ToolResult, ToolRunner
from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import DiscoverySource, ReconCapabilities


class SubfinderSource(DiscoverySource):
    """Discovers subdomains using ProjectDiscovery Subfinder."""

    name = "subfinder"
    passive = True
    description = "Passive subdomain enumeration through ProjectDiscovery Subfinder."

    def __init__(
        self,
        runner: ToolRunner | None = None,
        timeout: float | None = None,
    ):
        self.runner = runner or ToolRunner()
        self.timeout = timeout
        self.last_status = "not_run"
        self.last_run_at: str | None = None
        self.last_command: tuple[str, ...] = ()

    @property
    def capabilities(self) -> ReconCapabilities:
        return ReconCapabilities(
            mode="passive", requires_authorization=False,
            supported_target_types=("domain", "url"), required_binary="subfinder",
            timeout=self.timeout, description=self.description,
        )

    def discover(self, target: str) -> list[Asset]:
        target = target.strip()

        if not target:
            raise ValueError(
                "target must not be empty"
            )

        parsed = urlparse(target if "://" in target else f"https://{target}")
        target_host = parsed.hostname
        if not target_host:
            raise ValueError("target must contain a valid host")
        arguments = ["-d", target_host, "-silent"]
        self.last_command = ("subfinder", *arguments)
        self.last_run_at = datetime.now(timezone.utc).isoformat()
        result = self.runner.run_if_available(
            "subfinder",
            arguments,
            timeout=self.timeout,
        )

        if result is None:
            self.last_status = "missing"
            return []

        return self._parse_result(result)

    def _parse_result(
        self,
        result: ToolResult,
    ) -> list[Asset]:
        if result.timed_out:
            self.last_status = "timeout"
            return []

        if result.return_code != 0:
            self.last_status = "failed"
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
            if "://" in value or not self._valid_hostname(value):
                continue

            seen.add(value)

            assets.append(Asset(
                value=value, asset_type="subdomain", source=self.name,
                metadata={"tool": self.name, "observed_at": self.last_run_at or "",
                          "command": json.dumps(self.last_command)},
            ))

        self.last_status = "completed" if assets else "empty"

        return assets

    @staticmethod
    def _valid_hostname(value: str) -> bool:
        if len(value) > 253 or not value or ".." in value:
            return False
        return all(
            1 <= len(label) <= 63
            and re.fullmatch(r"(?i)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in value.rstrip(".").split(".")
        )
