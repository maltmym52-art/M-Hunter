"""Scope-aware Recon adapters for optional third-party command-line tools."""

from abc import abstractmethod
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

from m_hunter.application.models import AuthorizationGrant
from m_hunter.application.scope import ScopeViolation, is_in_scope
from m_hunter.evidence.redaction import EvidenceRedactor
from m_hunter.integrations.tools.catalog import ToolCatalog
from m_hunter.integrations.tools.runner import ToolResult, ToolRunner
from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import DiscoverySource, ReconCapabilities
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL


class ExternalToolError(RuntimeError):
    """An external Recon command failed, timed out, or returned malformed data."""


class ExternalReconSource(DiscoverySource):
    """Base adapter enforcing capabilities, structured argv, and safe parsing."""

    name = "external"
    binary = ""
    mode = "passive"
    timeout = 30.0
    target_types = ("domain", "url")
    description = "Optional external Recon source."
    scope_aware = True

    def __init__(self, runner: Any | None = None, *, timeout: float | None = None) -> None:
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        self.runner = runner or ToolRunner()
        self.timeout = float(timeout if timeout is not None else self.timeout)
        self.last_status = "not_run"
        self.last_run_at: str | None = None
        self.last_command: tuple[str, ...] = ()
        self._redactor = EvidenceRedactor()

    @property
    def passive(self) -> bool:
        return self.mode == "passive"

    @property
    def capabilities(self) -> ReconCapabilities:
        return ReconCapabilities(
            mode=self.mode, requires_authorization=self.mode == "active",
            supported_target_types=self.target_types, required_binary=self.binary,
            timeout=self.timeout, description=self.description,
        )

    def discover(self, target: str) -> list[Asset]:
        if self.mode == "active":
            raise ScopeViolation(f"{self.name} requires discover_scoped with active authorization")
        host = self._host(target)
        return self._execute(host, target)

    def discover_scoped(
        self,
        target: str,
        *,
        scope_manager: ScopeManager,
        authorization: AuthorizationGrant,
        active_enabled: bool = False,
        **dependencies: Any,
    ) -> list[Asset]:
        """Check authorization and exact scope before building/running argv."""
        if not is_in_scope(scope_manager, target):
            raise ScopeViolation(f"Recon target is outside scope: {target}")
        if self.mode == "active":
            if not active_enabled:
                raise ScopeViolation(f"{self.name} requires explicit active mode")
            if not authorization.authorized:
                raise ScopeViolation(f"{self.name} requires explicit authorization")
        wordlist = dependencies.get("wordlist") if self.name == "ffuf" else None
        assets = self._execute(self._host(target), target, wordlist=wordlist)
        accepted: list[Asset] = []
        for asset in assets:
            asset_url = asset.value if asset.value.startswith(("http://", "https://")) else f"{urlparse(target).scheme or 'https'}://{asset.value}"
            if is_in_scope(scope_manager, asset_url):
                accepted.append(asset)
        return accepted

    def _execute(self, host: str, original_target: str, *, wordlist: Path | None = None) -> list[Asset]:
        status = ToolCatalog(self.runner).detect(self.binary, include_version=False)
        if not status.installed:
            self.last_status = "missing"
            return []
        if self.name == "ffuf" and wordlist is not None:
            arguments = self.arguments(host, original_target, wordlist=wordlist)
        else:
            arguments = self.arguments(host, original_target)
        command = (status.executable or self.binary, *map(str, arguments))
        self.last_command = tuple(self._safe_command((self.binary, *map(str, arguments))))
        self.last_run_at = datetime.now(timezone.utc).isoformat()
        try:
            if self.mode == "active" and callable(getattr(self.runner, "run_scoped", None)):
                result = self.runner.run_scoped(
                    original_target, command, timeout=self.timeout,
                )
            else:
                result = self.runner.run(command, timeout=self.timeout)
        except (ScopeViolation, ExternalToolError):
            self.last_status = "failed"
            raise
        except Exception as exc:
            self.last_status = "failed"
            raise ExternalToolError(f"{self.name} execution failed: {exc}") from exc
        if result.timed_out:
            self.last_status = "timeout"
            raise ExternalToolError(f"{self.name} timed out after {self.timeout:g}s")
        if result.return_code != 0:
            self.last_status = "failed"
            raise ExternalToolError(f"{self.name} exited with status {result.return_code}")
        try:
            assets = self.parse(result.stdout, host, original_target)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.last_status = "malformed"
            raise ExternalToolError(f"{self.name} returned malformed output: {exc}") from exc
        self.last_status = "completed" if assets else "empty"
        for asset in assets:
            asset.metadata.update({
                "tool": self.name,
                "observed_at": self.last_run_at or "",
                "command": json.dumps(self.last_command, ensure_ascii=False),
            })
        return assets

    def _safe_command(self, command: tuple[str, ...]) -> list[str]:
        values = list(command)
        # A wordlist path is operator-local configuration, not report evidence.
        for index, argument in enumerate(values[:-1]):
            if argument == "-w":
                values[index + 1] = "<WORDLIST>"
        return [self._redactor.redact_text(value) for value in values]

    @staticmethod
    def _host(target: str) -> str:
        value = target.strip()
        if not value:
            raise ValueError("target must not be empty")
        parsed = urlparse(value if "://" in value else f"https://{value}")
        if not parsed.hostname:
            raise ValueError("target must contain a valid host")
        return parsed.hostname

    @abstractmethod
    def arguments(self, host: str, target: str) -> list[str]:
        """Return argument tokens; never return a shell command string."""

    @abstractmethod
    def parse(self, output: str, host: str, target: str) -> list[Asset]:
        """Parse stdout into established Asset objects."""


class AmassSource(ExternalReconSource):
    name = binary = "amass"
    mode = "passive"
    description = "Passive subdomain enumeration through Amass."

    def arguments(self, host: str, target: str) -> list[str]:
        return ["enum", "-passive", "-d", host]

    def parse(self, output: str, host: str, target: str) -> list[Asset]:
        return _host_assets(output.splitlines(), self.name)


class HttpxSource(ExternalReconSource):
    name = binary = "httpx"
    mode = "active"
    target_types = ("domain", "url")
    description = "HTTP probing and metadata collection through ProjectDiscovery httpx."

    def arguments(self, host: str, target: str) -> list[str]:
        return ["-silent", "-json", "-status-code", "-title", "-tech-detect",
                "-no-color", "-rl", "10", "-timeout", str(max(1, int(self.timeout))), "-u", target]

    def parse(self, output: str, host: str, target: str) -> list[Asset]:
        assets = []
        for item in _json_lines(output):
            value = item.get("url") or item.get("input")
            if not isinstance(value, str) or not value.startswith(("http://", "https://")):
                continue
            try:
                url = URL(value)
            except ValueError:
                continue
            assets.append(Asset(value=str(url), asset_type="url", source=self.name,
                                metadata={key: self._redactor.redact_text(str(item[key]))
                                          for key in ("status_code", "title", "webserver") if item.get(key) is not None}))
        return _deduplicate(assets)


class NmapSource(ExternalReconSource):
    name = binary = "nmap"
    mode = "active"
    target_types = ("domain", "url")
    description = "Conservative TCP probe limited to common web service ports."
    WEB_PORTS = frozenset({80, 443, 8000, 8080, 8443})

    def arguments(self, host: str, target: str) -> list[str]:
        return ["-Pn", "-n", "-sT", "-T3", "-p", "80,443,8000,8080,8443", "-oG", "-", host]

    def parse(self, output: str, host: str, target: str) -> list[Asset]:
        assets = []
        for line in output.splitlines():
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            host_part = line.split("Ports:", 1)[0]
            target_host = host_part.split("(", 1)[1].split(")", 1)[0] if "(" in host_part else host
            for entry in line.split("Ports:", 1)[1].split(","):
                fields = entry.strip().split("/")
                if len(fields) < 5 or fields[1].casefold() != "open":
                    continue
                try:
                    port = int(fields[0])
                except ValueError:
                    continue
                if port not in self.WEB_PORTS:
                    continue
                service = fields[4].casefold()
                scheme = "https" if port in {443, 8443} or "https" in service else "http"
                value = f"{scheme}://{target_host}:{port}/"
                assets.append(Asset(value, "endpoint", source=self.name,
                                    metadata={"port": str(port), "service": service}))
        return _deduplicate(assets)


class FfufSource(ExternalReconSource):
    name = binary = "ffuf"
    mode = "active"
    target_types = ("url",)
    description = "Explicit wordlist-based content discovery against one in-scope URL."

    def __init__(self, runner: Any | None = None, *, timeout: float | None = None,
                 wordlist: str | Path | None = None) -> None:
        super().__init__(runner, timeout=timeout)
        self.wordlist = Path(wordlist).expanduser().resolve() if wordlist else None

    def arguments(self, host: str, target: str, *, wordlist: Path | None = None) -> list[str]:
        selected_wordlist = Path(wordlist).expanduser().resolve() if wordlist else self.wordlist
        if selected_wordlist is None or not selected_wordlist.is_file():
            raise ValueError("ffuf requires an existing --wordlist file")
        parsed = urlparse(target)
        base = target.rstrip("/") + "/FUZZ"
        return ["-u", base, "-w", str(selected_wordlist), "-mc", "all", "-json",
                "-rate", "10", "-t", "5", "-noninteractive",
                "-timeout", str(max(1, int(self.timeout)))]

    def parse(self, output: str, host: str, target: str) -> list[Asset]:
        if not output.strip():
            return []
        payload = json.loads(output)
        if not isinstance(payload, dict) or not isinstance(payload.get("results", []), list):
            raise ValueError("expected ffuf JSON object with results array")
        assets = []
        for item in payload.get("results", []):
            if not isinstance(item, dict) or not isinstance(item.get("url"), str):
                continue
            try:
                url = URL(item["url"])
            except ValueError:
                continue
            assets.append(Asset(str(url), "endpoint", source=self.name,
                                metadata={"status": str(item.get("status", "")),
                                          "length": str(item.get("length", ""))}))
        return _deduplicate(assets)


class NucleiSource(ExternalReconSource):
    name = binary = "nuclei"
    mode = "active"
    target_types = ("url",)
    description = "Optional active template scan; output becomes scoped observations, never Findings."

    def arguments(self, host: str, target: str) -> list[str]:
        return ["-u", target, "-jsonl", "-silent", "-no-color", "-no-interactsh",
                "-rl", "10", "-c", "5", "-timeout", str(max(1, int(self.timeout))),
                "-retries", "0"]

    def parse(self, output: str, host: str, target: str) -> list[Asset]:
        assets = []
        for item in _json_lines(output):
            matched = item.get("matched-at") or item.get("matched_at")
            if not isinstance(matched, str):
                continue
            try:
                url = URL(matched)
            except ValueError:
                continue
            info = item.get("info") if isinstance(item.get("info"), dict) else {}
            metadata = {
                "template_id": self._redactor.redact_text(str(item.get("template-id", ""))),
                "severity": self._redactor.redact_text(str(info.get("severity", ""))),
                "matcher_name": self._redactor.redact_text(str(item.get("matcher-name", ""))),
                "validation_state": "unvalidated_observation",
            }
            assets.append(Asset(str(url), "endpoint", source=self.name, metadata=metadata))
        return _deduplicate(assets)


def _json_lines(output: str) -> list[dict[str, Any]]:
    values = []
    for line in output.splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("expected one JSON object per line")
        values.append(value)
    return values


def _host_assets(lines: list[str], source: str) -> list[Asset]:
    assets = []
    seen = set()
    for line in lines:
        value = line.strip().rstrip(".")
        if not _valid_hostname(value):
            continue
        if value.casefold() in seen:
            continue
        try:
            # Validate using URL parsing without changing hostname labels.
            parsed = URL(f"https://{value}")
        except ValueError:
            continue
        seen.add(value.casefold())
        assets.append(Asset(parsed.host, "subdomain", source=source))
    return assets


def _valid_hostname(value: str) -> bool:
    if len(value) > 253 or not value or ".." in value:
        return False
    labels = value.rstrip(".").split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"(?i)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    )


def _deduplicate(assets: list[Asset]) -> list[Asset]:
    unique = []
    seen = set()
    for asset in assets:
        key = (asset.asset_type, asset.value.casefold())
        if key not in seen:
            seen.add(key)
            unique.append(asset)
    return unique
