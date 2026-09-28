"""Uniform, optional external-tool discovery and version checks."""

from dataclasses import dataclass
from typing import Any

from m_hunter.evidence.redaction import EvidenceRedactor
from m_hunter.integrations.tools.runner import ToolRunner


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    version_arguments: tuple[str, ...]


@dataclass(frozen=True)
class ToolStatus:
    name: str
    status: str
    installed: bool
    executable: str | None = None
    version: str | None = None
    error: str | None = None


TOOL_DEFINITIONS = (
    ToolDefinition("subfinder", ("-version",)),
    ToolDefinition("amass", ("-version",)),
    ToolDefinition("httpx", ("-version",)),
    ToolDefinition("nmap", ("--version",)),
    ToolDefinition("ffuf", ("-V",)),
    ToolDefinition("nuclei", ("-version",)),
)


class ToolCatalog:
    """Resolve and query the six supported optional reconnaissance tools."""

    def __init__(self, runner: Any | None = None, *, version_timeout: float = 3.0) -> None:
        self.runner = runner or ToolRunner()
        self.version_timeout = version_timeout
        self._definitions = {item.name: item for item in TOOL_DEFINITIONS}
        self._redactor = EvidenceRedactor()

    def detect(self, name: str, *, include_version: bool = True) -> ToolStatus:
        definition = self._definitions.get(name.casefold())
        if definition is None:
            raise ValueError(f"unsupported external tool: {name}")
        try:
            resolver = getattr(self.runner, "resolve", None)
            executable = resolver(definition.name) if callable(resolver) else None
            installed = bool(executable) if callable(resolver) else self.runner.is_available(definition.name)
            if not installed:
                return ToolStatus(definition.name, "missing", False)
            version = None
            if include_version:
                invocation = executable or definition.name
                try:
                    result = self.runner.run(
                        [invocation, *definition.version_arguments],
                        timeout=self.version_timeout,
                    )
                    lines = (result.stdout or result.stderr).strip().splitlines()
                    if lines and not getattr(result, "timed_out", False):
                        version = self._redactor.redact_text(lines[0])[:160]
                except Exception:
                    version = None
            return ToolStatus(
                definition.name, "installed", True,
                executable=str(executable) if executable else None,
                version=version,
            )
        except Exception as exc:
            return ToolStatus(definition.name, "unavailable", False, error=str(exc))

    def detect_all(self, *, include_version: bool = True) -> list[ToolStatus]:
        return [self.detect(item.name, include_version=include_version)
                for item in TOOL_DEFINITIONS]
