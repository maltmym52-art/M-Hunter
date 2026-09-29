"""Shared default application-service composition for CLI and desktop clients."""

from pathlib import Path

from m_hunter.analyzers.cache_control_security import CacheControlSecurityAnalyzer
from m_hunter.analyzers.http_cookie_security import HttpCookieSecurityAnalyzer
from m_hunter.analyzers.http_response_security import HttpResponseSecurityAnalyzer
from m_hunter.analyzers.metadata import MetadataAnalyzer
from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.analyzers.security_headers import SecurityHeadersAnalyzer
from m_hunter.analyzers.security_headers_baseline import SecurityHeadersBaselineAnalyzer
from m_hunter.application.service import ApplicationService
from m_hunter.config.settings import HttpSettings
from m_hunter.core.http import HttpEngine
from m_hunter.integrations.tools.recon_sources import (
    AmassSource, FfufSource, HttpxSource, NmapSource, NucleiSource,
)
from m_hunter.integrations.tools.runner import ToolRunner
from m_hunter.recon.scope import ScopeManager
from m_hunter.scanners.registry import ScannerRegistry
from m_hunter.scanners.security_headers import SecurityHeadersScanner


def default_scanner_registry() -> ScannerRegistry:
    """Build safe built-in scanners; ExampleScanner is deliberately excluded."""
    registry = ScannerRegistry()
    registry.register(SecurityHeadersScanner())
    return registry


def create_default_application_service(
    *, timeout: float = 10.0,
      external_tool_timeout: float = 45.0,
    scope_manager: ScopeManager | None = None,
    external_tools: bool = False,
    tool_runner: ToolRunner | None = None,
    recon_source_names: tuple[str, ...] | None = None,
    wordlist: Path | None = None,
) -> ApplicationService:
    """Compose the same optional integrations and analyzers for any UI client."""
    runner = tool_runner or ToolRunner(default_timeout=external_tool_timeout)
    selected = recon_source_names
    if selected is None and external_tools:
        selected = ("subfinder", "amass")
    sources: list[object] = []
    if selected:
        from m_hunter.integrations.tools.subfinder import SubfinderSource
        constructors = {
            "subfinder": lambda: SubfinderSource(runner=runner, timeout=external_tool_timeout),
            "amass": lambda: AmassSource(runner, timeout=external_tool_timeout),
            "httpx": lambda: HttpxSource(runner, timeout=external_tool_timeout),
            "nmap": lambda: NmapSource(runner, timeout=external_tool_timeout),
            "ffuf": lambda: FfufSource(runner, timeout=external_tool_timeout, wordlist=wordlist),
            "nuclei": lambda: NucleiSource(runner, timeout=external_tool_timeout),
        }
        unknown = set(selected) - constructors.keys()
        if unknown:
            raise ValueError(f"unknown Recon source(s): {', '.join(sorted(unknown))}")
        sources.extend(constructors[name]() for name in dict.fromkeys(selected))
    analyzers = AnalyzerRegistry()
    for analyzer in (
        SecurityHeadersAnalyzer(), MetadataAnalyzer(), SecurityHeadersBaselineAnalyzer(),
        HttpCookieSecurityAnalyzer(), CacheControlSecurityAnalyzer(),
        HttpResponseSecurityAnalyzer(),
    ):
        analyzers.register(analyzer)
    return ApplicationService(
        http_engine=HttpEngine(HttpSettings(timeout=timeout)),
        tool_runner=runner,
        recon_sources=sources,
        scanner_registry=default_scanner_registry(),
        analyzer_registry=analyzers,
        scope_manager=scope_manager,
    )
