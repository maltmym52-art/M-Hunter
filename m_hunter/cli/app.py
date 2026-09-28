"""Typer command surface over the application service.

Commands translate user options into application requests and render returned
data. Scan policy, authorization, validation, and evidence capture stay in
their respective application services.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import typer
from rich.console import Console
from rich.table import Table

from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.analyzers.metadata import MetadataAnalyzer
from m_hunter.analyzers.security_headers import SecurityHeadersAnalyzer
from m_hunter.application import (
    ApplicationService, AuthorizationGrant, ScanExecutionResult,
    ScanRequest, ScanState,
)
from m_hunter.config.settings import HttpSettings
from m_hunter.cli.contracts import ReportRequest
from m_hunter.core.http import HttpEngine
from m_hunter.core.response import HttpResponse
from m_hunter.evidence.redaction import EvidenceRedactor
from m_hunter.integrations.tools.runner import ToolRunner
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL
from m_hunter.scanners.registry import ScannerRegistry
from m_hunter.scanners.security_headers import SecurityHeadersScanner


TOOLS = ("subfinder", "amass", "httpx", "nmap", "ffuf", "nuclei")
_REDACTOR = EvidenceRedactor()
EXIT_INVALID = 2
EXIT_UNAUTHORIZED = 3
EXIT_SCOPE = 4
EXIT_OUTPUT = 5
EXIT_APPLICATION = 6


@dataclass
class CLIContext:
    """Injectable CLI dependencies; tests can supply local fakes."""

    application_service_factory: Callable[..., ApplicationService] | None = None
    tool_runner: Any = None
    console: Console | None = None


def _make_service(*, timeout: float, scope_manager: ScopeManager,
                  external_tools: bool, tool_runner: ToolRunner | None = None) -> ApplicationService:
    runner = tool_runner or ToolRunner(default_timeout=timeout)
    recon_sources: list[object] = []
    if external_tools:
        from m_hunter.integrations.tools.subfinder import SubfinderSource
        recon_sources.append(SubfinderSource(runner=runner, timeout=timeout))
    analyzers = AnalyzerRegistry()
    analyzers.register(SecurityHeadersAnalyzer())
    analyzers.register(MetadataAnalyzer())
    return ApplicationService(
        http_engine=HttpEngine(HttpSettings(timeout=timeout)),
        tool_runner=runner,
        recon_sources=recon_sources,
        scanner_registry=_default_scanners(),
        analyzer_registry=analyzers,
        scope_manager=scope_manager,
    )


def _default_scanners() -> ScannerRegistry:
    """Return supported built-in scanners, deliberately excluding ExampleScanner."""
    registry = ScannerRegistry()
    registry.register(SecurityHeadersScanner())
    return registry


def create_cli_context(*, application_service_factory=None, tool_runner=None,
                       console=None) -> CLIContext:
    """Create an injectable context for embedding and tests."""
    return CLIContext(application_service_factory, tool_runner, console)


app = typer.Typer(
    name="m-hunter", help="Web security research tools for authorized targets.",
    no_args_is_help=False, invoke_without_command=True, rich_markup_mode="rich",
)
console = Console()


def _ctx(ctx: typer.Context) -> CLIContext:
    return ctx.obj if isinstance(ctx.obj, CLIContext) else CLIContext()


def _console(ctx: typer.Context) -> Console:
    return _ctx(ctx).console or console


def _service(ctx: typer.Context, *, timeout: float, scope: ScopeManager,
             external_tools: bool) -> ApplicationService:
    deps = _ctx(ctx)
    factory = deps.application_service_factory
    if factory is not None:
        return factory(timeout=timeout, scope_manager=scope,
                       external_tools=external_tools, tool_runner=deps.tool_runner)
    return _make_service(timeout=timeout, scope_manager=scope,
                         external_tools=external_tools,
                         tool_runner=deps.tool_runner)


@app.callback()
def root(ctx: typer.Context) -> None:
    """M-Hunter Web Security Research Platform."""
    if ctx.invoked_subcommand is None:
        _console(ctx).print("[bold cyan]M-Hunter[/bold cyan] — Web Security Research Platform [dim]v0.1.0[/dim]")
        _console(ctx).print("Discover · Analyze · Validate · Report")


@app.command()
def version(ctx: typer.Context) -> None:
    """Show the installed M-Hunter version."""
    _console(ctx).print("M-Hunter 0.1.0")


def _scope(target: str, allow_hosts: list[str], exclude_paths: list[str]) -> ScopeManager:
    url = URL(target)
    hosts = {url.host, *(host.strip().lower() for host in allow_hosts if host.strip())}
    return ScopeManager(url, allowed_hosts=hosts, excluded_paths=set(exclude_paths))


def _response_from_json(path: Path, target: str) -> HttpResponse:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("response JSON must be an object")
        body = payload.get("body", "")
        content = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        headers = payload.get("headers", {})
        if not isinstance(headers, dict):
            raise ValueError("headers must be a JSON object")
        return HttpResponse(
            status_code=int(payload.get("status_code", 200)),
            url=str(payload.get("url", target)),
            headers={str(k): str(v) for k, v in headers.items()},
            content=content,
            cookies={str(k): str(v) for k, v in payload.get("cookies", {}).items()},
            response_time=float(payload.get("response_time", 0.0)),
            content_length=int(payload.get("content_length", len(content))),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise typer.BadParameter(f"cannot read HTTP response JSON: {exc}") from exc


def _safe_result(result: ScanExecutionResult, service: ApplicationService) -> dict[str, Any]:
    findings = []
    for finding in result.findings:
        evidence_records = service.evidence_service.store.for_finding(finding)
        evidence = [record.to_dict() for record in evidence_records]
        findings.append({
            "id": finding.id, "title": _safe_text(finding.title), "severity": _safe_text(finding.severity),
            "confidence": _safe_text(finding.confidence), "target": _safe_text(finding.target),
            "endpoint": _safe_text(finding.endpoint), "parameter": _safe_text(finding.parameter),
            "description": _safe_text(finding.description),
            # The evidence store is the authoritative sanitized export path.
            "evidence": [_safe_text(record.sanitized.evidence) for record in evidence_records],
            "evidence_ids": list(finding.evidence_ids), "evidence_records": evidence,
            "remediation": _safe_text(finding.remediation), "cwe": _safe_text(finding.cwe),
            "owasp": _safe_text(finding.owasp), "status": _safe_text(finding.status),
        })
    return {
        "state": result.state.value,
        "target": _safe_text(result.security.target if result.security else str(result.scan.target.url)),
        "assets": [{"value": _safe_text(a.value), "type": a.asset_type,
                    "source": _safe_text(a.source)} for a in result.assets],
        "findings": findings,
        "evidence_ids": list(result.evidence_ids),
        "errors": [{"component": _safe_text(i.component), "stage": i.stage.value, "error": _safe_text(i.error), "level": i.level} for i in result.issues],
        "statistics": vars(result.statistics),
        "duration": _duration(result),
    }


def _duration(result: ScanExecutionResult) -> float:
    """Compute elapsed seconds from the application scan lifecycle timestamps."""
    started, finished = result.scan.started_at, result.scan.finished_at
    if started is None:
        return 0.0
    return max(0.0, ((finished or datetime.now()) - started).total_seconds())


def _safe_text(value: str | None) -> str | None:
    """Redact credential patterns from arbitrary strings rendered by the CLI."""
    return _REDACTOR.redact_text(value) if value is not None else None


def _render_result(result: ScanExecutionResult, service: ApplicationService, out: Console) -> None:
    target = _safe_text(result.security.target if result.security else str(result.scan.target.url))
    out.print(f"[bold]Scan status:[/bold] {result.state.value}    [bold]Target:[/bold] {target}")
    out.print(f"Assets: {len(result.assets)}    Findings: {len(result.findings)}    Evidence: {len(result.evidence_ids)}    Duration: {_duration(result):.2f}s")
    if result.findings:
        table = Table("Severity", "Confidence", "Finding", "Endpoint", "Evidence")
        for finding in result.findings:
            count = len(service.evidence_service.store.for_finding(finding))
            table.add_row(_safe_text(finding.severity) or "", _safe_text(finding.confidence) or "",
                          _safe_text(finding.title) or "", _safe_text(finding.endpoint) or "—", str(count))
        out.print(table)
    if result.assets:
        table = Table("Asset", "Type", "Source")
        for asset in result.assets:
            table.add_row(_safe_text(asset.value) or "", asset.asset_type,
                          _safe_text(asset.source) or "—")
        out.print(table)
    for issue in result.issues:
        out.print(f"[{ 'yellow' if issue.level != 'error' else 'red' }]{issue.level}: {_safe_text(issue.component)} ({issue.stage.value}): {_safe_text(issue.error)}[/]")


def _finish_result(result: ScanExecutionResult, service: ApplicationService,
                    out: Console, output: Path | None, output_format: str) -> None:
    try:
        if output:
            payload = _safe_result(result, service)
            if output_format == "json":
                output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                output.write_text(_plain_summary(payload), encoding="utf-8")
            out.print(f"Results saved to {output}")
        elif output_format == "json":
            out.print_json(json.dumps(_safe_result(result, service), ensure_ascii=False))
        else:
            _render_result(result, service, out)
    except OSError as exc:
        out.print(f"[red]Output error:[/red] {exc}")
        raise typer.Exit(EXIT_OUTPUT)


def _plain_summary(payload: dict[str, Any]) -> str:
    return (f"M-Hunter scan: {payload['state']}\nTarget: {payload['target']}\n"
            f"Assets: {len(payload['assets'])}\nFindings: {len(payload['findings'])}\n"
            f"Evidence: {len(payload['evidence_ids'])}\n")


def _check_selected_names(service: ApplicationService, analyzers: list[str],
                          scanners: list[str], out: Console) -> None:
    """Reject typos while keeping component discovery in the registries."""
    unknown = [f"analyzer:{name}" for name in analyzers
               if name not in service.analyzer_registry.names()]
    unknown.extend(f"scanner:{name}" for name in scanners
                   if name not in service.scanner_registry.names())
    if unknown:
        out.print(f"[red]Unknown component selection:[/red] {', '.join(unknown)}")
        raise typer.Exit(EXIT_INVALID)


def _exit_for_result(result: ScanExecutionResult) -> None:
    if result.state == ScanState.FAILED:
        if result.security and not result.security.in_scope:
            raise typer.Exit(EXIT_SCOPE)
        if result.security and result.security.active_enabled and not result.security.authorization_granted:
            raise typer.Exit(EXIT_UNAUTHORIZED)
        raise typer.Exit(EXIT_APPLICATION)
    if result.state == ScanState.PARTIAL:
        raise typer.Exit(1)


@app.command()
def scan(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="HTTP(S) URL to scan."),
    active: bool = typer.Option(False, "--active/--passive", help="Enable active requests and scanner execution. Passive is the default."),
    authorization_reference: str | None = typer.Option(None, "--authorization-reference", help="Required proof/reference for authorized active testing."),
    allow_host: list[str] = typer.Option([], "--allow-host", help="Additional exact hostname in scope; repeatable."),
    exclude_path: list[str] = typer.Option([], "--exclude-path", help="Path glob excluded from scope; repeatable."),
    analyzer: list[str] = typer.Option([], "--analyzer", help="Analyzer name to run; repeatable."),
    scanner: list[str] = typer.Option([], "--scanner", help="Scanner name to run; repeatable."),
    include_example: bool = typer.Option(False, "--include-example", help="Explicitly opt in to the example scanner."),
    recon: bool = typer.Option(False, "--recon/--no-recon", help="Run configured Recon sources."),
    external_tools: bool = typer.Option(False, "--external-tools/--no-external-tools", help="Enable optional external Recon integrations."),
    output_format: str = typer.Option("text", "--format", help="Output format: text or json.", case_sensitive=False),
    output: Path | None = typer.Option(None, "--output", help="Write results to this path."),
    timeout: float = typer.Option(10.0, min=0.1, help="HTTP/tool timeout in seconds."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show extra scan diagnostics."),
) -> None:
    """Run a scoped scan through the ApplicationService."""
    out = _console(ctx)
    if output_format.lower() not in {"text", "json"}:
        raise typer.BadParameter("format must be text or json")
    if active and not (authorization_reference and authorization_reference.strip()):
        out.print("[red]Active scans require --authorization-reference.[/red]")
        raise typer.Exit(EXIT_UNAUTHORIZED)
    try:
        scope = _scope(target, allow_host, exclude_path)
    except (TypeError, ValueError) as exc:
        out.print(f"[red]Invalid target or scope:[/red] {exc}")
        raise typer.Exit(EXIT_INVALID)
    service = _service(ctx, timeout=timeout, scope=scope, external_tools=external_tools)
    _check_selected_names(service, analyzer, scanner, out)
    request = ScanRequest(
        target=target, active=active,
        authorization=AuthorizationGrant(active, authorization_reference if active else None),
        recon=recon, scanner_names=tuple(scanner) or None,
        analyzer_names=tuple(analyzer) or None,
        include_example_scanner=include_example,
    )
    result = service.run(request)
    _finish_result(result, service, out, output, output_format.lower())
    if verbose:
        out.print(f"Stages: {', '.join(f'{s.stage.value}={s.state.value}' for s in result.stages)}")
    _exit_for_result(result)


@app.command()
def recon(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="HTTP(S) URL to discover assets for."),
    allow_host: list[str] = typer.Option([], "--allow-host", help="Additional exact hostname in scope."),
    exclude_path: list[str] = typer.Option([], "--exclude-path", help="Path glob excluded from scope."),
    external_tools: bool = typer.Option(False, "--external-tools/--no-external-tools", help="Enable optional external Recon integrations."),
    output: Path | None = typer.Option(None, "--output", help="Write result JSON to this path."),
    timeout: float = typer.Option(10.0, min=0.1),
) -> None:
    """Run passive asset discovery through the ApplicationService."""
    out = _console(ctx)
    try:
        scope = _scope(target, allow_host, exclude_path)
    except (TypeError, ValueError) as exc:
        out.print(f"[red]Invalid target or scope:[/red] {exc}")
        raise typer.Exit(EXIT_INVALID)
    service = _service(ctx, timeout=timeout, scope=scope, external_tools=external_tools)
    result = service.run(ScanRequest(target, recon=True, run_scanners=False, run_analyzers=False))
    _finish_result(result, service, out, output, "json" if output else "text")
    _exit_for_result(result)


@app.command()
def analyze(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="URL associated with the saved response."),
    input_file: Path = typer.Option(..., "--input", help="JSON file containing a previously collected HTTP response."),
    analyzer: list[str] = typer.Option([], "--analyzer", help="Analyzer name to run; repeatable."),
    output: Path | None = typer.Option(None, "--output", help="Write result JSON to this path."),
    timeout: float = typer.Option(10.0, min=0.1),
) -> None:
    """Analyze a saved response without making network requests."""
    out = _console(ctx)
    try:
        scope = _scope(target, [], [])
        response = _response_from_json(input_file, target)
    except typer.BadParameter as exc:
        out.print(f"[red]{exc}[/red]")
        raise typer.Exit(EXIT_INVALID)
    except (TypeError, ValueError) as exc:
        out.print(f"[red]Invalid target:[/red] {exc}")
        raise typer.Exit(EXIT_INVALID)
    service = _service(ctx, timeout=timeout, scope=scope, external_tools=False)
    _check_selected_names(service, analyzer, [], out)
    result = service.run(ScanRequest(
        target, run_scanners=False, run_analyzers=True,
        analyzer_names=tuple(analyzer) or None,
        supplied_responses={response.url: response},
    ))
    _finish_result(result, service, out, output, "json" if output else "text")
    _exit_for_result(result)


@app.command()
def report(
    ctx: typer.Context,
    input_file: Path = typer.Argument(..., help="Scan result JSON input."),
    output_format: str = typer.Option("json", "--format", help="Requested report format: json, markdown, or html."),
    output: Path | None = typer.Option(None, "--output", help="Report destination path."),
) -> None:
    """Report command contract; report generation is delivered in Stage 6."""
    out = _console(ctx)
    if output_format.lower() not in {"json", "markdown", "html"}:
        raise typer.BadParameter("format must be json, markdown, or html")
    if not input_file.is_file():
        out.print(f"[red]Report input does not exist:[/red] {input_file}")
        raise typer.Exit(EXIT_INVALID)
    try:
        data = json.loads(input_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("result JSON must contain an object")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        out.print(f"[red]Invalid report input:[/red] {exc}")
        raise typer.Exit(EXIT_INVALID)
    report_request = ReportRequest(input_file, output_format.lower(), output)
    if report_request.output_path:
        out.print("[yellow]Report generation is not available until the Reporting stage.[/yellow]")
        raise typer.Exit(EXIT_OUTPUT)
    out.print(f"Report request accepted: {input_file} ({output_format.lower()})")
    out.print("[yellow]Generation contract is ready; report rendering arrives in Stage 6.[/yellow]")


@app.command()
def tools(ctx: typer.Context) -> None:
    """Show availability and version of optional external tools."""
    runner = _ctx(ctx).tool_runner or ToolRunner()
    out = _console(ctx)
    table = Table("Tool", "Status", "Version")
    for name in TOOLS:
        try:
            available = runner.is_available(name)
            version = "—"
            if available:
                try:
                    value = runner.run([name, "--version"], timeout=3.0)
                    text = (value.stdout or value.stderr).strip().splitlines()
                    if text:
                        version = text[0][:160]
                except Exception:
                    version = "unknown"
            table.add_row(name, "installed" if available else "missing", version)
        except Exception:
            table.add_row(name, "unknown", "unknown")
    out.print(table)


if __name__ == "__main__":
    app()
