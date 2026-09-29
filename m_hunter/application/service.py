"""Orchestrate scan components without coupling execution to a user interface."""

from datetime import datetime, timezone
from threading import RLock
from typing import Mapping

from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.application.models import (
    ScanExecutionResult,
    ScanIssue,
    ScanRequest,
    ScanSecurityContext,
    ScanStage,
    ScanState,
    StageRecord,
    StageState,
)
from m_hunter.application.scope import (
    ScopeViolation,
    ScopedHttpEngine,
    ScopedToolRunner,
    asset_url,
    is_in_scope,
)
from m_hunter.core.engine import ScanEngine
from m_hunter.core.finding import Finding
from m_hunter.core.http import HttpEngine
from m_hunter.core.request import HttpRequest
from m_hunter.core.scan import Scan
from m_hunter.core.target import Target
from m_hunter.evidence.service import EvidenceService
from m_hunter.evidence.redaction import EvidenceRedactor
from m_hunter.events.scan import (
    AssetDiscovered, ErrorOccurred, FindingCreated, RequestCompleted,
    ScanCancelled, ScanCompleted, ScanEventBus, ScanStarted, StageStarted,
    StageUpdated,
)
from m_hunter.findings.converter import (
    FindingProcessingStatus,
)
from m_hunter.integrations.tools.runner import ToolRunner
from m_hunter.integrations.tools.catalog import ToolCatalog
from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import DiscoveryEngine
from m_hunter.recon.pipeline import ReconPipeline
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL
from m_hunter.scanners.registry import ScannerRegistry
from m_hunter.validation.analysis import AnalysisValidation
from m_hunter.validation.analysis_pipeline import AnalysisFindingPipeline
from m_hunter.validation.indicator_adapter import default_security_validators


class ApplicationService:
    """Execute the target-to-findings workflow with injected dependencies.

    HTTP collection and scanner execution are active operations. They are
    disabled by default, require an explicit ``AuthorizationGrant``, and pass
    through ``ScopedHttpEngine``/the central scope checks.
    """

    def __init__(
        self,
        *,
        http_engine: object | None = None,
        tool_runner: ToolRunner | None = None,
        recon_pipeline: ReconPipeline | None = None,
        recon_sources: list[object] | None = None,
        scanner_registry: ScannerRegistry | None = None,
        analyzer_registry: AnalyzerRegistry | None = None,
        evidence_service: EvidenceService | None = None,
        scope_manager: ScopeManager | None = None,
        validators: Mapping[str, object] | None = None,
        finding_pipeline: AnalysisFindingPipeline | None = None,
        engine: ScanEngine | None = None,
        event_bus: ScanEventBus | None = None,
    ) -> None:
        inherited_http = getattr(engine, "http_engine", None) if engine is not None else None
        inherited_runner = getattr(engine, "tool_runner", None) if engine is not None else None
        self._owns_http_engine = http_engine is None and inherited_http is None
        self.http_engine = (
            http_engine if http_engine is not None
            else inherited_http if inherited_http is not None
            else HttpEngine()
        )
        self.tool_runner = (
            tool_runner if tool_runner is not None
            else inherited_runner if inherited_runner is not None
            else ToolRunner()
        )
        self.evidence_service = evidence_service if evidence_service is not None else EvidenceService()
        self._scope_manager = scope_manager
        self.validators = {**default_security_validators(), **dict(validators or {})}
        self._scanner_lock = RLock()
        self.event_bus = event_bus or ScanEventBus()
        self._event_redactor = EvidenceRedactor()

        self.scanner_registry = (
            scanner_registry if scanner_registry is not None
            else engine.registry if engine is not None
            else ScannerRegistry()
        )
        self.analyzer_registry = (
            analyzer_registry if analyzer_registry is not None
            else engine.analyzer_registry if engine is not None
            else AnalyzerRegistry()
        )

        if recon_pipeline is None:
            for source in recon_sources or []:
                if hasattr(source, "runner"):
                    source.runner = self.tool_runner
            discovery = DiscoveryEngine(sources=recon_sources or [])
            recon_pipeline = ReconPipeline(discovery=discovery, probe=None)
        self.recon_pipeline = recon_pipeline
        for source in self.recon_pipeline.discovery.get_sources():
            if hasattr(source, "runner"):
                source.runner = self.tool_runner

        self.finding_pipeline = (
            finding_pipeline if finding_pipeline is not None
            else engine.finding_pipeline if engine is not None
            else AnalysisFindingPipeline(evidence_service=self.evidence_service)
        )
        if finding_pipeline is not None or engine is not None:
            # Keep all stages on the same per-service evidence store.
            self.evidence_service = self.finding_pipeline.evidence_service
        self.engine = engine or ScanEngine(
            self.scanner_registry,
            analyzer_registry=self.analyzer_registry,
            finding_pipeline=self.finding_pipeline,
            http_engine=self.http_engine,
            tool_runner=self.tool_runner,
            auto_discover=False,
        )
        # The engine's legacy methods remain available and share these services.
        self.engine.http_engine = self.http_engine
        self.engine.tool_runner = self.tool_runner
        self.engine.registry = self.scanner_registry
        self.engine.analyzer_registry = self.analyzer_registry
        self.engine.finding_pipeline = self.finding_pipeline

    def run(self, request: ScanRequest) -> ScanExecutionResult:
        """Run one scan request and return lifecycle, issues, and aggregated data."""
        if not isinstance(request, ScanRequest):
            raise TypeError("request must be a ScanRequest")
        target = Target(request.target.strip())
        target_url = target.url
        target_url_obj = URL(target_url)
        scope = self._scope_manager or ScopeManager(target_url_obj)
        scan = Scan(target)
        result = ScanExecutionResult(scan=scan)
        result.state = ScanState.RUNNING
        scan.start()
        self._publish(ScanStarted, result, message="scan started")

        try:
            self._stage(result, ScanStage.SCOPE, StageState.RUNNING)
            target_in_scope = scope.is_allowed(target_url_obj)
            result.security = ScanSecurityContext(
                target=target_url,
                in_scope=target_in_scope,
                authorization_granted=request.authorization.authorized,
                active_enabled=request.active,
                authorization_reference=request.authorization.reference,
            )
            if not target_in_scope:
                self._issue(
                    result,
                    "ScopeManager",
                    ScanStage.SCOPE,
                    "target is outside the configured scope",
                    target=target_url,
                )
                self._stage(result, ScanStage.SCOPE, StageState.FAILED)
                return self._finish(result, ScanState.FAILED)
            self._stage(result, ScanStage.SCOPE, StageState.COMPLETED)

            if request.active and not request.authorization.authorized:
                self._issue(
                    result,
                    "Authorization",
                    ScanStage.SCOPE,
                    "active operations require explicit authorization",
                    target=target_url,
                )
                self._stage(result, ScanStage.SCOPE, StageState.FAILED)
                return self._finish(result, ScanState.FAILED)

            if self._cancelled(request):
                return self._finish(result, ScanState.CANCELLED)

            self._run_recon(request, result, target_url, scope)
            if self._cancelled(request):
                return self._finish(result, ScanState.CANCELLED)

            responses = self._collect_http(request, result, scope, target_url)
            if self._cancelled(request):
                return self._finish(result, ScanState.CANCELLED)

            if request.active and request.run_scanners:
                self._run_scanners(request, result, scope, target_url)
                responses.update(result.responses)
            else:
                self._stage(result, ScanStage.SCANNERS, StageState.SKIPPED)

            if request.run_analyzers:
                self._run_analyzers(request, result, scope, responses, target_url)
            else:
                self._stage(result, ScanStage.ANALYZERS, StageState.SKIPPED)
                self._stage(result, ScanStage.VALIDATION, StageState.SKIPPED)
                self._stage(result, ScanStage.EVIDENCE, StageState.SKIPPED)

            self._stage(result, ScanStage.AGGREGATION, StageState.RUNNING)
            result.findings = self._deduplicate_findings(result.findings, result)
            result.evidence_ids = list(
                dict.fromkeys(
                    evidence_id
                    for finding in result.findings
                    for evidence_id in finding.evidence_ids
                )
            )
            stats = result.statistics
            stats.findings = len(result.findings)
            stats.evidence_records = len(result.evidence_ids)
            stats.errors = len(result.errors)
            stats.warnings = len(result.warnings)
            self._stage(result, ScanStage.AGGREGATION, StageState.COMPLETED)

            final_state = (
                ScanState.PARTIAL if result.errors else ScanState.COMPLETED
            )
            return self._finish(result, final_state)
        except Exception as exc:
            self._issue(
                result,
                "ApplicationService",
                ScanStage.AGGREGATION,
                str(exc),
                target=target_url,
            )
            return self._finish(result, ScanState.PARTIAL if result.findings else ScanState.FAILED)

    def _run_recon(
        self,
        request: ScanRequest,
        result: ScanExecutionResult,
        target_url: str,
        scope: ScopeManager,
    ) -> None:
        self._stage(result, ScanStage.RECON, StageState.RUNNING)
        result.assets.append(Asset(target_url, "url", source="target"))
        self._publish(AssetDiscovered, result, stage=ScanStage.RECON.value,
                      message="target")
        if not request.recon:
            self._stage(result, ScanStage.RECON, StageState.SKIPPED)
            result.statistics.assets_discovered = len(result.assets)
            return
        registered_sources = self.recon_pipeline.discovery.get_sources()
        requested_names = request.recon_source_names
        by_name = {getattr(source, "name", source.__class__.__name__): source
                   for source in registered_sources}
        if requested_names is None:
            # Safe scans run passive sources only; explicit active mode opts
            # into configured active sources for backwards-compatible callers.
            sources = [source for source in registered_sources
                       if self._recon_mode(source) == "passive"
                       or (request.active and self._recon_mode(source) == "active")]
        else:
            sources = []
            for name in requested_names:
                source = by_name.get(name)
                if source is None:
                    self._issue(result, name, ScanStage.RECON,
                                f"unknown Recon source: {name}", target=target_url)
                    continue
                sources.append(source)
        try:
            passive_sources = []
            active_sources = []
            for source in sources:
                passive = self._recon_mode(source) == "passive"
                if not passive and not request.active:
                    self._issue(
                        result,
                        getattr(source, "name", source.__class__.__name__),
                        ScanStage.RECON,
                        "active Recon source requires explicit active mode and authorization",
                        target=target_url,
                        level="error",
                    )
                    continue
                if not passive and not callable(getattr(source, "discover_scoped", None)):
                    self._issue(
                        result,
                        getattr(source, "name", source.__class__.__name__),
                        ScanStage.RECON,
                        "active recon source skipped because it has no scoped execution adapter",
                        target=target_url,
                        level="warning",
                    )
                    continue
                capabilities = getattr(source, "capabilities", None)
                tool_name = getattr(capabilities, "required_binary", None) or getattr(source, "name", "").casefold()
                if tool_name in {"subfinder", "amass", "httpx", "nmap", "ffuf", "nuclei"} and not self.tool_runner.is_available(tool_name):
                    if hasattr(source, "last_status"):
                        source.last_status = "missing"
                    self._issue(
                        result,
                        tool_name,
                        ScanStage.RECON,
                        f"optional external tool is not installed: {tool_name}",
                        target=target_url,
                        level="warning",
                    )
                    continue
                (passive_sources if passive else active_sources).append(source)

            # Run each passive source through ReconPipeline with a fresh
            # inventory so one broken integration cannot hide later results.
            discovered = []
            for source in passive_sources:
                pipeline = ReconPipeline(
                    discovery=DiscoveryEngine(sources=[source]),
                    probe=None,
                )
                recon = pipeline.run(target_url, probe_assets=False)
                for error in recon.errors:
                    self._issue(
                        result,
                        getattr(source, "name", "ReconPipeline"),
                        ScanStage.RECON,
                        error,
                        target=target_url,
                    )
                discovered.extend(recon.discovered)
                if not recon.errors:
                    self._record_source_status(source, result, target_url)

            guarded_http = ScopedHttpEngine(
                self.http_engine,
                scope,
                request.authorization,
                active_enabled=request.active,
            )
            guarded_tools = ScopedToolRunner(
                self.tool_runner,
                scope,
                request.authorization,
            )
            for source in active_sources:
                original_runner = getattr(source, "runner", None)
                try:
                    if hasattr(source, "runner"):
                        source.runner = guarded_tools
                    discovered.extend(
                        source.discover_scoped(
                            target_url,
                            scope_manager=scope,
                            authorization=request.authorization,
                            active_enabled=request.active,
                            http_engine=guarded_http,
                            tool_runner=guarded_tools,
                        )
                    )
                    self._record_source_status(source, result, target_url)
                except Exception as exc:
                    self._issue(result, source.name, ScanStage.RECON, str(exc), target=target_url)
                finally:
                    if hasattr(source, "runner"):
                        source.runner = original_runner
            self._merge_observations(result, guarded_http)
            result.statistics.http_requests += guarded_http.request_count

            for asset in discovered:
                url = asset_url(asset.value, target_url)
                if is_in_scope(scope, url):
                    result.assets.append(asset)
                    self._publish(AssetDiscovered, result, stage=ScanStage.RECON.value,
                                  message=asset.asset_type)
                else:
                    self._issue(
                        result,
                        "ScopeManager",
                        ScanStage.RECON,
                        f"discovered asset rejected as out of scope: {asset.value}",
                        target=target_url,
                        endpoint=url,
                        level="warning",
                    )
        except Exception as exc:
            self._issue(result, "ReconPipeline", ScanStage.RECON, str(exc), target=target_url)
        result.assets = self._deduplicate_assets(result.assets)
        result.statistics.assets_discovered = len(result.assets)
        self._stage(
            result,
            ScanStage.RECON,
            StageState.PARTIAL if result.errors else StageState.COMPLETED,
        )

    @staticmethod
    def _recon_mode(source: object) -> str:
        capabilities = getattr(source, "capabilities", None)
        mode = getattr(capabilities, "mode", None)
        if mode in {"passive", "active"}:
            return mode
        return "passive" if bool(getattr(source, "passive", False)) else "active"

    def _record_source_status(
        self,
        source: object,
        result: ScanExecutionResult,
        target: str,
    ) -> None:
        status = getattr(source, "last_status", None)
        if status in {"timeout", "failed", "malformed"}:
            self._issue(
                result,
                getattr(source, "name", source.__class__.__name__),
                ScanStage.RECON,
                f"Recon source execution status: {status}",
                target=target,
            )

    def _collect_http(
        self,
        request: ScanRequest,
        result: ScanExecutionResult,
        scope: ScopeManager,
        target_url: str,
    ) -> dict[str, object]:
        self._stage(result, ScanStage.HTTP, StageState.RUNNING)
        responses: dict[str, object] = {}
        for url, supplied_request in request.supplied_requests.items():
            if is_in_scope(scope, url):
                result.requests[url] = supplied_request
            else:
                self._issue(result, "ScopeManager", ScanStage.HTTP,
                            "supplied request is outside scope", target=target_url, endpoint=url)
        for url, response in request.supplied_responses.items():
            if is_in_scope(scope, url):
                responses[url] = response
            else:
                self._issue(result, "ScopeManager", ScanStage.HTTP, "supplied response is outside scope", target=target_url, endpoint=url)
        if target_url in request.supplied_responses:
            responses[target_url] = request.supplied_responses[target_url]
        supplied_response_count = len(responses)

        if not request.active:
            self._stage(result, ScanStage.HTTP, StageState.COMPLETED if responses else StageState.SKIPPED)
            result.responses.update(responses)
            result.statistics.http_responses = len(result.responses)
            for _endpoint in responses:
                self._publish(RequestCompleted, result, stage=ScanStage.HTTP.value,
                              message="HTTP response available")
            return dict(result.responses)

        client = ScopedHttpEngine(
            self.http_engine,
            scope,
            request.authorization,
            active_enabled=request.active,
        )
        result.statistics.http_responses += supplied_response_count
        seen_urls = set(responses) | set(result.responses)
        for asset in result.assets:
            url = asset_url(asset.value, target_url)
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                outbound_request = HttpRequest(method="GET", url=url)
                response = client.send(outbound_request)
                responses[url] = response
                result.requests[url] = outbound_request
            except ScopeViolation as exc:
                self._issue(result, "ScopeManager", ScanStage.HTTP, str(exc), target=target_url, endpoint=url)
            except Exception as exc:
                self._issue(result, "HttpEngine", ScanStage.HTTP, str(exc), target=target_url, endpoint=url)
        result.statistics.http_requests += client.request_count
        result.responses.update(responses)
        self._merge_observations(result, client)
        for _endpoint in responses:
            self._publish(RequestCompleted, result, stage=ScanStage.HTTP.value,
                          message="HTTP response available")
        self._stage(
            result,
            ScanStage.HTTP,
            StageState.PARTIAL if result.errors else StageState.COMPLETED,
        )
        return dict(result.responses)

    def _run_scanners(
        self,
        request: ScanRequest,
        result: ScanExecutionResult,
        scope: ScopeManager,
        target_url: str,
    ) -> None:
        self._stage(result, ScanStage.SCANNERS, StageState.RUNNING)
        client = ScopedHttpEngine(
            self.http_engine,
            scope,
            request.authorization,
            active_enabled=True,
        )
        scanners = self.scanner_registry.get_all()
        if request.scanner_names is not None:
            allowed = set(request.scanner_names)
            scanners = [item for item in scanners if item.name in allowed]
        findings = []
        with self._scanner_lock:
            for scanner in scanners:
                if scanner.name.casefold() == "example" and not request.include_example_scanner:
                    continue
                if not getattr(scanner, "scope_aware", False):
                    self._issue(
                        result,
                        scanner.name,
                        ScanStage.SCANNERS,
                        "scanner skipped because it has no scoped execution adapter",
                        target=target_url,
                        level="warning",
                    )
                    continue
                if not is_in_scope(scope, target_url):
                    self._issue(result, "ScopeManager", ScanStage.SCANNERS, "scanner target is outside scope", target=target_url)
                    continue
                if getattr(scanner, "uses_http", False) and not hasattr(scanner, "http"):
                    self._issue(
                        result,
                        scanner.name,
                        ScanStage.SCANNERS,
                        "HTTP scanner has no injectable scoped client",
                        target=target_url,
                        level="warning",
                    )
                    continue
                had_http = hasattr(scanner, "http")
                previous_http = getattr(scanner, "http", None)
                if had_http:
                    scanner.http = client
                try:
                    findings.extend(scanner.run(result.scan.target))
                    result.statistics.scanners_run += 1
                except ScopeViolation as exc:
                    self._issue(result, scanner.name, ScanStage.SCANNERS, str(exc), target=target_url)
                except Exception as exc:
                    self._issue(result, scanner.name, ScanStage.SCANNERS, str(exc), target=target_url)
                finally:
                    if had_http:
                        scanner.http = previous_http
        result.statistics.http_requests += client.request_count
        self._merge_observations(result, client)
        existing_keys = {self._finding_key(item) for item in result.findings}
        for finding in findings:
            if not is_in_scope(scope, finding.target) or (
                finding.endpoint is not None
                and not is_in_scope(scope, finding.endpoint)
            ):
                self._issue(result, "ScopeManager", ScanStage.SCANNERS, "scanner finding target is outside scope", target=target_url, endpoint=finding.endpoint)
                continue
            key = self._finding_key(finding)
            if key in existing_keys:
                result.statistics.duplicates += 1
                continue
            try:
                self.evidence_service.record_legacy_finding(finding)
                result.findings.append(finding)
                existing_keys.add(key)
            except Exception as exc:
                self._issue(result, "EvidenceService", ScanStage.EVIDENCE, str(exc), target=target_url, endpoint=finding.endpoint)
        self._stage(result, ScanStage.SCANNERS, StageState.PARTIAL if result.errors else StageState.COMPLETED)

    def _run_analyzers(
        self,
        request: ScanRequest,
        result: ScanExecutionResult,
        scope: ScopeManager,
        responses: Mapping[str, object],
        target_url: str,
    ) -> None:
        self._stage(result, ScanStage.ANALYZERS, StageState.RUNNING)
        self._stage(result, ScanStage.VALIDATION, StageState.RUNNING)
        self._stage(result, ScanStage.EVIDENCE, StageState.RUNNING)
        analyzers = self.analyzer_registry.get_all()
        if request.analyzer_names is not None:
            allowed = set(request.analyzer_names)
            analyzers = [item for item in analyzers if item.name in allowed]
        for endpoint, response in responses.items():
            if not is_in_scope(scope, endpoint):
                continue
            for analyzer in analyzers:
                capabilities = getattr(analyzer, "capabilities", None)
                if ((getattr(capabilities, "mode", "passive") == "active"
                     or getattr(capabilities, "requires_authorization", False))
                        and (not request.active or not request.authorization.authorized)):
                    self._issue(result, analyzer.name, ScanStage.ANALYZERS,
                                "active analyzer requires explicit active mode and authorization",
                                target=target_url, endpoint=endpoint)
                    continue
                if (getattr(capabilities, "requires_request", False)
                        and endpoint not in result.requests):
                    self._issue(result, analyzer.name, ScanStage.ANALYZERS,
                                "analyzer skipped because request context is unavailable",
                                target=target_url, endpoint=endpoint, level="warning")
                    continue
                context = AnalysisContext(
                    response=response,
                    content=getattr(response, "text", None),
                    request_url=endpoint,
                    target=result.scan.target,
                    request=result.requests.get(endpoint),
                    options=request.analyzer_options.get(analyzer.name, {}),
                    # Do not copy arbitrary caller metadata or authorization
                    # references into Finding metadata or evidence context.
                    metadata={"scan_id": result.scan.id, "active_enabled": request.active},
                )
                try:
                    analysis = analyzer.run(context)
                    result.statistics.analyzers_run += 1
                    result.analyses.append(analysis)
                except Exception as exc:
                    self._issue(result, analyzer.name, ScanStage.ANALYZERS, str(exc), target=target_url, endpoint=endpoint)
                    continue
                validator = self.validators.get(analyzer.name)
                if validator is None:
                    decision = AnalysisValidation.informational(
                        metadata={"reason": "no validator configured"}
                    )

                    class _DecisionValidator:
                        def validate(self, _analysis, _context):
                            return decision

                    validator = _DecisionValidator()
                delegate = validator

                class _ScopeValidator:
                    @staticmethod
                    def _scope_decision(decision):
                        candidate = decision.candidate
                        if candidate is not None:
                            candidate_target = candidate.target or target_url
                            candidate_endpoint = candidate.endpoint or endpoint
                            if not is_in_scope(scope, candidate_target):
                                return AnalysisValidation.invalid(
                                    "validated Finding target is outside scope"
                                )
                            if not is_in_scope(scope, candidate_endpoint):
                                return AnalysisValidation.invalid(
                                    "validated Finding endpoint is outside scope"
                                )
                        return decision

                    def validate(self, analysis, analysis_context):
                        return self._scope_decision(
                            delegate.validate(analysis, analysis_context)
                        )

                    def validate_many(self, analysis, analysis_context):
                        validate_many = getattr(delegate, "validate_many", None)
                        decisions = (validate_many(analysis, analysis_context)
                                     if callable(validate_many)
                                     else [delegate.validate(analysis, analysis_context)])
                        return [self._scope_decision(item) for item in decisions]

                self._stage(result, ScanStage.VALIDATION, StageState.RUNNING)
                try:
                    process_many = getattr(self.finding_pipeline, "process_many", None)
                    processing_results = process_many(
                        analysis, context, _ScopeValidator()
                    ) if callable(process_many) else [self.finding_pipeline.process(
                        analysis, context, _ScopeValidator()
                    )]
                    for processing in processing_results:
                        result.statistics.analyses_validated += 1
                        if processing.status == FindingProcessingStatus.CREATED and processing.finding:
                            result.findings.append(processing.finding)
                            self._publish(FindingCreated, result, stage=ScanStage.VALIDATION.value,
                                          message=processing.finding.id)
                        elif processing.status == FindingProcessingStatus.DUPLICATE:
                            result.statistics.duplicates += 1
                        elif processing.status in {FindingProcessingStatus.VALIDATION_FAILED,
                                                  FindingProcessingStatus.INVALID}:
                            for error in processing.errors:
                                self._issue(result, analyzer.name, ScanStage.VALIDATION,
                                            error, target=target_url, endpoint=endpoint)
                except Exception as exc:
                    self._issue(result, analyzer.name, ScanStage.VALIDATION, str(exc), target=target_url, endpoint=endpoint)
        self._stage(result, ScanStage.ANALYZERS, StageState.PARTIAL if result.errors else StageState.COMPLETED)
        self._stage(result, ScanStage.VALIDATION, StageState.PARTIAL if result.errors else StageState.COMPLETED)
        self._stage(result, ScanStage.EVIDENCE, StageState.PARTIAL if result.errors else StageState.COMPLETED)

    @staticmethod
    def _deduplicate_assets(assets: list[Asset]) -> list[Asset]:
        result = []
        seen = set()
        for asset in assets:
            key = (asset.asset_type, asset.value.casefold())
            if key not in seen:
                seen.add(key)
                result.append(asset)
        return result

    @staticmethod
    def _merge_observations(
        result: ScanExecutionResult,
        client: ScopedHttpEngine,
    ) -> None:
        for request in client.request_log:
            result.requests.setdefault(request.full_url, request)
        for endpoint, response in client.response_log:
            result.responses.setdefault(endpoint, response)
        result.statistics.http_responses += len(client.response_log)

    @staticmethod
    def _finding_key(finding: Finding) -> tuple[str, ...]:
        return (
            finding.title.casefold(),
            finding.target.casefold(),
            (finding.endpoint or "").casefold(),
            (finding.parameter or "").casefold(),
            finding.evidence,
        )

    def _deduplicate_findings(
        self,
        findings: list[Finding],
        result: ScanExecutionResult,
    ) -> list[Finding]:
        unique = []
        seen: dict[tuple[str, ...], Finding] = {}
        for finding in findings:
            key = self._finding_key(finding)
            if key in seen:
                result.statistics.duplicates += 1
                canonical = seen[key]
                for evidence_id in finding.evidence_ids:
                    evidence = self.evidence_service.store.get(evidence_id)
                    if evidence is not None:
                        self.evidence_service.store.associate(evidence_id, canonical)
                continue
            seen[key] = finding
            unique.append(finding)
        return unique

    def _stage(
        self,
        result: ScanExecutionResult,
        stage: ScanStage,
        state: StageState,
    ) -> None:
        now = datetime.now(timezone.utc)
        record = next((item for item in result.stages if item.stage == stage), None)
        if record is None:
            record = StageRecord(stage=stage)
            result.stages.append(record)
        record.state = state
        if state == StageState.RUNNING and record.started_at is None:
            record.started_at = now
        if state not in {StageState.PENDING, StageState.RUNNING}:
            record.finished_at = now
        event_type = StageStarted if state == StageState.RUNNING else StageUpdated
        self._publish(event_type, result, stage=stage.value,
                      progress=round((list(ScanStage).index(stage) + (0.0 if state == StageState.RUNNING else 1.0)) / len(ScanStage), 3),
                      message=state.value)

    def _issue(
        self,
        result: ScanExecutionResult,
        component: str,
        stage: ScanStage,
        error: str,
        *,
        target: str | None = None,
        endpoint: str | None = None,
        level: str = "error",
    ) -> None:
        result.issues.append(
            ScanIssue(
                component=component,
                stage=stage,
                error=error,
                timestamp=datetime.now(timezone.utc),
                target=target,
                endpoint=endpoint,
                level=level,
            )
        )
        self._publish(ErrorOccurred, result, stage=stage.value,
                      message=f"{component}: {error}")

    def _publish(self, event_type: type, result: ScanExecutionResult, *,
                 stage: str | None = None, progress: float | None = None,
                 message: str | None = None) -> None:
        """Publish a redacted progress event; observers cannot affect the scan."""
        target = (result.security.target if result.security else str(result.scan.target.url))
        safe_target = self._event_redactor.redact_text(target)
        safe_message = self._event_redactor.redact_text(message) if message else None
        self.event_bus.publish(event_type(
            scan_id=result.scan.id, target=safe_target, stage=stage,
            progress=progress, discovered_assets=len(result.assets),
            findings_count=len(result.findings), errors_count=len(result.errors),
            message=safe_message,
        ))

    @staticmethod
    def _cancelled(request: ScanRequest) -> bool:
        return request.cancel_event is not None and request.cancel_event.is_set()

    def _finish(
        self,
        result: ScanExecutionResult,
        state: ScanState,
    ) -> ScanExecutionResult:
        result.state = state
        result.scan.status = state.value
        result.scan.finished_at = datetime.now(timezone.utc)
        result.statistics.findings = len(result.findings)
        result.statistics.evidence_records = len(result.evidence_ids) or sum(
            len(item.evidence_ids) for item in result.findings
        )
        result.statistics.errors = len(result.errors)
        result.statistics.warnings = len(result.warnings)
        if state == ScanState.CANCELLED:
            for stage in result.stages:
                if stage.state in {StageState.PENDING, StageState.RUNNING}:
                    stage.state = StageState.CANCELLED
                    stage.finished_at = datetime.now(timezone.utc)
            self._publish(ScanCancelled, result, progress=1.0, message=state.value)
        else:
            self._publish(ScanCompleted, result, progress=1.0, message=state.value)
        return result

    def close(self) -> None:
        """Close an internally owned HTTP engine; injected clients remain caller-owned."""
        if self._owns_http_engine:
            close = getattr(self.http_engine, "close", None)
            if callable(close):
                close()

    def tools_status(self, *, include_version: bool = True) -> list[dict[str, object]]:
        """Return optional tool status through the shared ToolRunner boundary."""
        return [
            {
                "name": item.name,
                "status": item.status,
                "installed": item.installed,
                "executable": item.executable,
                "version": item.version,
                "error": item.error,
            }
            for item in ToolCatalog(self.tool_runner).detect_all(include_version=include_version)
        ]

    def __enter__(self) -> "ApplicationService":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.close()
        return False
