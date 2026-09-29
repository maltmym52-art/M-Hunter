"""Headless-testable presentation controller over the shared application API."""

from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event, RLock
from typing import Any

from m_hunter.ai.models import AIAnalysisResult
from m_hunter.ai.service import AIAnalysisService
from m_hunter.application.models import ScanExecutionResult, ScanRequest
from m_hunter.application.service import ApplicationService
from m_hunter.evidence.redaction import EvidenceRedactor
from m_hunter.reporting.service import ReportService


class GUIController:
    """Presentation facade. All scans run through the injected application service."""

    PAGES = (
        "Dashboard", "New Scan", "Targets", "Scope", "Recon", "Scan Progress",
        "Findings", "Finding Details", "Evidence", "Reports", "AI Analyst",
        "Tools Status", "Settings",
    )

    def __init__(self, application_service: ApplicationService,
                 report_service: ReportService | None = None,
                 executor: ThreadPoolExecutor | None = None,
                 ai_analysis_service: AIAnalysisService | None = None) -> None:
        if not callable(getattr(application_service, "run", None)):
            raise TypeError("application_service must implement run(ScanRequest)")
        self.application_service = application_service
        self.report_service = report_service or ReportService()
        self.ai_analysis_service = ai_analysis_service
        self.ai_result: AIAnalysisResult | None = None
        self._executor = executor or ThreadPoolExecutor(max_workers=1, thread_name_prefix="m-hunter-gui")
        self._owns_executor = executor is None
        self._lock = RLock()
        self._cancel_event: Event | None = None
        self._future: Future[ScanExecutionResult] | None = None
        self.last_result: ScanExecutionResult | None = None
        self.redactor = EvidenceRedactor()
        self._progress_event = None
        self._tool_status: tuple[dict[str, Any], ...] | None = None
        self._tool_status_future = None
        event_bus = getattr(application_service, "event_bus", None)
        self._unsubscribe = (
            event_bus.subscribe(self._on_event)
            if callable(getattr(event_bus, "subscribe", None)) else None
        )

    def _on_event(self, event) -> None:
        """Retain the latest transport-neutral progress snapshot for the view."""
        with self._lock:
            self._progress_event = event

    def start_scan(self, request: ScanRequest) -> Future[ScanExecutionResult]:
        """Submit a request to ApplicationService; active policy remains there."""
        with self._lock:
            if self._future is not None and not self._future.done():
                raise RuntimeError("a scan is already running")
            request.cancel_event = Event()
            self._cancel_event = request.cancel_event
            self._future = self._executor.submit(self._run, request)
            return self._future

    def run_scan(self, request: ScanRequest) -> ScanExecutionResult:
        """Synchronous variant useful to embedding clients and headless tests."""
        with self._lock:
            request.cancel_event = request.cancel_event or Event()
            self._cancel_event = request.cancel_event
        return self._run(request)

    def _run(self, request: ScanRequest) -> ScanExecutionResult:
        result = self.application_service.run(request)
        with self._lock:
            self.last_result = result
        return result

    def cancel_scan(self) -> bool:
        """Request cooperative cancellation; ApplicationService honors checkpoints."""
        with self._lock:
            if self._future is None or self._future.done() or self._cancel_event is None:
                return False
            self._cancel_event.set()
            return True

    @property
    def scan_running(self) -> bool:
        with self._lock:
            return self._future is not None and not self._future.done()

    def report(self, format: str = "json") -> str:
        """Render the shared sanitized report representation of the last result."""
        if self.last_result is None:
            raise RuntimeError("no scan result is available")
        model = self.report_service.build(
            self.last_result, self.application_service.evidence_service
        )
        return self.report_service.render(model, format)

    def start_report(self, format: str = "json") -> Future[str]:
        """Render on the presentation executor so large reports never block Qt."""
        return self._executor.submit(self.report, format)

    def analyze_last_scan(self) -> AIAnalysisResult:
        """Request optional advisory analysis, never part of scan execution."""
        if self.last_result is None:
            raise RuntimeError("no scan result is available")
        if self.ai_analysis_service is None:
            self.ai_result = AIAnalysisResult("unavailable", error="no AI provider configured")
        else:
            try:
                self.ai_result = self.ai_analysis_service.analyze(
                    self.last_result, self.application_service.evidence_service
                )
            except Exception as exc:
                # AI is optional, so preparation/provider failures cannot modify
                # or invalidate the completed scan.
                self.ai_result = AIAnalysisResult("failed", error=self.redactor.redact_text(str(exc)))
        return self.ai_result

    def start_ai_analysis(self) -> Future[AIAnalysisResult]:
        """Run optional provider work off the GUI thread."""
        return self._executor.submit(self.analyze_last_scan)

    def view_data(self, *, non_blocking_tools: bool = False) -> dict[str, Any]:
        """Return presentation-safe page data; never expose raw Evidence objects."""
        if self.last_result is None:
            return {"pages": self.PAGES, "scan": None, "findings": (), "evidence": (),
                    "progress": self._progress_data(), "ai_analysis": None,
                    "tools": self._get_tool_status(non_blocking=non_blocking_tools)}
        model = self.report_service.build(
            self.last_result, self.application_service.evidence_service
        )
        payload = model.to_dict()
        evidence = self.application_service.evidence_service.store.export(
            self.last_result.evidence_ids
        )
        return {
            "pages": self.PAGES,
            "scan": payload["scan"],
            "target": payload["target"],
            "scope": payload["scope"],
            "assets": tuple(payload["assets"]),
            "findings": tuple(payload["findings"]),
            "evidence": tuple(evidence),
            "errors": tuple(payload["errors"]),
            "statistics": payload["statistics"],
            "progress": self._progress_data(),
            "ai_analysis": self._ai_data(),
            "tools": self._get_tool_status(non_blocking=non_blocking_tools),
        }

    def _get_tool_status(self, *, non_blocking: bool = False) -> tuple[dict[str, Any], ...]:
        if self._tool_status is None:
            if non_blocking:
                if self._tool_status_future is None:
                    self._tool_status_future = self._executor.submit(self._load_tool_status)
                elif self._tool_status_future.done():
                    self._tool_status = self._tool_status_future.result()
            else:
                self._tool_status = self._load_tool_status()
            if self._tool_status is None:
                return ({"name": "External tools", "status": "checking"},)
        return self._tool_status

    def _load_tool_status(self) -> tuple[dict[str, Any], ...]:
        getter = getattr(self.application_service, "tools_status", None)
        if not callable(getter):
            return ({"name": "external tools", "status": "managed by ApplicationService"},)
        try:
            values = getter(include_version=True)
            return tuple({
                key: self.redactor.redact_text(str(value)) if value is not None else None
                for key, value in item.items()
            } for item in values)
        except Exception as exc:
            return ({"name": "external tools", "status": "unavailable",
                     "error": self.redactor.redact_text(str(exc))},)

    def _ai_data(self) -> dict[str, Any] | None:
        if self.ai_result is None:
            return None
        return {
            "status": self.ai_result.status,
            "error": self.redactor.redact_text(self.ai_result.error or "") or None,
            "notes": tuple({
                "kind": note.kind,
                "text": self.redactor.redact_text(note.text),
                "finding_ids": note.finding_ids,
                "created_at": note.created_at.isoformat(),
            } for note in self.ai_result.notes),
        }

    def _progress_data(self) -> dict[str, Any] | None:
        event = self._progress_event
        if event is None:
            return None
        return {
            "stage": event.stage,
            "progress": event.progress,
            "target": self.redactor.redact_text(event.target),
            "discovered_assets": event.discovered_assets,
            "findings_count": event.findings_count,
            "errors_count": event.errors_count,
            "message": self.redactor.redact_text(event.message or ""),
        }

    def close(self) -> None:
        """Release only resources owned by this presentation controller."""
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        if self._owns_executor:
            self._executor.shutdown(wait=False, cancel_futures=False)
