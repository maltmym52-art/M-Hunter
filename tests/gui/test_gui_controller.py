"""GUI/controller security and shared-service contract tests."""

from threading import Event

from typer.testing import CliRunner

from m_hunter.ai import AIAnalysisService, MockAIProvider
from m_hunter.application import (ApplicationService, AuthorizationGrant,
                                  ScanExecutionResult, ScanRequest, ScanState)
from m_hunter.application.factory import create_default_application_service
from m_hunter.application.scope import ScopeViolation
from m_hunter.cli.app import app, create_cli_context
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.core.scan import Scan
from m_hunter.core.target import Target
from m_hunter.evidence.service import EvidenceService
from m_hunter.gui.controller import GUIController
from m_hunter.reporting.service import ReportService


TARGET = "https://example.test/"
RAW_SECRET = "Bearer gui-raw-secret"


class _PresentationService:
    def __init__(self):
        self.delegate = ApplicationService()
        self.event_bus = self.delegate.event_bus
        self.evidence_service = EvidenceService()
        self.requests = []
        self.tool_status_calls = 0

    def tools_status(self, *, include_version=True):
        self.tool_status_calls += 1
        return [{"name": "nmap", "status": "missing", "installed": False,
                 "version": None, "executable": None, "error": None}]

    def run(self, request):
        self.requests.append(request)
        result = self.delegate.run(request)
        finding = Finding("Safe title", "Low", "High", TARGET,
                          description=RAW_SECRET, evidence=RAW_SECRET)
        response = HttpResponse(200, TARGET, {"Authorization": RAW_SECRET}, RAW_SECRET.encode(),
                                {"session": "raw-cookie"}, 0.01, len(RAW_SECRET))
        record = self.evidence_service.record(
            __import__("m_hunter.analyzers.context", fromlist=["AnalysisContext"]).AnalysisContext(
                response=response, request_url=TARGET, target=TARGET),
            finding, evidence=RAW_SECRET,
        )
        result.findings.append(finding)
        result.evidence_ids.append(record.id)
        return result


def test_gui_has_headless_pages_and_only_uses_application_service_contract():
    service = _PresentationService()
    controller = GUIController(service)  # type: ignore[arg-type]
    result = controller.run_scan(ScanRequest(TARGET, run_scanners=False))
    assert result.state == ScanState.COMPLETED
    assert "Dashboard" in controller.view_data()["pages"]
    assert "New Scan" in controller.view_data()["pages"]
    assert controller.view_data()["progress"]["progress"] == 1.0
    assert controller.view_data()["progress"]["discovered_assets"] >= 1
    assert controller.view_data()["tools"][0]["status"] == "missing"
    assert service.tool_status_calls == 1  # cached; GUI never probes binaries itself
    assert service.requests[0].target == TARGET
    controller.close()


def test_gui_displays_only_sanitized_data_and_shared_report():
    service = _PresentationService()
    controller = GUIController(service)  # type: ignore[arg-type]
    controller.run_scan(ScanRequest(TARGET, run_scanners=False))
    serialized = str(controller.view_data()) + controller.report("html")
    assert RAW_SECRET not in serialized
    assert "raw-cookie" not in serialized
    controller.close()


def test_scan_ai_note_and_report_preserve_validated_finding():
    service = _PresentationService()
    provider = MockAIProvider({"notes": [{"kind": "analyst_note",
                                           "text": "Review the sanitized evidence."}]})
    controller = GUIController(service, ai_analysis_service=AIAnalysisService(provider))  # type: ignore[arg-type]
    result = controller.run_scan(ScanRequest(TARGET, run_scanners=False))
    original = [(item.id, item.title, item.severity, item.confidence, item.evidence)
                for item in result.findings]
    note_result = controller.analyze_last_scan()
    report = controller.report("json")
    view = controller.view_data()
    assert note_result.notes[0].kind == "analyst_note"
    assert "Review the sanitized evidence." in str(view["ai_analysis"])
    assert all(item[0] in report for item in original)
    assert [(item.id, item.title, item.severity, item.confidence, item.evidence)
            for item in result.findings] == original
    controller.close()


def test_cli_and_gui_share_the_same_scan_request_service_contract():
    service = create_default_application_service(external_tools=False)
    controller = GUIController(service)
    controller.run_scan(ScanRequest(TARGET, run_scanners=False))
    runner = CliRunner()
    ctx = create_cli_context(application_service_factory=lambda **_kwargs: service)
    cli_result = runner.invoke(app, ["scan", TARGET, "--no-recon"], obj=ctx)
    assert cli_result.exit_code == 0
    assert isinstance(service.run(ScanRequest(TARGET, run_scanners=False)), ScanExecutionResult)
    assert controller.last_result is not None
    controller.close()


def test_active_gui_request_is_not_allowed_to_bypass_application_scope():
    calls = []

    class RejectingScope:
        def is_allowed(self, _url):
            return False

    class HTTP:
        def request(self, *_args, **_kwargs):
            calls.append(True)
            raise AssertionError("out-of-scope GUI scan attempted HTTP")

    service = ApplicationService(http_engine=HTTP(), scope_manager=RejectingScope())
    controller = GUIController(service)  # type: ignore[arg-type]
    result = controller.run_scan(ScanRequest(TARGET, active=True,
        authorization=AuthorizationGrant(True, "ticket")))
    assert result.state == ScanState.FAILED
    assert calls == []
    controller.close()


def test_active_gui_scan_without_authorization_is_rejected_by_application_service():
    service = ApplicationService()
    controller = GUIController(service)
    result = controller.run_scan(ScanRequest(TARGET, active=True))
    assert result.state == ScanState.FAILED
    assert any("explicit authorization" in issue.error for issue in result.errors)
    controller.close()


def test_cancellation_is_cooperative_and_keeps_result_state_consistent():
    started = Event()

    class BlockingService:
        evidence_service = EvidenceService()

        def run(self, request):
            started.set()
            request.cancel_event.wait(2)
            result = ScanExecutionResult(Scan(Target(request.target)), state=ScanState.CANCELLED)
            result.scan.status = "cancelled"
            return result

    controller = GUIController(BlockingService())  # type: ignore[arg-type]
    future = controller.start_scan(ScanRequest(TARGET))
    assert started.wait(1)
    assert controller.cancel_scan()
    result = future.result(timeout=2)
    assert result.state == ScanState.CANCELLED
    assert controller.last_result is result
    controller.close()
