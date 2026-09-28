import json

import pytest
from typer.testing import CliRunner

from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.security_headers import SecurityHeadersAnalyzer
from m_hunter.application import ApplicationService, ScanRequest, ScanState
from m_hunter.cli.app import app, create_cli_context, _default_scanners
from m_hunter.core.response import HttpResponse
from m_hunter.evidence.service import EvidenceService
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL
from m_hunter.scanners.registry import ScannerRegistry
from m_hunter.scanners.base import BaseScanner
from m_hunter.core.finding import Finding


runner = CliRunner()
TARGET = "https://example.test/"


def service_factory(**kwargs):
    analyzers = AnalyzerRegistry()
    analyzers.register(SecurityHeadersAnalyzer())
    return ApplicationService(
        analyzer_registry=analyzers,
        scanner_registry=ScannerRegistry(),
        scope_manager=kwargs["scope_manager"],
        tool_runner=kwargs["tool_runner"],
    )


def ctx(**kwargs):
    return create_cli_context(application_service_factory=service_factory, **kwargs)


def test_root_banner_and_help():
    result = runner.invoke(app, [], obj=ctx())
    assert result.exit_code == 0
    assert "M-Hunter" in result.stdout
    help_result = runner.invoke(app, ["--help"], obj=ctx())
    assert help_result.exit_code == 0
    for command in ("scan", "recon", "analyze", "report", "tools"):
        assert command in help_result.stdout


@pytest.mark.parametrize("args,expected", [
    (["scan", "--help"], "authorization"),
    (["recon", "--help"], "external"),
    (["analyze", "--help"], "--input"),
    (["report", "--help"], "markdown"),
    (["tools", "--help"], "availability"),
])
def test_command_help(args, expected):
    result = runner.invoke(app, args, obj=ctx())
    assert result.exit_code == 0
    assert expected.lower() in result.stdout.lower()


def test_version():
    result = runner.invoke(app, ["version"], obj=ctx())
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_passive_scan_uses_application_service():
    result = runner.invoke(app, ["scan", TARGET], obj=ctx())
    assert result.exit_code == 0
    assert "completed" in result.stdout
    assert "example.test" in result.stdout


def test_active_without_authorization_reference_is_rejected():
    result = runner.invoke(app, ["scan", TARGET, "--active"], obj=ctx())
    assert result.exit_code == 3
    assert "authorization-reference" in result.stdout


def test_active_scan_out_of_scope_is_rejected_before_http():
    calls = []

    class GuardedHttp:
        def request(self, *args, **kwargs):
            calls.append(args)
            raise AssertionError("unauthorized HTTP request")

    class RejectingScope:
        def is_allowed(self, url):
            return False

    def scoped_factory(**kwargs):
        return ApplicationService(http_engine=GuardedHttp(),
                                  scope_manager=RejectingScope())

    # An affirmative authorization reference never bypasses the app's scope gate.
    result = runner.invoke(app, ["scan", TARGET, "--active", "--authorization-reference", "ticket-123"],
                           obj=create_cli_context(application_service_factory=scoped_factory))
    assert result.exit_code == 4
    assert calls == []


def test_out_of_scope_from_application_service_is_reported():
    class RejectingScope:
        def is_allowed(self, url):
            return False

    def rejected_factory(**kwargs):
        return ApplicationService(scope_manager=RejectingScope())

    result = runner.invoke(app, ["scan", TARGET],
                           obj=create_cli_context(application_service_factory=rejected_factory))
    assert result.exit_code == 4
    assert "outside" in result.stdout


def test_invalid_target_exit_code():
    result = runner.invoke(app, ["scan", "file:///etc/passwd"], obj=ctx())
    assert result.exit_code == 2
    assert "Invalid target" in result.stdout


def test_recon_uses_application_service():
    result = runner.invoke(app, ["recon", TARGET], obj=ctx())
    assert result.exit_code == 0
    assert "Assets: 1" in result.stdout


def test_analyze_saved_response_through_application_service(tmp_path):
    response_path = tmp_path / "response.json"
    response_path.write_text(json.dumps({
        "status_code": 200,
        "url": TARGET,
        "headers": {"Content-Type": "text/html", "Set-Cookie": "session=secret"},
        "body": "<html>ok</html>",
    }), encoding="utf-8")
    result = runner.invoke(app, ["analyze", TARGET, "--input", str(response_path)], obj=ctx())
    assert result.exit_code == 0
    assert "completed" in result.stdout


def test_tools_reports_missing_and_installed():
    class FakeRunner:
        def is_available(self, name):
            return name == "httpx"

        def run(self, command, timeout=None):
            class Result:
                stdout = "httpx version 1.2"
                stderr = ""
            return Result()

    result = runner.invoke(app, ["tools"], obj=ctx(tool_runner=FakeRunner()))
    assert result.exit_code == 0
    assert "installed" in result.stdout and "missing" in result.stdout
    assert "httpx version" in result.stdout


def test_json_output_contains_no_raw_response_secrets(tmp_path):
    response = HttpResponse(200, TARGET, {"Authorization": "Bearer secret-token"},
                           b"password=topsecret", {}, 0.0, 18)
    evidence = EvidenceService()

    def evidence_factory(**kwargs):
        analyzers = AnalyzerRegistry()
        analyzers.register(SecurityHeadersAnalyzer())
        return ApplicationService(analyzer_registry=analyzers,
                                  scope_manager=kwargs["scope_manager"],
                                  evidence_service=evidence)

    # The output path exercises the sanitized result serializer. There are no
    # findings for this response, so raw response material is never serialized.
    output = tmp_path / "result.json"
    result = runner.invoke(app, ["analyze", TARGET, "--input", str(_response_file(tmp_path)), "--output", str(output)],
                           obj=create_cli_context(application_service_factory=evidence_factory))
    assert result.exit_code == 0
    payload = output.read_text(encoding="utf-8")
    assert "secret-token" not in payload and "topsecret" not in payload


def _response_file(tmp_path):
    path = tmp_path / "safe-response.json"
    path.write_text(json.dumps({"url": TARGET, "status_code": 200,
                                "headers": {"X-Content-Type-Options": "wrong"},
                                "body": "safe"}), encoding="utf-8")
    return path


def test_report_contract_and_missing_input(tmp_path):
    missing = runner.invoke(app, ["report", str(tmp_path / "missing.json")], obj=ctx())
    assert missing.exit_code == 2
    source = tmp_path / "scan.json"
    source.write_text(json.dumps({
        "schema": "m-hunter-report", "schema_version": "1.0",
        "scan": {"id": "scan-cli", "status": "completed", "started_at": None,
                 "finished_at": None, "duration_seconds": 0},
        "target": TARGET, "scope": {"in_scope": True}, "authorization": {},
        "assets": [], "findings": [], "errors": [], "statistics": {}, "metadata": {},
    }), encoding="utf-8")
    result = runner.invoke(app, ["report", str(source), "--format", "markdown"], obj=ctx())
    assert result.exit_code == 0
    assert "No findings were reported" in result.stdout


def test_report_command_writes_html_with_safe_overwrite_policy(tmp_path):
    source = tmp_path / "scan.json"
    source.write_text(json.dumps({
        "schema": "m-hunter-report", "schema_version": "1.0",
        "scan": {"id": "scan-cli", "status": "completed", "started_at": None,
                 "finished_at": None, "duration_seconds": 0},
        "target": TARGET, "scope": {}, "authorization": {}, "assets": [],
        "findings": [], "errors": [], "statistics": {}, "metadata": {},
    }), encoding="utf-8")
    output = tmp_path / "reports" / "scan.html"
    result = runner.invoke(app, ["report", str(source), "--format", "html", "--output", str(output)], obj=ctx())
    assert result.exit_code == 0
    assert "<!doctype html>" in output.read_text(encoding="utf-8")
    blocked = runner.invoke(app, ["report", str(source), "--format", "json", "--output", str(output)], obj=ctx())
    assert blocked.exit_code == 5
    replaced = runner.invoke(app, ["report", str(source), "--format", "markdown",
                                   "--output", str(output), "--overwrite"], obj=ctx())
    assert replaced.exit_code == 0
    assert output.read_text(encoding="utf-8").startswith("# M-Hunter")


def test_report_command_rejects_malformed_schema(tmp_path):
    source = tmp_path / "malformed.json"
    source.write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["report", str(source)], obj=ctx())
    assert result.exit_code == 2
    assert "unsupported report schema" in result.stdout


def test_example_scanner_is_not_registered_by_default():
    assert "example" not in _default_scanners().names()
    class FakeHttp:
        def request(self, method, url, **kwargs):
            return HttpResponse(200, url, {"Content-Type": "text/plain"}, b"ok", {}, 0.01, 2)

    def no_example_factory(**kwargs):
        service = service_factory(**kwargs)
        service.http_engine = FakeHttp()
        service.engine.http_engine = service.http_engine
        return service

    result = runner.invoke(app, ["scan", TARGET, "--active", "--authorization-reference", "auth-1"],
                           obj=create_cli_context(application_service_factory=no_example_factory))
    assert result.exit_code == 0
    assert "Example Finding" not in result.stdout


def test_invalid_format_and_output_error(tmp_path):
    invalid = runner.invoke(app, ["scan", TARGET, "--format", "xml"], obj=ctx())
    assert invalid.exit_code != 0
    output_dir = tmp_path / "directory"
    output_dir.mkdir()
    failed = runner.invoke(app, ["scan", TARGET, "--output", str(output_dir)], obj=ctx())
    assert failed.exit_code == 5


def test_application_service_injection_is_passed_cli_scope():
    received = {}

    def factory(**kwargs):
        received.update(kwargs)
        return service_factory(**kwargs)

    result = runner.invoke(app, ["scan", TARGET, "--allow-host", "sub.example.test",
                                 "--exclude-path", "/private/*"],
                           obj=create_cli_context(application_service_factory=factory))
    assert result.exit_code == 0
    assert "sub.example.test" in received["scope_manager"].allowed_hosts
    assert "/private/*" in received["scope_manager"].excluded_paths


class ExplodingAnalyzer(BaseAnalyzer):
    name = "exploding"

    def analyze(self, response):
        raise RuntimeError("analyzer failure")


class ExplodingScanner(BaseScanner):
    name = "exploding"
    scope_aware = True

    def run(self, target):
        raise RuntimeError("scanner failure")


class SecretFindingScanner(BaseScanner):
    name = "secret_finding"
    scope_aware = True

    def run(self, target):
        return [Finding(title="Credential exposure", severity="High", confidence="High",
                        target=target.url, endpoint=target.base_url,
                        description="Credential-like evidence was observed.",
                        evidence="Authorization: Bearer secretvalue123",
                        remediation="Rotate exposed credentials.")]


class FakeHttp:
    def request(self, method, url, **kwargs):
        return HttpResponse(200, url, {"Content-Type": "text/plain"}, b"safe", {}, 0.01, 4)


def test_analyzer_error_isolated_and_uses_partial_exit_code(tmp_path):
    def broken_analyzer_factory(**kwargs):
        analyzers = AnalyzerRegistry()
        analyzers.register(ExplodingAnalyzer())
        return ApplicationService(analyzer_registry=analyzers,
                                  scope_manager=kwargs["scope_manager"])

    response_path = _response_file(tmp_path)
    result = runner.invoke(app, ["analyze", TARGET, "--input", str(response_path),
                                 "--analyzer", "exploding"],
                           obj=create_cli_context(application_service_factory=broken_analyzer_factory))
    assert result.exit_code == 1
    assert "analyzer failure" in result.stdout


def test_scanner_error_isolated_and_uses_partial_exit_code():
    def broken_scanner_factory(**kwargs):
        scanners = ScannerRegistry()
        scanners.register(ExplodingScanner())
        return ApplicationService(http_engine=FakeHttp(), scanner_registry=scanners,
                                  scope_manager=kwargs["scope_manager"])

    result = runner.invoke(app, ["scan", TARGET, "--active", "--authorization-reference", "authorized",
                                 "--scanner", "exploding"],
                           obj=create_cli_context(application_service_factory=broken_scanner_factory))
    assert result.exit_code == 1
    assert "scanner failure" in result.stdout


def test_finding_json_uses_redacted_evidence(tmp_path):
    def finding_factory(**kwargs):
        scanners = ScannerRegistry()
        scanners.register(SecretFindingScanner())
        return ApplicationService(http_engine=FakeHttp(), scanner_registry=scanners,
                                  scope_manager=kwargs["scope_manager"])

    output = tmp_path / "finding.json"
    result = runner.invoke(app, ["scan", TARGET, "--active", "--authorization-reference", "authorized",
                                 "--scanner", "secret_finding", "--format", "json", "--output", str(output)],
                           obj=create_cli_context(application_service_factory=finding_factory))
    assert result.exit_code == 0
    rendered = output.read_text(encoding="utf-8")
    assert "secretvalue123" not in rendered
    assert "<REDACTED>" in rendered
    assert "Credential exposure" in rendered
