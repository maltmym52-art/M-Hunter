"""Local-only end-to-end release smoke flow using synthetic HTTP observations."""

import json

import pytest

from m_hunter.ai import AIAnalysisService, MockAIProvider
from typer.testing import CliRunner

from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.analyzers.security_headers_baseline import SecurityHeadersBaselineAnalyzer
from m_hunter.analyzers.http_cookie_security import HttpCookieSecurityAnalyzer
from m_hunter.analyzers.cache_control_security import CacheControlSecurityAnalyzer
from m_hunter.analyzers.xss import XSSAnalyzer
from m_hunter.application import ApplicationService, ScanRequest
from m_hunter.cli.app import app, create_cli_context
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.evidence.service import EvidenceService
from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import DiscoverySource
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL
from m_hunter.reporting import ReportService
from m_hunter.scanners.registry import ScannerRegistry
from m_hunter.validation.analysis import AnalysisValidation, FindingCandidate


TARGET = "https://m-hunter.test/"
ENDPOINT = "https://m-hunter.test/fixture"
MARKER = "MHUNTER_LOCAL_XSS_MARKER"
FIXTURE_SECRET = "fixture-only-secret-token"


class LocalFixtureSource(DiscoverySource):
    """Passive in-memory source; never uses DNS, HTTP, or a subprocess."""

    name = "local-fixture"
    passive = True

    def discover(self, _target: str) -> list[Asset]:
        return [Asset(ENDPOINT, "endpoint", source=self.name)]


class FixtureReflectionValidator:
    """Validate only the synthetic marker supplied by this local test."""

    def validate(self, analysis, context):
        if not analysis.data.reflected:
            return AnalysisValidation.informational()
        return AnalysisValidation.finding(FindingCandidate(
            title="Local fixture reflected marker (not an exploitability claim)",
            severity="Low", confidence="Low", target=context.request_url,
            endpoint=context.request_url, parameter="q",
            description="Synthetic response contains the test marker for pipeline verification.",
            evidence=f"Synthetic marker reflected: {analysis.data.marker}",
            remediation="This local fixture is test data; no remediation is asserted.",
            metadata={"test_fixture": True},
        ))


def fixture_response() -> HttpResponse:
    body = f"<html><script>const x = '{MARKER}';</script></html>".encode()
    return HttpResponse(
        status_code=200,
        url=ENDPOINT,
        headers={
            "Content-Type": "text/html",
            "Cache-Control": "public, max-age=120",
            "Authorization": f"Bearer {FIXTURE_SECRET}",
        },
        content=body,
        cookies={"sessionid": FIXTURE_SECRET},
        response_time=0.0,
        content_length=len(body),
        repeated_headers={"Set-Cookie": [f"sessionid={FIXTURE_SECRET}; Path=/"]},
    )


def make_local_service() -> ApplicationService:
    analyzers = AnalyzerRegistry()
    for analyzer in (
        SecurityHeadersBaselineAnalyzer(), HttpCookieSecurityAnalyzer(),
        CacheControlSecurityAnalyzer(), XSSAnalyzer(),
    ):
        analyzers.register(analyzer)
    scope = ScopeManager(URL(TARGET), allowed_hosts={"m-hunter.test"})
    return ApplicationService(
        analyzer_registry=analyzers,
        validators={"xss": FixtureReflectionValidator()},
        evidence_service=EvidenceService(),
        recon_sources=[LocalFixtureSource()],
        scanner_registry=ScannerRegistry(),
        scope_manager=scope,
    )


def run_fixture_scan():
    service = make_local_service()
    response = fixture_response()
    request = HttpRequest("GET", ENDPOINT, params={"q": MARKER, "token": FIXTURE_SECRET})
    result = service.run(ScanRequest(
        TARGET,
        active=False,
        recon=True,
        run_scanners=False,
        supplied_requests={ENDPOINT: request},
        supplied_responses={ENDPOINT: response},
        analyzer_options={
            "xss": {"marker": MARKER},
            "cache_control_security": {"sensitive_content": True},
        },
    ))
    return service, result


def test_local_fixture_runs_full_passive_pipeline_and_all_report_formats():
    service, result = run_fixture_scan()
    assert result.state.value == "completed"
    assert any(asset.value == ENDPOINT for asset in result.assets)
    assert result.analyses
    assert result.findings
    assert all(finding.evidence_ids for finding in result.findings)
    assert any("reflected marker" in finding.title.lower() for finding in result.findings)
    assert any("Cookie" in finding.title for finding in result.findings)
    assert any("cacheable" in finding.title.lower() for finding in result.findings)
    report_service = ReportService()
    report_model = report_service.build(result, service.evidence_service)
    rendered = {
        format_name: report_service.render(report_model, format_name)
        for format_name in ("json", "markdown", "html")
    }
    assert json.loads(rendered["json"])["findings"]
    assert "Findings" in rendered["markdown"]
    assert "<html" in rendered["html"].lower()
    assert all(FIXTURE_SECRET not in text for text in rendered.values())
    assert result.statistics.http_requests == 0
    service.close()


def test_local_fixture_ai_smoke_uses_sanitized_evidence_and_cannot_change_findings():
    service, result = run_fixture_scan()
    provider = MockAIProvider({"notes": [{
        "kind": "analyst_note", "text": "Review the synthetic fixture observations.",
        "finding_ids": [finding.id for finding in result.findings],
        "severity": "Critical", "confidence": "Certain",
    }]})
    ai = AIAnalysisService(provider)
    before = [(item.id, item.title, item.severity, item.confidence, item.evidence)
              for item in result.findings]
    note = ai.analyze(result, service.evidence_service)
    assert note.status == "completed"
    assert note.notes and note.notes[0].kind == "analyst_note"
    assert all(FIXTURE_SECRET not in str(provider_request)
               for provider_request in provider.requests)
    assert [(item.id, item.title, item.severity, item.confidence, item.evidence)
            for item in result.findings] == before
    assert len(result.findings) == len(ReportService().build(
        result, service.evidence_service
    ).findings)
    service.close()


@pytest.mark.parametrize("format_name,suffix", [
    ("json", ".json"), ("markdown", ".md"), ("html", ".html"),
])
def test_cli_report_smoke_for_all_formats(tmp_path, format_name, suffix):
    service, result = run_fixture_scan()
    reports = ReportService()
    input_path = tmp_path / "scan.json"
    output_path = tmp_path / f"report{suffix}"
    reports.write(reports.build(result, service.evidence_service), "json", input_path)
    cli = CliRunner().invoke(app, [
        "report", str(input_path), "--format", format_name,
        "--output", str(output_path),
    ])
    assert cli.exit_code == 0, cli.stdout
    rendered = output_path.read_text(encoding="utf-8")
    assert rendered
    assert FIXTURE_SECRET not in rendered
    service.close()


def test_cli_recon_uses_a_fake_local_source():
    runner = CliRunner()

    def service_factory(**kwargs):
        return ApplicationService(
            recon_sources=[LocalFixtureSource()],
            scanner_registry=ScannerRegistry(),
            scope_manager=kwargs["scope_manager"],
        )

    context = create_cli_context(application_service_factory=service_factory)
    result = runner.invoke(app, ["recon", TARGET, "--no-external-tools"], obj=context)
    assert result.exit_code == 0, result.stdout
    assert "local-fixture" in result.stdout
    assert ENDPOINT in result.stdout


def test_cli_passive_scan_does_not_make_network_requests():
    calls = []

    class HTTP:
        def request(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("passive scan must not issue HTTP")

    def service_factory(**kwargs):
        return ApplicationService(http_engine=HTTP(), scope_manager=kwargs["scope_manager"])

    context = create_cli_context(application_service_factory=service_factory)
    result = CliRunner().invoke(app, ["scan", TARGET, "--passive", "--no-recon"], obj=context)
    assert result.exit_code == 0, result.stdout
    assert "completed" in result.stdout
    assert calls == []
