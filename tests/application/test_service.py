from threading import Event

from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.application import (
    ApplicationService,
    AuthorizationGrant,
    ScanRequest,
    ScanStage,
    ScanState,
    StageState,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import DiscoveryEngine, DiscoverySource
from m_hunter.recon.pipeline import ReconPipeline
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL
from m_hunter.scanners.base import BaseScanner
from m_hunter.scanners.example import ExampleScanner
from m_hunter.scanners.security_headers import SecurityHeadersScanner
from m_hunter.scanners.registry import ScannerRegistry
from m_hunter.validation.analysis import AnalysisValidation, FindingCandidate


TARGET = "https://example.test/"


def make_response(url=TARGET, body=b"verified marker"):
    return HttpResponse(
        200, url, {"Content-Type": "text/plain", "X-Observed": "yes"}, body,
        {"sid": "private-cookie"}, 0.01, len(body),
    )


class FakeHttp:
    def __init__(self, response=None, error=None):
        self.response_value = response or make_response()
        self.error = error
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.error:
            raise self.error
        return self.response_value


class MarkerAnalyzer(BaseAnalyzer):
    name = "marker"

    def analyze(self, response):
        return {"evidence": response.text, "status": response.status_code}


class BrokenAnalyzer(BaseAnalyzer):
    name = "broken_analyzer"

    def analyze(self, response):
        raise RuntimeError("analyzer exploded")


class MarkerValidator:
    def validate(self, analysis, context):
        return AnalysisValidation.finding(
            FindingCandidate(
                title="Observed marker", severity="Medium", confidence="High",
                target=TARGET, endpoint=context.request_url,
                description="A marker was observed in the response.",
                evidence=analysis.data["evidence"], remediation="Review behavior.",
                metadata={"rule": "marker"},
            )
        )


class BrokenValidator:
    def validate(self, analysis, context):
        raise RuntimeError("validator failed")


class StaticSource(DiscoverySource):
    name = "static-test"
    passive = True

    def __init__(self, assets=None, error=None):
        self.assets = list(assets or [])
        self.error = error

    def discover(self, target):
        if self.error:
            raise self.error
        return list(self.assets)


class OptionalSource(StaticSource):
    name = "subfinder"


class FakeToolRunner:
    def __init__(self, available=False):
        self.available = available

    def is_available(self, name):
        return self.available

    def run(self, command, **kwargs):
        return command


class StaticScanner(BaseScanner):
    name = "static_scanner"
    scope_aware = True

    def __init__(self, findings=None, error=None):
        self.findings = list(findings or [])
        self.error = error
        self.calls = 0

    def run(self, target):
        self.calls += 1
        if self.error:
            raise self.error
        return list(self.findings)


class UnawareScanner(StaticScanner):
    name = "unaware"
    scope_aware = False


def analyzer_registry(*analyzers):
    registry = AnalyzerRegistry()
    for analyzer in analyzers:
        registry.register(analyzer)
    return registry


def app(**kwargs):
    kwargs.setdefault("http_engine", FakeHttp())
    kwargs.setdefault("tool_runner", FakeToolRunner())
    return ApplicationService(**kwargs)


def authorized(**kwargs):
    return ScanRequest(
        target=TARGET,
        active=True,
        authorization=AuthorizationGrant(True, reference="engagement-42"),
        **kwargs,
    )


def test_end_to_end_target_scope_http_analysis_validation_evidence_finding():
    http = FakeHttp()
    service = app(
        http_engine=http,
        analyzer_registry=analyzer_registry(MarkerAnalyzer()),
        validators={"marker": MarkerValidator()},
    )
    result = service.run(authorized())

    assert result.state == ScanState.COMPLETED
    assert [call[1] for call in http.calls] == [TARGET]
    assert http.calls[0][2]["follow_redirects"] is False
    assert len(result.analyses) == len(result.findings) == 1
    finding = result.findings[0]
    assert finding.title == "Observed marker" and finding.evidence_ids
    assert result.evidence_ids == finding.evidence_ids
    evidence = service.evidence_service.store.for_finding(finding)[0]
    assert evidence.sanitized.body == "verified marker"
    assert evidence.sanitized.method == "GET"
    assert evidence.sanitized.request["url"] == TARGET
    assert result.scan.status == "completed"
    assert result.scan.started_at and result.scan.finished_at
    assert result.statistics.http_requests == result.statistics.findings == 1
    assert result.security.in_scope and result.security.authorization_granted


def test_passive_only_uses_supplied_response_and_skips_active_components():
    http = FakeHttp()
    result = app(
        http_engine=http,
        analyzer_registry=analyzer_registry(MarkerAnalyzer()),
        validators={"marker": MarkerValidator()},
    ).run(ScanRequest(target=TARGET, supplied_responses={TARGET: make_response()}))
    assert result.state == ScanState.COMPLETED
    assert not http.calls and result.findings
    assert next(s for s in result.stages if s.stage == ScanStage.SCANNERS).state == StageState.SKIPPED


def test_active_operation_requires_explicit_authorization():
    http = FakeHttp()
    result = app(http_engine=http).run(ScanRequest(target=TARGET, active=True))
    assert result.state == ScanState.FAILED
    assert not http.calls
    assert "explicit authorization" in result.errors[0].error


def test_out_of_scope_target_is_rejected_before_any_http():
    http = FakeHttp()
    scope = ScopeManager(URL("https://allowed.test/"))
    result = app(http_engine=http, scope_manager=scope).run(authorized())
    assert result.state == ScanState.FAILED
    assert not http.calls
    assert result.errors[0].stage == ScanStage.SCOPE


def test_discovered_out_of_scope_asset_is_not_probed():
    http = FakeHttp()
    recon = ReconPipeline(DiscoveryEngine(sources=[StaticSource([Asset("outside.test", "domain")])]))
    result = app(http_engine=http, recon_pipeline=recon).run(authorized(recon=True))
    assert all("outside.test" not in call[1] for call in http.calls)
    assert any("out of scope" in issue.error for issue in result.warnings)


def test_scanner_failure_is_isolated_and_other_scanners_continue():
    class GoodScanner(StaticScanner):
        name = "good_scanner"

    registry = ScannerRegistry()
    broken = StaticScanner(error=RuntimeError("scanner failed"))
    good = GoodScanner([Finding("scanner issue", "Low", "High", TARGET, evidence="proof")])
    registry.register(broken)
    registry.register(good)
    result = app(scanner_registry=registry).run(authorized())
    assert result.state == ScanState.PARTIAL
    assert broken.calls == good.calls == 1 and result.findings
    assert any(issue.component == "static_scanner" for issue in result.errors)


def test_analyzer_failure_does_not_prevent_other_analyzer():
    result = app(
        analyzer_registry=analyzer_registry(BrokenAnalyzer(), MarkerAnalyzer()),
        validators={"marker": MarkerValidator()},
    ).run(ScanRequest(target=TARGET, supplied_responses={TARGET: make_response()}))
    assert result.state == ScanState.PARTIAL
    assert len(result.analyses) == len(result.findings) == 1
    assert any(issue.component == "broken_analyzer" for issue in result.errors)


def test_validation_failure_is_recorded_and_scan_finishes_partial():
    result = app(
        analyzer_registry=analyzer_registry(MarkerAnalyzer()),
        validators={"marker": BrokenValidator()},
    ).run(ScanRequest(target=TARGET, supplied_responses={TARGET: make_response()}))
    assert result.state == ScanState.PARTIAL and not result.findings
    assert result.errors[0].stage == ScanStage.VALIDATION


def test_validator_cannot_create_finding_outside_scan_scope():
    class ForeignTargetValidator:
        def validate(self, analysis, context):
            return AnalysisValidation.finding(
                FindingCandidate(
                    title="Foreign", severity="Low", confidence="High",
                    target="https://other.test/", endpoint="https://other.test/",
                    evidence="signal",
                )
            )

    result = app(
        analyzer_registry=analyzer_registry(MarkerAnalyzer()),
        validators={"marker": ForeignTargetValidator()},
    ).run(ScanRequest(target=TARGET, supplied_responses={TARGET: make_response()}))
    assert result.findings == []
    assert any("outside scope" in issue.error for issue in result.errors)


def test_evidence_redacts_secrets_and_keeps_useful_body():
    service = app(
        analyzer_registry=analyzer_registry(MarkerAnalyzer()),
        validators={"marker": MarkerValidator()},
    )
    secret = make_response(body=b"password=hidden and public proof")
    result = service.run(ScanRequest(target=TARGET, supplied_responses={TARGET: secret}))
    evidence = service.evidence_service.store.for_finding(result.findings[0])[0]
    assert "hidden" not in str(evidence.to_dict())
    assert "public proof" in evidence.sanitized.body


def test_findings_deduplicate_across_scanners_and_analyzers():
    legacy = Finding(
        "Observed marker", "Medium", "High", TARGET, endpoint=TARGET,
        description="A marker was observed in the response.",
        evidence="verified marker", remediation="Review behavior.",
    )
    scanners = ScannerRegistry()
    scanners.register(StaticScanner([legacy]))
    service = app(
        scanner_registry=scanners,
        analyzer_registry=analyzer_registry(MarkerAnalyzer()),
        validators={"marker": MarkerValidator()},
    )
    result = service.run(authorized())
    assert len(result.findings) == 1
    assert result.statistics.duplicates == 1
    assert result.findings[0].evidence_ids


def test_missing_external_tool_is_warning_and_does_not_abort_recon():
    recon = ReconPipeline(DiscoveryEngine(sources=[OptionalSource([Asset("sub.example.test", "subdomain")])]))
    result = app(recon_pipeline=recon, tool_runner=FakeToolRunner()).run(
        ScanRequest(target=TARGET, recon=True)
    )
    assert result.state == ScanState.COMPLETED and not result.errors
    assert any("not installed" in issue.error for issue in result.warnings)
    assert len(result.assets) == 1


def test_active_recon_source_receives_only_scoped_dependencies():
    class ScopedSource(DiscoverySource):
        name = "scoped_active_test"
        passive = False

        def __init__(self):
            self.received = None

        def discover(self, target):
            raise AssertionError("active source must use discover_scoped")

        def discover_scoped(self, target, **dependencies):
            self.received = dependencies
            dependencies["http_engine"].get(target)
            dependencies["tool_runner"].run_scoped(
                target, ["fake-tool", target]
            )
            return [Asset(target, "url", source=self.name)]

    source = ScopedSource()
    service = app(recon_sources=[source])
    result = service.run(authorized(recon=True))
    assert source.received is not None
    assert source.received["scope_manager"].is_allowed(URL(TARGET))
    assert len(result.responses) == 1


def test_recon_source_failure_does_not_hide_other_discovery_results():
    class BrokenSource(StaticSource):
        name = "broken_source"

    class GoodSource(StaticSource):
        name = "good_source"

    recon = ReconPipeline(
        DiscoveryEngine(
            sources=[
                BrokenSource(error=RuntimeError("source down")),
                GoodSource([Asset("example.test", "subdomain")]),
            ]
        )
    )
    result = app(recon_pipeline=recon).run(ScanRequest(target=TARGET, recon=True))
    assert any(asset.value == "example.test" for asset in result.assets)
    assert any(issue.component == "broken_source" for issue in result.errors)


def test_scoped_http_engine_never_follows_redirects_automatically():
    http = FakeHttp()
    service = app(http_engine=http)
    result = service.run(authorized())
    assert result.state == ScanState.COMPLETED
    assert http.calls[0][2]["follow_redirects"] is False


def test_http_scanner_uses_scoped_injection_and_restores_its_dependency():
    registry = ScannerRegistry()
    scanner = SecurityHeadersScanner(http=FakeHttp())
    original = scanner.http
    registry.register(scanner)
    service = app(scanner_registry=registry)
    result = service.run(authorized())
    assert result.statistics.scanners_run == 1
    assert result.statistics.http_requests == 2
    assert result.statistics.http_responses == 2
    assert scanner.http is original


def test_example_scanner_requires_explicit_opt_in():
    registry = ScannerRegistry()
    registry.register(ExampleScanner())
    service = app(scanner_registry=registry)
    skipped = service.run(authorized())
    assert not skipped.findings
    opted_in = service.run(authorized(include_example_scanner=True))
    assert any(item.title == "Example Finding" for item in opted_in.findings)


def test_injected_dependencies_are_shared_with_engine_and_finding_pipeline():
    http = FakeHttp()
    runner = FakeToolRunner()
    service = ApplicationService(http_engine=http, tool_runner=runner)
    assert service.engine.http_engine is http
    assert service.engine.tool_runner is runner
    assert service.finding_pipeline.evidence_service is service.evidence_service
    assert service.engine.registry is service.scanner_registry
    assert service.engine.analyzer_registry is service.analyzer_registry


def test_scan_request_rejects_empty_target_or_missing_authorization_model():
    import pytest

    with pytest.raises(ValueError, match="target"):
        ScanRequest(target=" ")
    with pytest.raises(TypeError, match="AuthorizationGrant"):
        ScanRequest(target=TARGET, authorization=None)


def test_scanner_without_scoped_execution_adapter_is_skipped():
    registry = ScannerRegistry()
    scanner = UnawareScanner()
    registry.register(scanner)
    result = app(scanner_registry=registry).run(authorized())
    assert scanner.calls == 0
    assert any("no scoped execution adapter" in item.error for item in result.warnings)


def test_scope_guard_blocks_active_http_without_touching_transport():
    http = FakeHttp()
    result = app(
        http_engine=http,
        scope_manager=ScopeManager(URL("https://other.test/")),
    ).run(authorized())
    assert result.state == ScanState.FAILED
    assert http.calls == []


def test_cancelled_request_has_terminal_lifecycle_state():
    cancel = Event()
    cancel.set()
    result = app().run(ScanRequest(target=TARGET, cancel_event=cancel))
    assert result.state == ScanState.CANCELLED
    assert result.scan.status == "cancelled" and result.scan.finished_at
