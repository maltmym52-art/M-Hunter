"""End-to-end proof of the security analysis-to-reporting path."""

import json

from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.analyzers.security_headers_baseline import SecurityHeadersBaselineAnalyzer
from m_hunter.analyzers.http_cookie_security import HttpCookieSecurityAnalyzer
from m_hunter.analyzers.cache_control_security import CacheControlSecurityAnalyzer
from m_hunter.analyzers.sqli import SQLiAnalyzer
from m_hunter.analyzers.xss import XSSAnalyzer
from m_hunter.analyzers.web_cache_key_security import WebCacheKeySecurityAnalyzer, WebCacheKeyIndicatorType
from m_hunter.application import ApplicationService, AuthorizationGrant, ScanRequest, ScanState
from m_hunter.application.scope import ScopeViolation
from m_hunter.core.finding import Finding
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.evidence.service import EvidenceService
from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import DiscoverySource
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL
from m_hunter.reporting.service import ReportService
from m_hunter.findings.identity import finding_semantic_identity
from m_hunter.scanners.example import ExampleScanner
from m_hunter.scanners.registry import ScannerRegistry
from m_hunter.integrations.tools.recon_sources import NmapSource
from m_hunter.integrations.tools.runner import ToolResult
from m_hunter.validation.analysis import AnalysisValidation, FindingCandidate


TARGET = "https://example.test/search?q=reflected&token=query-secret"
AUTH_SECRET = "Bearer authorization-secret"
COOKIE_SECRET = "cookie-secret-value"
JWT_SECRET = "eyJabcdefgh.eyJijklmnop.eyJqrstuvwx"
API_SECRET = "api_1234567890abcdef12345678"
PASSWORD_SECRET = "password-secret-value"


def response(url=TARGET, *, body=b"reflected marker", headers=None, cookies=None):
    return HttpResponse(
        status_code=200,
        url=url,
        headers=headers or {},
        content=body,
        cookies=cookies or {},
        response_time=0.01,
        content_length=len(body),
        repeated_headers={"Set-Cookie": [f"session={COOKIE_SECRET}; HttpOnly; SameSite=Lax"]},
    )


def registry(*analyzers):
    value = AnalyzerRegistry()
    for analyzer in analyzers:
        value.register(analyzer)
    return value


class ReflectedMarkerValidator:
    def validate(self, analysis, context):
        if not analysis.data.reflected:
            return AnalysisValidation.informational()
        return AnalysisValidation.finding(FindingCandidate(
            title="Reflected input observed", severity="Medium", confidence="High",
            target=context.request_url, endpoint=context.request_url, parameter="q",
            description="The supplied marker was reflected in the response.",
            evidence=f"Reflected marker: {analysis.data.marker}",
            remediation="Review the encoding and context of reflected input.",
            cwe="CWE-79", owasp="A03:2021",
        ))


class FakeHTTP:
    def __init__(self, headers=None, body=b"reflected marker"):
        self.headers = headers or {}
        self.body = body
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return response(url, body=self.body, headers=self.headers,
                        cookies={"session": COOKIE_SECRET})


def test_passive_security_headers_flow_reaches_report():
    headers = {"X-XSS-Protection": "1"}
    service = ApplicationService(analyzer_registry=registry(SecurityHeadersBaselineAnalyzer()))
    result = service.run(ScanRequest(
        TARGET, run_scanners=False,
        supplied_responses={TARGET: response(headers=headers)},
    ))
    assert result.findings
    assert all(finding.evidence_ids for finding in result.findings)
    assert any(finding.title == "Legacy X-XSS-Protection Configuration" for finding in result.findings)
    report = ReportService().build(result, service.evidence_service)
    assert any("Legacy X-XSS-Protection" in item["title"] for item in report.findings)


def test_default_server_version_disclosure_flows_to_evidence_and_all_reports():
    from m_hunter.application.factory import create_default_application_service

    target = "http://127.0.0.1:8765/"
    supplied = response(target, headers={"Server": "nginx/1.25.3"})
    service = create_default_application_service()
    http_spy = FakeHTTP()
    service.http_engine = http_spy
    result = service.run(ScanRequest(
        target,
        run_scanners=False,
        supplied_responses={target: supplied},
    ))
    assert http_spy.calls == []

    matches = [item for item in result.findings
               if item.title == "Server Version Disclosure"]
    assert len(matches) == 1
    finding = matches[0]
    assert finding.severity == "Low"
    assert finding.confidence == "High"
    assert finding.evidence == "nginx/1.25.3"
    assert finding_semantic_identity(finding) == (
        "semantic", "server_version_disclosure"
    )
    evidence = service.evidence_service.store.for_finding(finding)
    assert len(evidence) == 1
    assert evidence[0].sanitized.evidence == "nginx/1.25.3"
    assert evidence[0].sanitized.headers["response"]["Server"] == "nginx/1.25.3"

    reports = ReportService()
    model = reports.build(result, service.evidence_service)
    outputs = {
        fmt: reports.render(model, fmt)
        for fmt in ("json", "markdown", "html")
    }
    assert "Server Version Disclosure" in outputs["json"]
    assert "nginx/1.25.3" in outputs["json"]
    assert "Server Version Disclosure" in outputs["markdown"]
    assert "nginx/1.25.3" in outputs["markdown"]
    assert "Server Version Disclosure" in outputs["html"]
    assert "nginx/1.25.3" in outputs["html"]


def test_server_version_disclosure_requires_a_version_and_is_passive():
    from m_hunter.application.factory import create_default_application_service

    target = "http://127.0.0.1:8765/"
    service = create_default_application_service()
    analyzer = service.analyzer_registry.get("http_response_security")
    assert analyzer.capabilities.mode == "passive"
    assert not analyzer.capabilities.requires_authorization

    for headers in ({"Server": "nginx"}, {}):
        result = service.run(ScanRequest(
            target,
            run_scanners=False,
            supplied_responses={target: response(target, headers=headers)},
        ))
        assert not any(item.title == "Server Version Disclosure"
                       for item in result.findings)


def test_server_version_observation_identity_preserves_distinct_versions():
    from m_hunter.application.factory import create_default_application_service

    target = "http://127.0.0.1:8765/"
    service = create_default_application_service()
    for version in ("nginx/1.25.3", "nginx/1.26.0"):
        result = service.run(ScanRequest(
            target,
            run_scanners=False,
            supplied_responses={target: response(target, headers={"Server": version})},
        ))
        finding = next(item for item in result.findings
                       if item.title == "Server Version Disclosure")
        assert finding.evidence == version
        evidence = service.evidence_service.store.for_finding(finding)
        assert any(item.sanitized.evidence == version for item in evidence)


def test_semantically_identical_server_observations_are_deduplicated():
    from m_hunter.application.factory import create_default_application_service
    from m_hunter.analyzers.http_response_security import HttpResponseSecurityAnalyzer

    target = "http://127.0.0.1:8765/"
    service = create_default_application_service()
    duplicate_name = "http_response_security_repeat"
    service.analyzer_registry.register_legacy(
        HttpResponseSecurityAnalyzer(), name=duplicate_name
    )
    service.validators[duplicate_name] = service.validators["http_response_security"]

    result = service.run(ScanRequest(
        target,
        run_scanners=False,
        supplied_responses={target: response(target, headers={"Server": "nginx/1.25.3"})},
    ))
    matches = [item for item in result.findings
               if item.title == "Server Version Disclosure"]
    assert len(matches) == 1
    assert result.statistics.duplicates == 1
    assert matches[0].evidence == "nginx/1.25.3"


def test_missing_x_content_type_options_is_one_finding_across_scanner_and_analyzer():
    from m_hunter.scanners.registry import ScannerRegistry
    from m_hunter.scanners.security_headers import SecurityHeadersScanner

    target = "http://127.0.0.1:8765/"
    scanners = ScannerRegistry()
    scanners.register(SecurityHeadersScanner())
    service = ApplicationService(
        http_engine=FakeHTTP(headers={}), scanner_registry=scanners,
        analyzer_registry=registry(SecurityHeadersBaselineAnalyzer()),
    )
    try:
        result = service.run(ScanRequest(
            target, active=True, authorization=AuthorizationGrant(True, "local-qa"),
        ))
        related = [
            finding for finding in result.findings
            if "content-type-options" in finding.title.casefold()
            or "mime sniffing" in finding.title.casefold()
        ]
        assert len(related) == 1
        assert related[0].title == "Missing X-Content-Type-Options Header"
        assert related[0].evidence_ids
        assert result.statistics.duplicates == 1
    finally:
        service.close()


def test_invalid_x_content_type_options_becomes_evidenced_finding():
    target = "http://127.0.0.1:8765/"
    service = ApplicationService(
        analyzer_registry=registry(SecurityHeadersBaselineAnalyzer()),
    )
    try:
        result = service.run(ScanRequest(
            target, run_scanners=False,
            supplied_responses={target: response(
                target, headers={"X-Content-Type-Options": "invalid"},
            )},
        ))
        finding = next(
            item for item in result.findings
            if item.title == "MIME Sniffing Protection Missing"
        )
        assert finding.evidence == "invalid"
        assert finding.evidence_ids
        assert service.evidence_service.store.for_finding(finding)
    finally:
        service.close()


def test_cookie_response_flows_through_validation_and_redacted_evidence():
    service = ApplicationService(analyzer_registry=registry(HttpCookieSecurityAnalyzer()))
    result = service.run(ScanRequest(
        TARGET, run_scanners=False,
        supplied_responses={TARGET: response(cookies={"session": COOKIE_SECRET})},
    ))
    assert any("Cookie Missing Secure" in finding.title for finding in result.findings)
    evidence = service.evidence_service.store.for_finding(result.findings[0])[0]
    assert COOKIE_SECRET in str(evidence.raw.to_dict())
    assert COOKIE_SECRET not in str(evidence.sanitized.to_dict())


def test_cache_analysis_uses_existing_validator_and_request_context():
    service = ApplicationService(analyzer_registry=registry(CacheControlSecurityAnalyzer()))
    service.finding_pipeline  # initialized centrally with shared EvidenceService
    request = HttpRequest("GET", TARGET, params={"token": "query-secret"})
    result = service.run(ScanRequest(
        TARGET, run_scanners=False,
        supplied_requests={TARGET: request},
        supplied_responses={TARGET: response(headers={"Cache-Control": "public, max-age=3600"})},
        analyzer_options={"cache_control_security": {"sensitive_content": True}},
    ))
    assert any(finding.title == "Sensitive Content Is Publicly Cacheable" for finding in result.findings)
    finding = next(item for item in result.findings
                   if item.title == "Sensitive Content Is Publicly Cacheable")
    evidence = service.evidence_service.store.for_finding(finding)[0]
    assert evidence.sanitized.method == "GET"
    assert evidence.sanitized.url.endswith("token=<REDACTED>")


def test_input_analyzer_receives_request_and_response_context_then_is_validated():
    service = ApplicationService(
        analyzer_registry=registry(XSSAnalyzer()),
        validators={"xss": ReflectedMarkerValidator()},
    )
    request = HttpRequest("GET", "https://example.test/search", params={"q": "marker"})
    result = service.run(ScanRequest(
        TARGET, run_scanners=False,
        supplied_requests={TARGET: request},
        supplied_responses={TARGET: response()},
        analyzer_options={"xss": {"marker": "marker"}},
        metadata={"authorization": AUTH_SECRET, "api_key": API_SECRET},
    ))
    finding = next(item for item in result.findings if item.title == "Reflected input observed")
    assert result.analyses[0].analyzer_name == "xss"
    assert finding.evidence_ids
    assert AUTH_SECRET not in str(finding)
    assert API_SECRET not in str(finding.metadata)


def test_registry_adapts_legacy_response_analyzer_without_changing_direct_api():
    legacy = SQLiAnalyzer()
    analyzer_registry = registry(legacy)
    registered = analyzer_registry.get("sqli")
    assert registered.analyzer is legacy
    assert registered.capabilities.mode == "passive"
    analysis = registered.run(AnalysisContext(response=response(body=b"SQL syntax error")))
    assert analysis.analyzer_name == "sqli"
    assert analysis.data.detected
    assert legacy.analyze(response()).detected is False


def test_legacy_analysis_result_passes_validator_evidence_and_core_finding():
    class SQLiIndicatorValidator:
        def validate(self, analysis, context):
            if not analysis.data.detected:
                return AnalysisValidation.informational()
            return AnalysisValidation.finding(FindingCandidate(
                title="Database error indicator", severity="High", confidence="Medium",
                target=context.request_url, endpoint=context.request_url,
                description="A database error indicator was present in the supplied response.",
                evidence="SQL syntax error marker",
                remediation="Review query handling and error disclosure.",
            ))

    service = ApplicationService(
        analyzer_registry=registry(SQLiAnalyzer()),
        validators={"sqli": SQLiIndicatorValidator()},
    )
    result = service.run(ScanRequest(
        TARGET, run_scanners=False,
        supplied_responses={TARGET: response(body=b"SQL syntax error")},
    ))
    finding = next(item for item in result.findings
                   if item.title == "Database error indicator")
    assert result.analyses[0].analyzer_name == "sqli"
    assert finding.evidence_ids
    assert service.evidence_service.store.for_finding(finding)


def test_base_analyzer_context_options_and_request_url_reach_its_legacy_method():
    analyzer = WebCacheKeySecurityAnalyzer()
    analysis = analyzer.run(AnalysisContext(
        response=response(headers={"Cache-Control": "public, max-age=600"}),
        request_url="https://example.test/search?token=secret",
        options={"cacheable": True, "unkeyed_parameters": {"token"}},
    ))
    assert analysis.data.has_type(WebCacheKeyIndicatorType.SENSITIVE_QUERY_PARAMETER)
    assert analysis.data.has_type(WebCacheKeyIndicatorType.UNKEYED_QUERY_PARAMETER)


class ReconAssetSource(DiscoverySource):
    name = "test_recon"
    passive = True

    def discover(self, target):
        return [Asset("api.example.test", "subdomain", source=self.name)]


def test_full_scan_recon_http_analysis_evidence_finding_report_and_example_gate():
    headers = {
        "X-XSS-Protection": "1",
        "Cache-Control": "public, max-age=600",
        "Authorization": AUTH_SECRET,
        "X-Api-Key": API_SECRET,
        "X-JWT": JWT_SECRET,
    }
    http = FakeHTTP(headers=headers, body=b"marker reflected; password=password-secret-value")
    recon_scope = ScopeManager(URL(TARGET), allowed_hosts={"example.test", "api.example.test"})
    scanners = ScannerRegistry()
    scanners.register(ExampleScanner())
    service = ApplicationService(
        http_engine=http,
        recon_sources=[ReconAssetSource()],
        scanner_registry=scanners,
        analyzer_registry=registry(SecurityHeadersBaselineAnalyzer(), HttpCookieSecurityAnalyzer(),
                                  CacheControlSecurityAnalyzer(), XSSAnalyzer()),
        validators={"xss": ReflectedMarkerValidator()},
        scope_manager=recon_scope,
    )
    result = service.run(ScanRequest(
        TARGET, recon=True, active=True,
        authorization=AuthorizationGrant(True, reference="authorized-test-engagement"),
        analyzer_options={"cache_control_security": {"sensitive_content": True},
                          "xss": {"marker": "marker"}},
        run_scanners=True, include_example_scanner=False,
    ))
    assert result.state == ScanState.COMPLETED
    assert any(asset.value == "api.example.test" for asset in result.assets)
    assert len(http.calls) == 2
    assert result.statistics.scanners_run == 0
    assert result.findings and all(item.evidence_ids for item in result.findings)
    assert any(item.endpoint == "https://api.example.test" for item in result.findings)

    reports = ReportService()
    model = reports.build(result, service.evidence_service)
    outputs = [reports.render(model, format_name) for format_name in ("json", "markdown", "html")]
    serialized = "\n".join(outputs)
    for secret in (AUTH_SECRET, COOKIE_SECRET, JWT_SECRET, API_SECRET,
                   PASSWORD_SECRET, "query-secret", "authorized-test-engagement"):
        assert secret not in serialized
    assert "<REDACTED>" in serialized


class BrokenAnalyzer(BaseAnalyzer):
    name = "broken"

    def analyze(self, response):
        raise RuntimeError("expected analyzer failure")


class BrokenValidator:
    def validate(self, analysis, context):
        raise RuntimeError("expected validator failure")


def test_failure_isolation_keeps_valid_analyzers_running_and_records_validator_error():
    service = ApplicationService(
        analyzer_registry=registry(BrokenAnalyzer(), SecurityHeadersBaselineAnalyzer(), XSSAnalyzer()),
        validators={"xss": BrokenValidator()},
    )
    result = service.run(ScanRequest(
        TARGET, run_scanners=False,
        supplied_responses={TARGET: response(headers={"X-XSS-Protection": "1"})},
        analyzer_options={"xss": {"marker": "marker"}},
    ))
    assert any(issue.component == "broken" for issue in result.errors)
    assert any("validator failed" in issue.error for issue in result.errors)
    assert any(item.title == "Legacy X-XSS-Protection Configuration" for item in result.findings)
    assert not any(item.title == "Reflected input observed" for item in result.findings)


class RawFindingAnalyzer(BaseAnalyzer):
    name = "raw_finding"

    def analyze(self, response):
        return Finding("Raw", "High", "High", response.url,
                       evidence="not validated")


def test_analyzer_returning_finding_cannot_bypass_validation():
    service = ApplicationService(analyzer_registry=registry(RawFindingAnalyzer()))
    result = service.run(ScanRequest(
        TARGET, run_scanners=False, supplied_responses={TARGET: response()},
    ))
    assert isinstance(result.analyses[0].data, Finding)
    assert not result.findings


def test_legacy_scanner_finding_is_sanitized_before_application_exposes_it():
    evidence = EvidenceService()
    finding = Finding(
        "Sensitive response", "Low", "High", TARGET, endpoint=TARGET,
        description=f"Authorization: {AUTH_SECRET}", evidence=JWT_SECRET,
        metadata={"api_key": API_SECRET, "password": PASSWORD_SECRET},
    )
    evidence.record_legacy_finding(finding)
    rendered_finding = str(finding)
    for secret in (AUTH_SECRET, JWT_SECRET, API_SECRET, PASSWORD_SECRET, "query-secret"):
        assert secret not in rendered_finding


def test_converter_and_all_report_formats_redact_secrets_from_validated_candidate():
    class CredentialSignal(BaseAnalyzer):
        name = "credential_signal"

        def analyze(self, response):
            return {"observed": True}

    class CredentialValidator:
        def validate(self, analysis, context):
            return AnalysisValidation.finding(FindingCandidate(
                title="Credential-related response", severity="Medium", confidence="High",
                target=context.request_url, endpoint=context.request_url,
                description=f"Observed Authorization: {AUTH_SECRET}",
                evidence=f"Authorization: {AUTH_SECRET}; Cookie: session={COOKIE_SECRET}; "
                         f"jwt={JWT_SECRET}; api_key={API_SECRET}; password={PASSWORD_SECRET}",
                metadata={"api_key": API_SECRET, "password": PASSWORD_SECRET},
            ))

    service = ApplicationService(
        analyzer_registry=registry(CredentialSignal()),
        validators={"credential_signal": CredentialValidator()},
    )
    result = service.run(ScanRequest(
        TARGET, run_scanners=False,
        supplied_responses={TARGET: response()},
    ))
    finding = result.findings[0]
    for secret in (AUTH_SECRET, COOKIE_SECRET, JWT_SECRET, API_SECRET, PASSWORD_SECRET):
        assert secret not in str(finding)
    reports = ReportService()
    report = reports.build(result, service.evidence_service)
    for output_format in ("json", "markdown", "html"):
        rendered = reports.render(report, output_format)
        for secret in (AUTH_SECRET, COOKIE_SECRET, JWT_SECRET, API_SECRET, PASSWORD_SECRET):
            assert secret not in rendered


class FailingEvidenceService(EvidenceService):
    def record(self, *args, **kwargs):
        raise RuntimeError("evidence backend unavailable")


def test_evidence_failure_does_not_expose_raw_secret_or_create_finding():
    service = ApplicationService(
        analyzer_registry=registry(SecurityHeadersBaselineAnalyzer()),
        evidence_service=FailingEvidenceService(),
    )
    result = service.run(ScanRequest(
        TARGET, run_scanners=False,
        supplied_responses={TARGET: response(body=f"password={PASSWORD_SECRET}".encode(),
                                             headers={"Authorization": AUTH_SECRET,
                                                      "X-XSS-Protection": "1"})},
    ))
    assert not result.findings
    assert any("evidence backend unavailable" in issue.error for issue in result.errors)
    report = ReportService().build(result, service.evidence_service)
    for format_name in ("json", "markdown", "html"):
        rendered = ReportService().render(report, format_name)
        assert AUTH_SECRET not in rendered
        assert PASSWORD_SECRET not in rendered


def test_active_http_collection_rejects_unauthorized_or_out_of_scope_target():
    http = FakeHTTP()
    unauthorized = ApplicationService(http_engine=http).run(ScanRequest(
        TARGET, active=True, run_scanners=False,
        supplied_responses={},
    ))
    assert unauthorized.state == ScanState.FAILED
    assert not http.calls

    outside_scope = ScopeManager(URL("https://other.test/"))
    http = FakeHTTP()
    out_of_scope = ApplicationService(http_engine=http, scope_manager=outside_scope).run(
        ScanRequest(TARGET, active=True,
                    authorization=AuthorizationGrant(True, reference="engagement"),
                    run_scanners=False)
    )
    assert out_of_scope.state == ScanState.FAILED
    assert not http.calls


def test_hostile_target_text_stays_a_structured_argument_and_is_not_shell_command():
    class RecordingRunner:
        def __init__(self):
            self.calls = []

        def resolve(self, name):
            return f"/fake/{name}"

        def run(self, command, *, timeout=None, **kwargs):
            self.calls.append(tuple(command))
            return ToolResult(tuple(command), 0, "", "", 0.0)

    runner = RecordingRunner()
    source = NmapSource(runner)
    hostile_url = "https://example.test/$(whoami)"
    source.discover_scoped(hostile_url, scope_manager=ScopeManager(URL("https://example.test/")),
                           authorization=AuthorizationGrant(True), active_enabled=True)
    assert len(runner.calls) == 1
    assert isinstance(runner.calls[0], tuple)
    assert not any("whoami" in argument or "$" in argument for argument in runner.calls[0])


def test_duplicate_analyzer_signals_create_one_finding():
    class SignalAnalyzer(BaseAnalyzer):
        def __init__(self, name):
            self.name = name

        def analyze(self, response):
            return {"signal": "same"}

    class SignalValidator:
        def validate(self, analysis, context):
            return AnalysisValidation.finding(FindingCandidate(
                title="Shared finding", severity="Low", confidence="High",
                target=context.request_url, endpoint=context.request_url,
                description="Shared validated signal.", evidence="same evidence",
            ))

    service = ApplicationService(
        analyzer_registry=registry(SignalAnalyzer("source_one"), SignalAnalyzer("source_two")),
        validators={"source_one": SignalValidator(), "source_two": SignalValidator()},
    )
    result = service.run(ScanRequest(
        TARGET, run_scanners=False, supplied_responses={TARGET: response()},
    ))
    assert len(result.findings) == 1
    assert result.statistics.duplicates == 1
