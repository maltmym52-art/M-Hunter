"""Safety and integration checks for advisory AI analysis."""

from types import MappingProxyType

import pytest

from m_hunter.ai import AIAnalysisService, MockAIProvider
from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.analyzers.security_headers_baseline import SecurityHeadersBaselineAnalyzer
from m_hunter.application import ApplicationService, ScanRequest
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.evidence.service import EvidenceService
from m_hunter.reporting.service import ReportService


TARGET = "https://example.test/?token=query-secret"
SECRETS = (
    "Authorization-secret", "cookie-secret", "eyJheader.eyJpayload.signature",
    "sk_test_0123456789abcdef", "password-secret", "session-secret",
)


def scan_with_secrets():
    evidence = EvidenceService()
    analyzers = AnalyzerRegistry()
    analyzers.register(SecurityHeadersBaselineAnalyzer())
    service = ApplicationService(evidence_service=evidence, analyzer_registry=analyzers)
    body = ("Authorization: Bearer Authorization-secret\n"
            "Cookie: sid=cookie-secret\n"
            "token=eyJheader.eyJpayload.signature\n"
            "api_key=sk_test_0123456789abcdef password=password-secret session=session-secret").encode()
    response = HttpResponse(200, TARGET, {"Authorization": "Bearer Authorization-secret",
                                          "Cookie": "sid=cookie-secret",
                                          "X-XSS-Protection": "1"}, body,
                            {"sid": "cookie-secret"}, 0.1, len(body))
    result = service.run(ScanRequest(
        TARGET, run_scanners=False,
        supplied_requests={TARGET: HttpRequest("GET", TARGET,
                         headers={"Authorization": "Bearer Authorization-secret"},
                         cookies={"sid": "cookie-secret"}, params={"token": "session-secret"})},
        supplied_responses={TARGET: response},
    ))
    assert result.findings, "security header response should flow through validation into a Finding"
    finding = result.findings[0]
    safe_record = evidence.store.for_finding(finding)[0]
    return service, result, finding, safe_record


def test_ai_receives_sanitized_immutable_inputs_and_only_returns_advisory_notes():
    service, result, finding, evidence = scan_with_secrets()
    provider = MockAIProvider({"notes": [{"kind": "hypothesis",
        "text": "Review this evidence and bearer Authorization-secret",
        "finding_ids": [finding.id, "unknown-id"],
        "severity": "Critical", "confidence": "Certain"}]})
    ai = AIAnalysisService(provider)
    before_finding = (finding.title, finding.severity, finding.confidence, finding.evidence)
    before_raw = evidence.raw.to_dict()

    analysis = ai.analyze(result, service.evidence_service)

    sent = str(provider.requests[0])
    request_contract = provider.requests[0]
    assert analysis.status == "completed"
    assert analysis.notes[0].kind == "hypothesis"
    assert analysis.notes[0].finding_ids == (finding.id,)
    assert "Authorization-secret" not in analysis.notes[0].text
    assert all(secret not in sent for secret in SECRETS)
    assert "<REDACTED>" in sent
    assert isinstance(provider.requests[0].summary, MappingProxyType)
    assert not hasattr(request_contract, "application_service")
    assert not hasattr(request_contract, "scope_manager")
    assert not hasattr(request_contract, "tool_runner")
    assert not hasattr(request_contract, "http_engine")
    with pytest.raises(TypeError):
        provider.requests[0].summary["status"] = "mutated"
    with pytest.raises(TypeError):
        provider.requests[0].http_observations[0]["status_code"] = 500
    assert (finding.title, finding.severity, finding.confidence, finding.evidence) == before_finding
    assert evidence.raw.to_dict() == before_raw
    assert not hasattr(analysis.notes[0], "severity")
    assert not hasattr(analysis.notes[0], "confidence")


def test_ai_malformed_output_and_provider_failure_are_nonfatal_to_scan():
    service, result, _finding, _evidence = scan_with_secrets()
    original_state = result.state
    malformed = AIAnalysisService(MockAIProvider({"finding": {"title": "made up"}}))
    failed = AIAnalysisService(_BrokenProvider())
    assert malformed.analyze(result, service.evidence_service).status == "invalid"
    assert failed.analyze(result, service.evidence_service).status == "failed"
    assert result.state == original_state
    assert result.findings[0].title != ""


class _BrokenProvider:
    name = "broken"

    def analyze(self, _request):
        raise RuntimeError("Authorization: Bearer provider-secret")


def test_reporting_remains_shared_and_ai_notes_do_not_enter_findings():
    service, result, finding, _evidence = scan_with_secrets()
    ai_result = AIAnalysisService(MockAIProvider()).analyze(result, service.evidence_service)
    report = ReportService().build(result, service.evidence_service)
    assert ai_result.notes
    assert len(report.findings) == len(result.findings)
    assert finding.id in {item["id"] for item in report.findings}
