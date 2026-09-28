import json
from datetime import datetime, timezone

import pytest

from m_hunter.application.models import (
    ScanExecutionResult, ScanIssue, ScanSecurityContext, ScanStage, ScanState,
    ScanStatistics,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.core.scan import Scan
from m_hunter.core.target import Target
from m_hunter.evidence.service import EvidenceService
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.recon.asset import Asset
from m_hunter.reporting import (
    HTMLRenderer, JSONRenderer, MarkdownRenderer, REPORT_SCHEMA_VERSION,
    ReportError, ReportModel, ReportNormalizer, ReportOutputError, ReportService,
)


TARGET = "https://example.test/"


def make_result(*, finding_count=1, secrets=False):
    started = datetime(2025, 1, 1, tzinfo=timezone.utc)
    finished = datetime(2025, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
    scan = Scan(Target(TARGET), id="scan-test", started_at=started, finished_at=finished)
    result = ScanExecutionResult(scan=scan, state=ScanState.PARTIAL)
    result.security = ScanSecurityContext(TARGET, True, True, False, "private-ticket")
    result.assets = [Asset("api.example.test", "subdomain", source="fixture")]
    evidence_service = EvidenceService()
    for index in range(finding_count):
        finding = Finding(
            title=f"Finding {index}", severity=("Low" if index == 0 else "Critical"),
            confidence="High", target=TARGET, endpoint=TARGET + "?token=endpointsecret",
            parameter="id", description="Observed behavior", evidence="evidence marker",
            remediation="Review the behavior", cwe="CWE-79", owasp="A03:2021",
            metadata={"ordinary": "value", "api_key": "metadatasecret"},
        )
        result.findings.append(finding)
        if secrets:
            headers = {
                "Authorization": "Bearer bearer-raw-secret",
                "Cookie": "sid=cookie-raw-secret",
                "X-Api-Key": "api-raw-secret",
            }
            body = (b'{"password":"password-raw-secret",'
                    b'"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature-secret"}'
                    b'\nAuthorization: Basic basic-raw-secret')
        else:
            headers, body = {"Content-Type": "text/plain"}, b"safe"
        response = HttpResponse(200, TARGET, headers, body,
                                {"session": "cookie-value"}, 0.01, len(body))
        record = evidence_service.record(
            AnalysisContext(response=response, request_url=TARGET, target=TARGET,
                            metadata={"authorization": "metadata-secret"}),
            finding, analyzer="fixture", evidence="payload evidence",
            description="Captured response", input_value={"secret": "input-secret"},
        )
        result.evidence_ids.append(record.id)
    result.statistics = ScanStatistics(assets_discovered=1, findings=finding_count,
                                       evidence_records=finding_count, warnings=1)
    result.issues = [ScanIssue("fixture", ScanStage.ANALYZERS, "safe diagnostic",
                               target=TARGET, level="warning")]
    return result, evidence_service


def test_report_model_schema_and_round_trip():
    result, evidence = make_result()
    report = ReportNormalizer().normalize(result, evidence)
    assert report.schema_version == REPORT_SCHEMA_VERSION
    assert report.to_dict()["schema"] == "m-hunter-report"
    loaded = ReportModel.from_dict(report.to_dict())
    assert loaded == report
    assert loaded.authorization == {
        "active_enabled": False, "granted": True, "reference_present": True,
    }
    assert "private-ticket" not in json.dumps(loaded.to_dict())


def test_severity_order_is_display_only_and_values_are_preserved():
    result, evidence = make_result(finding_count=2)
    report = ReportNormalizer().normalize(result, evidence)
    assert [item["severity"] for item in report.findings] == ["Critical", "Low"]
    assert {item["severity"] for item in report.findings} == {"Critical", "Low"}


def test_empty_scan_renders_all_formats():
    result, evidence = make_result(finding_count=0)
    report = ReportNormalizer().normalize(result, evidence)
    assert "No findings" in MarkdownRenderer().render(report)
    assert "No findings" in HTMLRenderer().render(report)
    assert json.loads(JSONRenderer().render(report))["findings"] == []


def test_json_is_structured_and_deterministic_with_datetime_enum_and_tuples():
    result, evidence = make_result()
    service = ReportService()
    report = service.build(result, evidence)
    first = service.render(report, "json")
    second = service.render(report, "json")
    decoded = json.loads(first)
    assert first == second
    assert decoded["scan"]["started_at"] == "2025-01-01T00:00:00+00:00"
    assert decoded["findings"][0]["evidence_refs"]
    assert decoded["findings"][0]["severity"] == "Low"  # one finding fixture


@pytest.mark.parametrize("renderer,markers", [
    (JSONRenderer(), ("schema_version", "evidence_refs", "CWE-79")),
    (MarkdownRenderer(), ("## Summary", "## Findings", "Remediation", "## Statistics", "## Errors")),
    (HTMLRenderer(), ("<!doctype html>", "#summary", "#findings", "#statistics", "#errors", "<style>")),
])
def test_renderers_include_required_sections(renderer, markers):
    result, evidence = make_result()
    output = renderer.render(ReportNormalizer().normalize(result, evidence))
    for marker in markers:
        assert marker.lower() in output.lower()


def test_html_is_escaped_and_self_contained():
    result, evidence = make_result()
    result.findings[0].title = "<script>alert(1)</script>"
    html = HTMLRenderer().render(ReportNormalizer().normalize(result, evidence))
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "https://" not in html or "https://example.test" in html
    assert "cdn." not in html


@pytest.mark.parametrize("renderer", [JSONRenderer(), MarkdownRenderer(), HTMLRenderer()])
def test_raw_secrets_never_appear_in_any_report_format(renderer):
    result, evidence = make_result(secrets=True)
    text = renderer.render(ReportNormalizer().normalize(result, evidence))
    for secret in (
        "bearer-raw-secret", "basic-raw-secret", "cookie-raw-secret", "api-raw-secret",
        "password-raw-secret", "signature-secret", "cookie-value",
        "metadatasecret", "metadata-secret", "input-secret", "endpointsecret",
        "private-ticket",
    ):
        assert secret not in text
    assert "REDACTED" in text


def test_raw_evidence_is_not_consulted_by_normalizer():
    result, evidence_service = make_result(secrets=True)
    evidence = evidence_service.store.for_finding(result.findings[0])[0]
    evidence.raw = None  # type: ignore[assignment]
    report = ReportNormalizer().normalize(result, evidence_service)
    assert report.findings[0]["evidence"]


def test_model_discards_raw_fields_before_renderer_access():
    result, evidence_service = make_result()
    payload = ReportNormalizer().normalize(result, evidence_service).to_dict()
    payload["authorization"]["authorization_reference"] = "private-ref"
    payload["findings"][0]["evidence"][0]["raw"] = {"payload": "unmarked-raw-secret"}
    model = ReportModel.from_dict(payload)
    rendered = JSONRenderer().render(model)
    assert "private-ref" not in rendered
    assert "unmarked-raw-secret" not in rendered
    assert "raw" not in model.findings[0]["evidence"][0]


def test_load_rejects_malformed_and_unknown_schema(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(ReportError):
        ReportService().load(path)
    path.write_text(json.dumps({"schema": "other", "schema_version": "1.0"}), encoding="utf-8")
    with pytest.raises(ReportError, match="unsupported report schema"):
        ReportService().load(path)


def test_load_migrates_flat_stage_five_scan_json(tmp_path):
    path = tmp_path / "legacy-scan.json"
    path.write_text(json.dumps({
        "state": "completed", "target": TARGET,
        "assets": [{"value": TARGET, "type": "url", "source": "target"}],
        "findings": [{"id": "f-1", "title": "Legacy", "severity": "Medium",
                      "confidence": "High", "target": TARGET,
                      "evidence": "safe legacy evidence", "evidence_ids": []}],
        "errors": [], "statistics": {"findings": 1}, "duration": 2.5,
    }), encoding="utf-8")
    report = ReportService().load(path)
    assert report.schema_version == "1.0"
    assert report.status == "completed"
    assert report.findings[0]["title"] == "Legacy"


def test_output_creates_directories_and_refuses_overwrite(tmp_path):
    result, evidence = make_result()
    service = ReportService()
    report = service.build(result, evidence)
    path = tmp_path / "nested" / "report.json"
    service.write(report, "json", path)
    assert path.is_file()
    original = path.read_text(encoding="utf-8")
    with pytest.raises(ReportOutputError, match="cannot write report"):
        service.write(report, "json", path)
    assert path.read_text(encoding="utf-8") == original
    service.write(report, "markdown", path, overwrite=True)
    assert path.read_text(encoding="utf-8").startswith("# M-Hunter")


def test_output_filesystem_error_is_clear(tmp_path):
    result, evidence = make_result()
    report = ReportService().build(result, evidence)
    path = tmp_path / "not-a-dir"
    path.write_text("occupied", encoding="utf-8")
    with pytest.raises(ReportOutputError):
        ReportService().write(report, "html", path / "report.html")


def test_from_dict_validates_collection_shapes():
    result, evidence = make_result()
    payload = ReportNormalizer().normalize(result, evidence).to_dict()
    payload["findings"] = {"bad": "shape"}
    with pytest.raises(ValueError, match="findings must be an array"):
        ReportModel.from_dict(payload)
