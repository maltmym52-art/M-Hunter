"""Safe preparation and validation of optional AI analyst requests."""

from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping

from m_hunter.ai.models import AIAnalysisNote, AIAnalysisRequest, AIAnalysisResult
from m_hunter.ai.providers import AIProvider
from m_hunter.application.models import ScanExecutionResult
from m_hunter.evidence.redaction import EvidenceRedactor
from m_hunter.evidence.service import EvidenceService
from m_hunter.reporting.service import ReportService


def _freeze(value: Any) -> Any:
    """Copy nested provider input into immutable mapping/tuple primitives."""
    if isinstance(value, Mapping):
        return MappingProxyType({str(k): _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return _freeze({field.name: getattr(value, field.name) for field in fields(value)})
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


class AIAnalysisService:
    """Ask an optional provider to explain/correlate data without scan powers."""

    ALLOWED_KINDS = frozenset({
        "explanation", "correlation", "prioritization_rationale",
        "remediation_explanation", "duplicate_suggestion", "analyst_note",
        "hypothesis", "summary",
    })

    def __init__(self, provider: AIProvider,
                 report_service: ReportService | None = None,
                 redactor: EvidenceRedactor | None = None) -> None:
        self.provider = provider
        self.report_service = report_service or ReportService()
        self.redactor = redactor or EvidenceRedactor()

    def prepare(self, scan: ScanExecutionResult,
                evidence_service: EvidenceService) -> AIAnalysisRequest:
        """Build a redacted, allowlisted input snapshot, excluding raw Evidence."""
        report = self.report_service.build(scan, evidence_service).to_dict()
        finding_ids = {str(item.get("id", "")) for item in report["findings"]}
        evidence = tuple(
            item for item in evidence_service.store.export(scan.evidence_ids)
            if set(item.get("finding_ids", ())) & finding_ids
        )
        observations = []
        for endpoint, response in scan.responses.items():
            request = scan.requests.get(endpoint)
            observations.append({
                "url": self.redactor.redact_text(str(getattr(response, "url", endpoint))),
                "status_code": getattr(response, "status_code", None),
                "headers": self.redactor.redact_headers(getattr(response, "headers", {}) or {}),
                "cookies": self.redactor.redact_cookies(getattr(response, "cookies", {}) or {}),
                "body": self.redactor.redact_body(getattr(response, "content", b"")),
                "request": ({
                    "method": getattr(request, "method", None),
                    "url": self.redactor.redact_text(str(getattr(request, "full_url", endpoint))),
                    "headers": self.redactor.redact_headers(getattr(request, "headers", {}) or {}),
                    "cookies": self.redactor.redact_cookies(getattr(request, "cookies", {}) or {}),
                    "params": self.redactor.redact_value(getattr(request, "params", {}) or {}),
                    "body": self.redactor.redact_value(getattr(request, "body", None)),
                } if request is not None else None),
            })
        return AIAnalysisRequest(
            scan_id=str(report["scan"]["id"]),
            summary=_freeze({
                "scan": report["scan"], "target": report["target"],
                "statistics": report["statistics"], "status": report["scan"]["status"],
            }),
            findings=tuple(_freeze(item) for item in report["findings"]),
            evidence=tuple(_freeze(item) for item in evidence),
            http_observations=tuple(_freeze(item) for item in observations),
            recon_metadata=tuple(_freeze(item) for item in report["assets"]),
        )

    def analyze(self, scan: ScanExecutionResult,
                evidence_service: EvidenceService) -> AIAnalysisResult:
        """Return advisory notes; provider errors never mutate/fail a scan."""
        request = self.prepare(scan, evidence_service)
        try:
            payload = self.provider.analyze(request)
            notes_payload = payload.get("notes") if isinstance(payload, Mapping) else None
            if not isinstance(notes_payload, (list, tuple)):
                return AIAnalysisResult("invalid", error="provider output must contain a notes array")
            notes = []
            known_ids = {str(item.get("id", "")) for item in request.findings}
            for item in notes_payload:
                if not isinstance(item, Mapping) or not isinstance(item.get("text"), str):
                    return AIAnalysisResult("invalid", error="provider returned a malformed analyst note")
                kind = str(item.get("kind", "analyst_note"))
                if kind not in self.ALLOWED_KINDS:
                    kind = "analyst_note"
                ids = item.get("finding_ids", ())
                if not isinstance(ids, (list, tuple)):
                    return AIAnalysisResult("invalid", error="finding_ids must be an array")
                safe_ids = tuple(str(value) for value in ids if str(value) in known_ids)
                notes.append(AIAnalysisNote(
                    kind=kind,
                    text=self.redactor.redact_text(item["text"]),
                    finding_ids=safe_ids,
                    created_at=datetime.now(timezone.utc),
                ))
            return AIAnalysisResult("completed", tuple(notes))
        except Exception as exc:
            return AIAnalysisResult("failed", error=self.redactor.redact_text(str(exc)))
