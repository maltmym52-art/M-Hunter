"""Convert application scan results into sanitized report documents."""

from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Mapping

from m_hunter.application.models import ScanExecutionResult
from m_hunter.evidence.service import EvidenceService
from m_hunter.evidence.redaction import EvidenceRedactor
from m_hunter.reporting.model import ReportModel


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}


def to_json_value(value: Any) -> Any:
    """Convert supported Python values to deterministic JSON primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return to_json_value(value.value)
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: to_json_value(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): to_json_value(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (tuple, list, set, frozenset)):
        sequence = list(value)
        if isinstance(value, (set, frozenset)):
            sequence.sort(key=lambda item: repr(item))
        return [to_json_value(item) for item in sequence]
    return str(value)


class ReportNormalizer:
    """Extract only allowlisted scan data and sanitized evidence snapshots."""

    def __init__(self, redactor: EvidenceRedactor | None = None) -> None:
        self.redactor = redactor or EvidenceRedactor()

    def normalize(self, result: ScanExecutionResult,
                  evidence_service: EvidenceService | None = None) -> ReportModel:
        if not isinstance(result, ScanExecutionResult):
            raise TypeError("result must be a ScanExecutionResult")
        scan = result.scan
        security = result.security
        target = security.target if security else scan.target.url
        findings = []
        store = evidence_service.store if evidence_service is not None else None
        for finding in result.findings:
            evidence_records = store.for_finding(finding) if store is not None else ()
            evidence = [self._evidence_snapshot(item) for item in evidence_records]
            findings.append({
                "id": self._text(finding.id),
                "title": self._text(finding.title),
                "severity": self._text(finding.severity),
                "confidence": self._text(finding.confidence),
                "target": self._text(finding.target),
                "endpoint": self._text(finding.endpoint),
                "parameter": self._text(finding.parameter),
                "description": self._text(finding.description),
                "remediation": self._text(finding.remediation),
                "cwe": self._text(finding.cwe),
                "owasp": self._text(finding.owasp),
                "status": self._text(finding.status),
                "created_at": to_json_value(finding.created_at),
                "updated_at": to_json_value(finding.updated_at),
                "metadata": self._safe_value(finding.metadata),
                "evidence_refs": list(finding.evidence_ids),
                "evidence": evidence,
            })
        findings.sort(key=lambda item: (
            SEVERITY_ORDER.get(str(item["severity"]).casefold(), 99),
            str(item["title"]).casefold(),
            str(item["endpoint"] or "").casefold(),
            str(item["id"]),
        ))
        assets = [{"value": self._text(asset.value), "type": asset.asset_type,
                   "source": self._text(asset.source)} for asset in result.assets]
        assets.sort(key=lambda item: (item["type"], item["value"] or "", item["source"] or ""))
        errors = [{
            "component": self._text(issue.component),
            "stage": self._text(issue.stage),
            "level": self._text(issue.level),
            "error": self._text(issue.error),
            "timestamp": to_json_value(issue.timestamp),
            "target": self._text(issue.target),
            "endpoint": self._text(issue.endpoint),
        } for issue in result.issues]
        errors.sort(key=lambda item: (item["stage"] or "", item["component"] or "", item["timestamp"] or ""))
        return ReportModel(
            scan_id=str(scan.id), target=self._text(target) or "",
            status=self._text(result.state) or "unknown",
            started_at=to_json_value(scan.started_at),
            finished_at=to_json_value(scan.finished_at),
            duration_seconds=self._duration(scan.started_at, scan.finished_at),
            scope={"in_scope": security.in_scope if security else None},
            authorization={
                "active_enabled": security.active_enabled if security else False,
                "granted": security.authorization_granted if security else False,
                "reference_present": bool(security.authorization_reference) if security else False,
            },
            assets=tuple(assets), findings=tuple(findings), errors=tuple(errors),
            statistics=to_json_value(result.statistics),
            metadata={"stage_states": [
                {"stage": self._text(stage.stage), "state": self._text(stage.state),
                 "started_at": to_json_value(stage.started_at),
                 "finished_at": to_json_value(stage.finished_at)}
                for stage in result.stages
            ]},
        )

    def _evidence_snapshot(self, evidence: Any) -> dict[str, Any]:
        """Use only Evidence.sanitized; deliberately never inspect Evidence.raw."""
        safe = evidence.sanitized
        return self._safe_value({
            "id": evidence.id,
            "request": safe.request,
            "response": safe.response,
            "url": safe.url,
            "method": safe.method,
            "status_code": safe.status_code,
            "headers": safe.headers,
            "body": safe.body,
            "parameter": safe.parameter,
            "input_value": safe.input_value,
            "analyzer": safe.analyzer,
            "source": safe.source,
            "timestamp": safe.timestamp,
            "description": safe.description,
            "context": safe.context,
            "evidence": safe.evidence,
        })

    def _safe_value(self, value: Any) -> Any:
        value = to_json_value(value)
        return self.redactor.redact_value(value)

    def _text(self, value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, Enum):
            value = value.value
        return self.redactor.redact_text(str(value))

    @staticmethod
    def _duration(started: datetime | None, finished: datetime | None) -> float:
        if started is None or finished is None:
            return 0.0
        return max(0.0, (finished - started).total_seconds())
