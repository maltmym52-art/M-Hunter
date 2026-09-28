"""Stable, transport-neutral report document model."""

from dataclasses import dataclass, field
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
import re
from typing import Any, Mapping
from m_hunter.evidence.redaction import EvidenceRedactor


REPORT_SCHEMA = "m-hunter-report"
REPORT_SCHEMA_VERSION = "1.0"
_SENSITIVE_HEADER_LINE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)[^\r\n]*"
)


@dataclass(frozen=True)
class ReportModel:
    """Normalized scan report containing only presentation-safe data.

    Evidence snapshots in this model must already be sanitized. The model
    intentionally does not retain ScanExecutionResult, Finding, or Evidence
    objects, so renderers have no route to raw evidence material.
    """

    scan_id: str
    target: str
    status: str
    started_at: str | None
    finished_at: str | None
    duration_seconds: float
    scope: Mapping[str, Any] = field(default_factory=dict)
    authorization: Mapping[str, Any] = field(default_factory=dict)
    assets: tuple[Mapping[str, Any], ...] = ()
    findings: tuple[Mapping[str, Any], ...] = ()
    errors: tuple[Mapping[str, Any], ...] = ()
    statistics: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema: str = REPORT_SCHEMA
    schema_version: str = REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Enforce a redacted, allowlisted shape before any renderer sees data."""
        redactor = EvidenceRedactor()
        safe = lambda value: _safe_report_value(value, redactor)
        object.__setattr__(self, "scan_id", redactor.redact_text(str(self.scan_id)))
        object.__setattr__(self, "target", redactor.redact_text(str(self.target)))
        object.__setattr__(self, "status", redactor.redact_text(str(self.status)))
        object.__setattr__(self, "started_at", safe(self.started_at))
        object.__setattr__(self, "finished_at", safe(self.finished_at))
        object.__setattr__(self, "schema", redactor.redact_text(str(self.schema)))
        object.__setattr__(self, "schema_version", redactor.redact_text(str(self.schema_version)))
        object.__setattr__(self, "scope", _allow(self.scope, {"in_scope"}, safe))
        object.__setattr__(self, "authorization", _allow(
            self.authorization,
            {"active_enabled", "granted", "reference_present"}, safe,
        ))
        object.__setattr__(self, "assets", tuple(
            _allow(item, {"value", "type", "source"}, safe) for item in self.assets
        ))
        finding_fields = {
            "id", "title", "severity", "confidence", "target", "endpoint",
            "parameter", "description", "remediation", "cwe", "owasp",
            "status", "created_at", "updated_at", "metadata", "evidence_refs",
            "evidence",
        }
        evidence_fields = {
            "id", "request", "response", "url", "method", "status_code",
            "headers", "body", "parameter", "input_value", "analyzer",
            "source", "timestamp", "description", "context", "evidence",
        }
        findings = []
        for finding in self.findings:
            item = _allow(finding, finding_fields, safe)
            item["evidence"] = tuple(
                _allow(evidence, evidence_fields, safe)
                for evidence in finding.get("evidence", ())
                if isinstance(evidence, Mapping)
            )
            refs = finding.get("evidence_refs", ())
            item["evidence_refs"] = tuple(safe(ref) for ref in refs) if isinstance(refs, (list, tuple)) else ()
            findings.append(item)
        object.__setattr__(self, "findings", tuple(findings))
        object.__setattr__(self, "errors", tuple(
            _allow(item, {"component", "stage", "level", "error", "timestamp", "target", "endpoint"}, safe)
            for item in self.errors
        ))
        stats_fields = {
            "assets_discovered", "http_requests", "http_responses", "scanners_run",
            "analyzers_run", "analyses_validated", "findings", "evidence_records",
            "duplicates", "errors", "warnings",
        }
        object.__setattr__(self, "statistics", _allow(self.statistics, stats_fields, safe))
        object.__setattr__(self, "metadata", _allow(self.metadata, {"stage_states"}, safe))

    def to_dict(self) -> dict[str, Any]:
        """Return the explicit, versioned JSON-compatible report structure."""
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "scan": {
                "id": self.scan_id,
                "status": self.status,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "duration_seconds": self.duration_seconds,
            },
            "target": self.target,
            "scope": dict(self.scope),
            "authorization": dict(self.authorization),
            "assets": [dict(item) for item in self.assets],
            "findings": [dict(item) for item in self.findings],
            "errors": [dict(item) for item in self.errors],
            "statistics": dict(self.statistics),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReportModel":
        """Load a persisted report document without unsafe deserialization."""
        if not isinstance(value, Mapping):
            raise ValueError("report document must be a JSON object")
        if value.get("schema") != REPORT_SCHEMA:
            raise ValueError("unsupported report schema")
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise ValueError(f"unsupported report schema version: {value.get('schema_version')!r}")
        scan = value.get("scan")
        if not isinstance(scan, Mapping):
            raise ValueError("report scan metadata must be an object")
        for key in ("assets", "findings", "errors"):
            if not isinstance(value.get(key, []), list):
                raise ValueError(f"report {key} must be an array")
        for key in ("scope", "authorization", "statistics", "metadata"):
            if not isinstance(value.get(key, {}), Mapping):
                raise ValueError(f"report {key} must be an object")
        try:
            duration = float(scan["duration_seconds"])
            if duration < 0:
                raise ValueError("duration_seconds must not be negative")
            return cls(
                scan_id=str(scan["id"]),
                target=str(value["target"]),
                status=str(scan["status"]),
                started_at=_optional_string(scan.get("started_at")),
                finished_at=_optional_string(scan.get("finished_at")),
                duration_seconds=duration,
                scope=dict(value.get("scope", {})),
                authorization=dict(value.get("authorization", {})),
                assets=tuple(_mapping_items(value.get("assets", []), "assets")),
                findings=tuple(_mapping_items(value.get("findings", []), "findings")),
                errors=tuple(_mapping_items(value.get("errors", []), "errors")),
                statistics=dict(value.get("statistics", {})),
                metadata=dict(value.get("metadata", {})),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid report document: {exc}") from exc


def _allow(value: Mapping[str, Any], keys: set[str], sanitize) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {key: sanitize(value[key]) for key in sorted(keys) if key in value}


def _safe_report_value(value: Any, redactor: EvidenceRedactor) -> Any:
    """Redact values recursively and discard raw-evidence-shaped fields."""
    if isinstance(value, str):
        text = redactor.redact_text(value)
        return _SENSITIVE_HEADER_LINE.sub(r"\1<REDACTED>", text)
    if isinstance(value, datetime):
        return value
    if isinstance(value, Enum):
        return _safe_report_value(value.value, redactor)
    if is_dataclass(value) and not isinstance(value, type):
        value = {item.name: getattr(value, item.name) for item in fields(value)}
    if isinstance(value, Mapping):
        safe = {}
        for key in sorted(value, key=lambda item: str(item)):
            name = str(key)
            normalized = name.casefold().replace("-", "_")
            if normalized == "raw" or normalized.startswith("raw_"):
                continue
            safe[name] = _safe_report_value(value[key], redactor)
        return redactor.redact_value(safe)
    if isinstance(value, (tuple, list)):
        return tuple(_safe_report_value(item, redactor) for item in value)
    return redactor.redact_value(value)


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("timestamp fields must be strings or null")
    return value


def _mapping_items(values: list[Any], label: str) -> list[Mapping[str, Any]]:
    result = []
    for item in values:
        if not isinstance(item, Mapping):
            raise ValueError(f"each {label} item must be an object")
        result.append(dict(item))
    return result
