"""Evidence records with separate raw and sanitized representations."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4


def _json_safe(value: Any) -> Any:
    """Convert sanitized arbitrary values to JSON-compatible values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


@dataclass(frozen=True)
class EvidenceData:
    """Captured HTTP and analysis context for one piece of evidence."""

    request: Any = None
    response: Any = None
    url: str | None = None
    method: str | None = None
    status_code: int | None = None
    headers: Mapping[str, Any] = field(default_factory=dict)
    body: str | None = None
    parameter: str | None = None
    input_value: Any = None
    analyzer: str | None = None
    source: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""
    context: Mapping[str, Any] = field(default_factory=dict)
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of this snapshot."""
        return {
            "request": _json_safe(self.request),
            "response": _json_safe(self.response),
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "headers": _json_safe(self.headers),
            "body": self.body,
            "parameter": self.parameter,
            "input_value": _json_safe(self.input_value),
            "analyzer": self.analyzer,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "context": _json_safe(self.context),
            "evidence": self.evidence,
        }


@dataclass
class Evidence:
    """Evidence with raw data kept separate from the safe export view.

    ``to_dict`` and the convenience attributes expose only sanitized values.
    Raw material is available through ``raw`` for controlled internal use.
    """

    raw: EvidenceData
    sanitized: EvidenceData
    id: str = field(default_factory=lambda: str(uuid4()))
    finding_ids: list[str] = field(default_factory=list)

    @property
    def url(self) -> str | None:
        return self.sanitized.url

    @property
    def method(self) -> str | None:
        return self.sanitized.method

    @property
    def status_code(self) -> int | None:
        return self.sanitized.status_code

    @property
    def headers(self) -> Mapping[str, Any]:
        return self.sanitized.headers

    @property
    def body(self) -> str | None:
        return self.sanitized.body

    @property
    def parameter(self) -> str | None:
        return self.sanitized.parameter

    @property
    def input_value(self) -> Any:
        return self.sanitized.input_value

    @property
    def analyzer(self) -> str | None:
        return self.sanitized.analyzer

    @property
    def source(self) -> str | None:
        return self.sanitized.source

    @property
    def timestamp(self) -> datetime:
        return self.sanitized.timestamp

    @property
    def description(self) -> str:
        return self.sanitized.description

    @property
    def context(self) -> Mapping[str, Any]:
        return self.sanitized.context

    @property
    def request(self) -> Any:
        return self.sanitized.request

    @property
    def response(self) -> Any:
        return self.sanitized.response

    def to_dict(self) -> dict[str, Any]:
        """Serialize only the sanitized snapshot for reporting/UI use."""
        return {
            "id": self.id,
            "finding_ids": list(self.finding_ids),
            **self.sanitized.to_dict(),
        }
