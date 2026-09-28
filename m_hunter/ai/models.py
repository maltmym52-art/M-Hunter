"""Immutable transport types for advisory AI analysis."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


@dataclass(frozen=True)
class AIAnalysisRequest:
    """Sanitized, read-only scan material. Contains no domain service handles."""

    scan_id: str
    summary: Mapping[str, Any]
    findings: tuple[Mapping[str, Any], ...] = ()
    evidence: tuple[Mapping[str, Any], ...] = ()
    http_observations: tuple[Mapping[str, Any], ...] = ()
    recon_metadata: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class AIAnalysisNote:
    """An advisory note only; deliberately has no severity/confidence fields."""

    kind: str
    text: str
    finding_ids: tuple[str, ...] = ()
    created_at: datetime = datetime.min.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class AIAnalysisResult:
    """Non-authoritative analyst notes that cannot represent a Finding."""

    status: str
    notes: tuple[AIAnalysisNote, ...] = ()
    error: str | None = None
