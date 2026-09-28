"""Thread-safe in-memory evidence store with deduplication and associations."""

import hashlib
import json
from threading import RLock
from typing import Iterable

from m_hunter.core.finding import Finding
from m_hunter.evidence.model import Evidence


class InMemoryEvidenceStore:
    """Keep evidence records and Finding links for the lifetime of a scan."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[str, Evidence] = {}
        self._fingerprints: dict[str, str] = {}

    def add(self, evidence: Evidence) -> Evidence:
        """Store evidence or return the existing record for an exact duplicate."""
        fingerprint = self._fingerprint(evidence)
        with self._lock:
            existing_id = self._fingerprints.get(fingerprint)
            if existing_id is not None:
                return self._records[existing_id]
            self._records[evidence.id] = evidence
            self._fingerprints[fingerprint] = evidence.id
            return evidence

    def associate(self, evidence_id: str, finding: Finding) -> Evidence:
        """Link a stored record to a Finding without duplicating either link."""
        with self._lock:
            evidence = self._records[evidence_id]
            if finding.id not in evidence.finding_ids:
                evidence.finding_ids.append(finding.id)
            if evidence.id not in finding.evidence_ids:
                finding.evidence_ids.append(evidence.id)
            return evidence

    def get(self, evidence_id: str) -> Evidence | None:
        with self._lock:
            return self._records.get(evidence_id)

    def all(self) -> tuple[Evidence, ...]:
        with self._lock:
            return tuple(self._records.values())

    def for_finding(self, finding: Finding | str) -> tuple[Evidence, ...]:
        finding_id = finding.id if isinstance(finding, Finding) else finding
        with self._lock:
            return tuple(
                item for item in self._records.values()
                if finding_id in item.finding_ids
            )

    def export(self, evidence_ids: Iterable[str] | None = None) -> list[dict]:
        """Return sanitized dictionaries suitable for reports and UI."""
        with self._lock:
            records = (
                [self._records[item] for item in evidence_ids if item in self._records]
                if evidence_ids is not None
                else list(self._records.values())
            )
            return [item.to_dict() for item in records]

    @staticmethod
    def _fingerprint(evidence: Evidence) -> str:
        # Timestamp and generated ID do not distinguish duplicate observations.
        snapshot = evidence.sanitized.to_dict()
        snapshot.pop("timestamp", None)
        serialized = json.dumps(snapshot, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
