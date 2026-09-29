"""Evidence capture and safe association helpers for application layers."""

from typing import Any

from m_hunter.analyzers.context import AnalysisContext
from m_hunter.core.finding import Finding
from m_hunter.evidence.collector import EvidenceCollector
from m_hunter.evidence.model import Evidence
from m_hunter.evidence.store import InMemoryEvidenceStore


class EvidenceService:
    """Capture, deduplicate, and associate evidence without Finding concerns."""

    def __init__(
        self,
        collector: EvidenceCollector | None = None,
        store: InMemoryEvidenceStore | None = None,
    ) -> None:
        self.collector = collector or EvidenceCollector()
        self.store = store or InMemoryEvidenceStore()

    def record(
        self,
        context: AnalysisContext,
        finding: Finding,
        *,
        analyzer: str | None = None,
        source: str = "analysis",
        evidence: str = "",
        description: str = "",
        parameter: str | None = None,
        input_value: Any = None,
    ) -> Evidence:
        """Capture sanitized/reporting evidence and attach it to a Finding."""
        record = self.collector.capture(
            context,
            analyzer=analyzer,
            source=source,
            evidence=evidence,
            description=description,
            parameter=parameter,
            input_value=input_value,
        )
        record = self.store.add(record)
        # Legacy Finding.evidence remains a supported display field, so keep it
        # useful while ensuring its text cannot bypass evidence redaction.
        finding.evidence = record.sanitized.evidence
        redactor = self.collector.redactor
        for attribute in ("title", "target", "endpoint", "parameter", "description",
                          "remediation", "cwe", "owasp"):
            value = getattr(finding, attribute, None)
            if isinstance(value, str):
                setattr(finding, attribute, redactor.redact_text(value))
        finding.metadata = redactor.redact_value(finding.metadata)
        return self.store.associate(record.id, finding)

    def record_legacy_finding(self, finding: Finding) -> Evidence:
        """Wrap legacy textual Finding evidence in the unified safe model."""
        context = AnalysisContext(
            request_url=finding.endpoint,
            target=finding.target,
        )
        return self.record(
            context,
            finding,
            analyzer="legacy",
            source="legacy_finding",
            evidence=finding.evidence,
            description=finding.description,
            parameter=finding.parameter,
        )
