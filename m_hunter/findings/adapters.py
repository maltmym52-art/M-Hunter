"""Compatibility adapters for legacy Finding factories and pipelines."""

from collections.abc import Iterable
from typing import Any

from m_hunter.core.finding import Finding
from m_hunter.findings.converter import FindingConverter
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.evidence.service import EvidenceService


class LegacyFindingAdapter:
    """Normalize legacy finding or pipeline outputs to ``core.Finding``.

    Existing pipeline APIs remain unchanged; callers can pass their returned
    finding list or a result object exposing a ``findings`` collection here.
    """

    @staticmethod
    def to_core(value: Any) -> Finding:
        if isinstance(value, Finding):
            return value

        required = ("title", "severity", "confidence", "target")
        missing = [name for name in required if not hasattr(value, name)]
        if missing:
            raise TypeError(
                "legacy finding is missing required fields: "
                + ", ".join(missing)
            )

        fields = {
            name: getattr(value, name, default)
            for name, default in (
                ("title", ""),
                ("severity", ""),
                ("confidence", ""),
                ("target", ""),
                ("id", None),
                ("endpoint", None),
                ("parameter", None),
                ("description", ""),
                ("evidence", ""),
                ("remediation", ""),
                ("cwe", None),
                ("owasp", None),
                ("status", "open"),
                ("created_at", None),
                ("updated_at", None),
                ("metadata", {}),
            )
        }
        fields = {
            name: value
            for name, value in fields.items()
            if value is not None
        }
        fields["metadata"] = dict(fields.get("metadata", {}))
        return FindingConverter.create_from_fields(**fields)

    @classmethod
    def from_pipeline_output(
        cls,
        output: Any,
        *,
        evidence_service: EvidenceService | None = None,
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Adapt a legacy pipeline result or iterable of findings."""
        values = getattr(output, "findings", output)
        if isinstance(values, Finding):
            values = [values]
        if not isinstance(values, Iterable) or isinstance(values, (str, bytes)):
            raise TypeError(
                "legacy pipeline output must contain an iterable of findings"
            )
        findings = [cls.to_core(value) for value in values]
        if evidence_service is not None:
            for finding in findings:
                if context is not None:
                    evidence_service.record(
                        context,
                        finding,
                        analyzer="legacy",
                        source="legacy_pipeline",
                        evidence=finding.evidence,
                        description=finding.description,
                        parameter=finding.parameter,
                    )
                else:
                    evidence_service.record_legacy_finding(finding)
        return findings
