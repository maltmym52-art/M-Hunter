"""Public reporting service and safe persistence helpers."""

import json
import os
from pathlib import Path
import tempfile
from typing import Literal

from m_hunter.application.models import ScanExecutionResult
from m_hunter.evidence.service import EvidenceService
from m_hunter.reporting.model import ReportModel
from m_hunter.reporting.normalize import ReportNormalizer
from m_hunter.reporting.renderers import HTMLRenderer, JSONRenderer, MarkdownRenderer


ReportFormat = Literal["json", "markdown", "html"]


class ReportError(Exception):
    """Base reporting error suitable for CLI presentation."""


class ReportOutputError(ReportError):
    """Filesystem error while saving a report."""


class ReportService:
    """Normalize, render, load, and safely persist scan reports."""

    def __init__(self, normalizer: ReportNormalizer | None = None) -> None:
        self.normalizer = normalizer or ReportNormalizer()
        self.renderers = {
            "json": JSONRenderer(),
            "markdown": MarkdownRenderer(),
            "html": HTMLRenderer(),
        }

    def build(self, result: ScanExecutionResult,
              evidence_service: EvidenceService | None = None) -> ReportModel:
        return self.normalizer.normalize(result, evidence_service)

    def render(self, report: ReportModel, format: ReportFormat | str) -> str:
        try:
            renderer = self.renderers[format.lower()]
        except (AttributeError, KeyError) as exc:
            raise ValueError(f"unsupported report format: {format}") from exc
        return renderer.render(report)

    def load(self, path: str | Path) -> ReportModel:
        """Read a versioned JSON report document; never unpickle input."""
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
            # Stage 5 emitted a flat scan-result JSON shape. Keep those saved
            # artifacts readable while all newly written files use v1 reports.
            if isinstance(value, dict) and value.get("schema") != "m-hunter-report":
                value = self._migrate_legacy_scan_result(value)
            return ReportModel.from_dict(value)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ReportError(f"cannot read report input: {exc}") from exc

    @staticmethod
    def _migrate_legacy_scan_result(value: dict) -> dict:
        if "state" not in value or "target" not in value:
            return value
        scan = {
            "id": str(value.get("scan_id", "legacy-import")),
            "status": str(value.get("state", "unknown")),
            "started_at": value.get("started_at"),
            "finished_at": value.get("finished_at"),
            "duration_seconds": value.get("duration", 0),
        }
        findings = []
        for finding in value.get("findings", []):
            if not isinstance(finding, dict):
                continue
            findings.append({
                "id": finding.get("id", ""), "title": finding.get("title", "Untitled"),
                "severity": finding.get("severity", "unknown"),
                "confidence": finding.get("confidence", "unknown"),
                "target": finding.get("target", value["target"]),
                "endpoint": finding.get("endpoint"), "parameter": finding.get("parameter"),
                "description": finding.get("description", ""),
                "remediation": finding.get("remediation", ""),
                "cwe": finding.get("cwe"), "owasp": finding.get("owasp"),
                "status": finding.get("status", "open"),
                "metadata": finding.get("metadata", {}),
                "evidence_refs": finding.get("evidence_ids", []),
                "evidence": finding.get("evidence_records", []),
            })
        return {
            "schema": "m-hunter-report", "schema_version": "1.0",
            "scan": scan, "target": value["target"],
            "scope": {"in_scope": None},
            "authorization": {"active_enabled": False, "granted": False,
                              "reference_present": False},
            "assets": value.get("assets", []), "findings": findings,
            "errors": value.get("errors", []), "statistics": value.get("statistics", {}),
            "metadata": {},
        }

    def write(self, report: ReportModel, format: ReportFormat | str,
              path: str | Path, *, overwrite: bool = False) -> Path:
        """Save UTF-8 report data, creating parent directories safely.

        Existing files are refused unless ``overwrite`` is explicitly true.
        A sibling temporary file plus atomic replacement is used for overwrite.
        """
        destination = Path(path)
        text = self.render(report, format)
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not overwrite:
                with destination.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(text)
                return destination
            handle, temporary = tempfile.mkstemp(prefix=f".{destination.name}.",
                                                  suffix=".tmp", dir=destination.parent)
            try:
                with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                    stream.write(text)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, destination)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            return destination
        except OSError as exc:
            raise ReportOutputError(f"cannot write report to {destination}: {exc}") from exc
