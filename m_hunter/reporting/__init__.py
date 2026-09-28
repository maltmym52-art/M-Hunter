"""Scan result normalization and offline report rendering."""

from m_hunter.reporting.model import REPORT_SCHEMA, REPORT_SCHEMA_VERSION, ReportModel
from m_hunter.reporting.normalize import ReportNormalizer, to_json_value
from m_hunter.reporting.renderers import HTMLRenderer, JSONRenderer, MarkdownRenderer
from m_hunter.reporting.service import ReportError, ReportOutputError, ReportService

__all__ = [
    "HTMLRenderer", "JSONRenderer", "MarkdownRenderer", "REPORT_SCHEMA",
    "REPORT_SCHEMA_VERSION", "ReportError", "ReportModel", "ReportNormalizer",
    "ReportOutputError", "ReportService", "to_json_value",
]
