"""Stable semantic identity shared by Finding conversion and aggregation."""

from typing import Any

from m_hunter.core.finding import Finding


_HEADER_SEMANTICS = {
    "missing x-content-type-options header": "x-content-type-options-missing",
    "x-content-type-options header missing": "x-content-type-options-missing",
    "x_content_type_options_missing": "x-content-type-options-missing",
    "nosniff_missing": "x-content-type-options-nosniff-invalid-or-missing",
}


def finding_semantic_identity(finding: Finding) -> tuple[str, str]:
    """Prefer a validated candidate indicator; otherwise use a stable title.

    Analyzer names are deliberately excluded: independent components can report
    the same vulnerability. Candidate indicators identify the validated rule
    semantics and are already carried in Finding metadata by the adapter.
    """
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    validation = metadata.get("validation", {})
    candidate = validation.get("candidate", {}) if isinstance(validation, dict) else {}
    if not isinstance(candidate, dict):
        candidate = {}

    for name in ("indicator", "semantic_type", "finding_type", "vulnerability_type"):
        value = candidate.get(name)
        if value is None:
            continue
        normalized = str(value).casefold().strip()
        canonical = _HEADER_SEMANTICS.get(normalized)
        if canonical == "x-content-type-options-missing":
            return ("title", canonical)
        return ("semantic", canonical or normalized)

    title = " ".join(finding.title.casefold().split())
    return ("title", _HEADER_SEMANTICS.get(title, title))


def finding_deduplication_key(finding: Finding) -> tuple[Any, ...]:
    """Build a conservative key without normalizing meaningful URL details."""
    return (
        finding_semantic_identity(finding),
        finding.target,
        finding.endpoint or "",
        finding.parameter or "",
        (finding.cwe or "").casefold(),
        finding.evidence,
    )
