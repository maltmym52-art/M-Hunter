"""Convert validated analysis into the canonical ``core.Finding`` model."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.finding import Finding
from m_hunter.validation.analysis import (
    AnalysisDisposition,
    AnalysisValidation,
)
from m_hunter.validation.finding import FindingValidator


class FindingProcessingStatus(str, Enum):
    CREATED = "created"
    INFORMATIONAL = "informational"
    INVALID = "invalid"
    DUPLICATE = "duplicate"
    VALIDATION_FAILED = "validation_failed"


@dataclass(frozen=True)
class FindingProcessingResult:
    """Outcome of validating and converting one analysis result."""

    status: FindingProcessingStatus
    finding: Finding | None = None
    errors: tuple[str, ...] = field(default_factory=tuple)


class FindingConverter:
    """Central construction point for findings derived from analysis."""

    def __init__(self, validator: FindingValidator | None = None) -> None:
        self.validator = validator or FindingValidator()
        self._seen: set[tuple[Any, ...]] = set()

    @staticmethod
    def create_from_fields(**fields: Any) -> Finding:
        """Create the canonical Finding for legacy factory compatibility."""
        return Finding(**fields)

    def convert(
        self,
        analysis: AnalysisResult,
        validation: AnalysisValidation,
        context: AnalysisContext,
    ) -> FindingProcessingResult:
        """Validate a decision and create a Finding only when warranted."""
        if not isinstance(analysis, AnalysisResult):
            return FindingProcessingResult(
                FindingProcessingStatus.INVALID,
                errors=("analysis must be an AnalysisResult",),
            )
        if not isinstance(validation, AnalysisValidation):
            return FindingProcessingResult(
                FindingProcessingStatus.INVALID,
                errors=("validation must be an AnalysisValidation",),
            )
        if not isinstance(context, AnalysisContext):
            return FindingProcessingResult(
                FindingProcessingStatus.INVALID,
                errors=("context must be an AnalysisContext",),
            )

        if validation.disposition == AnalysisDisposition.INFORMATIONAL:
            return FindingProcessingResult(
                FindingProcessingStatus.INFORMATIONAL,
                errors=validation.errors,
            )
        if validation.disposition == AnalysisDisposition.INVALID:
            return FindingProcessingResult(
                FindingProcessingStatus.INVALID,
                errors=validation.errors or ("analysis was rejected",),
            )
        if validation.errors:
            return FindingProcessingResult(
                FindingProcessingStatus.VALIDATION_FAILED,
                errors=validation.errors,
            )

        candidate = validation.candidate
        if candidate is None:
            return FindingProcessingResult(
                FindingProcessingStatus.INVALID,
                errors=("finding decision is missing its candidate",),
            )

        target = candidate.target or self._target_value(context)
        missing = [
            name
            for name, value in (
                ("title", candidate.title),
                ("severity", candidate.severity),
                ("confidence", candidate.confidence),
                ("target", target),
                ("evidence", candidate.evidence),
            )
            if not isinstance(value, str) or not value.strip()
        ]
        if missing:
            return FindingProcessingResult(
                FindingProcessingStatus.INVALID,
                errors=tuple(
                    f"{name} is required to create a finding"
                    for name in missing
                ),
            )

        combined_metadata = {
            "analysis": {
                "analyzer_name": analysis.analyzer_name,
                "status": analysis.status,
                "metadata": dict(analysis.metadata),
                "errors": list(analysis.errors),
            },
            "context": {
                "metadata": dict(context.metadata),
            },
            "validation": {
                "metadata": dict(validation.metadata),
                "candidate": dict(candidate.metadata),
            },
        }
        finding = Finding(
            title=candidate.title,
            severity=candidate.severity,
            confidence=candidate.confidence,
            target=target,
            endpoint=candidate.endpoint,
            parameter=candidate.parameter,
            description=candidate.description,
            evidence=candidate.evidence,
            remediation=candidate.remediation,
            cwe=candidate.cwe,
            owasp=candidate.owasp,
            status=candidate.status,
            metadata=combined_metadata,
        )

        structural_validation = self.validator.validate(finding)
        if not structural_validation.valid:
            return FindingProcessingResult(
                FindingProcessingStatus.VALIDATION_FAILED,
                finding=finding,
                errors=tuple(structural_validation.errors),
            )

        key = self._deduplication_key(finding)
        if key in self._seen:
            return FindingProcessingResult(
                FindingProcessingStatus.DUPLICATE,
                errors=("duplicate finding",),
            )

        self._seen.add(key)
        return FindingProcessingResult(
            FindingProcessingStatus.CREATED,
            finding=finding,
        )

    @staticmethod
    def _target_value(context: AnalysisContext) -> str | None:
        target = context.target
        if isinstance(target, str):
            return target
        if target is not None:
            return target.url
        if context.response is not None:
            return context.response.url
        if context.request is not None:
            return context.request.url
        return None

    @staticmethod
    def _deduplication_key(finding: Finding) -> tuple[Any, ...]:
        return (
            finding.title.casefold(),
            finding.target.casefold(),
            (finding.endpoint or "").casefold(),
            (finding.parameter or "").casefold(),
            finding.evidence,
        )
