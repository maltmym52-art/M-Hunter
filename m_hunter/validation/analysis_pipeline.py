"""Connect semantic analysis validation to canonical Finding creation."""

from dataclasses import dataclass
from typing import Protocol

from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.findings.converter import (
    FindingConverter,
    FindingProcessingResult,
    FindingProcessingStatus,
)
from m_hunter.validation.analysis import AnalysisValidation


class AnalysisValidator(Protocol):
    """Validator contract for the unified analysis-to-finding path."""

    def validate(
        self,
        analysis: AnalysisResult,
        context: AnalysisContext,
    ) -> AnalysisValidation:
        """Classify analysis and optionally describe a supported finding."""


@dataclass
class AnalysisFindingPipeline:
    """Apply semantic validation, structural validation, and conversion."""

    converter: FindingConverter

    def __init__(self, converter: FindingConverter | None = None) -> None:
        self.converter = converter or FindingConverter()

    def process(
        self,
        analysis: AnalysisResult,
        context: AnalysisContext,
        validator: AnalysisValidator,
    ) -> FindingProcessingResult:
        if not isinstance(analysis, AnalysisResult):
            return FindingProcessingResult(
                FindingProcessingStatus.INVALID,
                errors=("analysis must be an AnalysisResult",),
            )
        if analysis.data is None:
            return FindingProcessingResult(
                FindingProcessingStatus.INVALID,
                errors=("analysis data is incomplete",),
            )

        try:
            decision = validator.validate(analysis, context)
        except Exception as exc:
            return FindingProcessingResult(
                FindingProcessingStatus.VALIDATION_FAILED,
                errors=(f"validator failed: {exc}",),
            )

        if not isinstance(decision, AnalysisValidation):
            return FindingProcessingResult(
                FindingProcessingStatus.VALIDATION_FAILED,
                errors=(
                    "validator must return an AnalysisValidation",
                ),
            )

        return self.converter.convert(analysis, decision, context)
