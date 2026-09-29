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
from m_hunter.evidence.service import EvidenceService
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
    evidence_service: EvidenceService

    def __init__(
        self,
        converter: FindingConverter | None = None,
        evidence_service: EvidenceService | None = None,
    ) -> None:
        self.converter = converter or FindingConverter()
        self.evidence_service = evidence_service or EvidenceService()

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

        result = self.converter.convert(analysis, decision, context)
        if (
            result.status in {
                FindingProcessingStatus.CREATED,
                FindingProcessingStatus.DUPLICATE,
            }
            and result.finding is not None
        ):
            candidate = decision.candidate
            evidence_context = AnalysisContext(
                response=context.response,
                content=context.content,
                request_url=context.request_url,
                target=context.target,
                request=context.request,
                options=context.options,
                metadata={
                    **dict(context.metadata),
                    "analysis": dict(analysis.metadata),
                    "validation": dict(decision.metadata),
                },
            )
            self.evidence_service.record(
                evidence_context,
                result.finding,
                analyzer=analysis.analyzer_name,
                source="analysis_validation",
                evidence=(candidate.evidence if candidate else ""),
                description=(candidate.description if candidate else ""),
                parameter=(candidate.parameter if candidate else None),
            )
        return result

    def process_many(self, analysis: AnalysisResult, context: AnalysisContext,
                     validator: AnalysisValidator) -> list[FindingProcessingResult]:
        """Process all decisions from a legacy indicator validator, if present."""
        validate_many = getattr(validator, "validate_many", None)
        if not callable(validate_many):
            return [self.process(analysis, context, validator)]
        try:
            decisions = validate_many(analysis, context)
        except Exception as exc:
            return [FindingProcessingResult(
                FindingProcessingStatus.VALIDATION_FAILED,
                errors=(f"validator failed: {exc}",),
            )]

        results = []
        for decision in decisions:
            class _FixedDecision:
                def validate(self, _analysis, _context):
                    return decision
            results.append(self.process(analysis, context, _FixedDecision()))
        return results
