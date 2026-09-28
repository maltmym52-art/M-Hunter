from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.engine import ScanEngine
from m_hunter.core.finding import Finding
from m_hunter.findings.converter import (
    FindingProcessingStatus,
)
from m_hunter.validation.analysis import (
    AnalysisValidation,
    FindingCandidate,
)
from m_hunter.validation.analysis_pipeline import AnalysisFindingPipeline


class FindingValidatorStub:
    def validate(self, analysis, context):
        return AnalysisValidation.finding(
            FindingCandidate(
                title="Validated issue",
                severity="High",
                confidence="Medium",
                endpoint=context.request_url,
                evidence=analysis.data["evidence"],
                metadata={"rule": "test"},
            )
        )


class InformationalValidatorStub:
    def validate(self, analysis, context):
        return AnalysisValidation.informational()


class InvalidValidatorStub:
    def validate(self, analysis, context):
        return AnalysisValidation.invalid("validator rejected signal")


class BrokenValidatorStub:
    def validate(self, analysis, context):
        raise RuntimeError("validation backend unavailable")


_DEFAULT_DATA = object()


def make_analysis(data=_DEFAULT_DATA):
    return AnalysisResult(
        analyzer_name="test-analyzer",
        data=(
            {"evidence": "observed response marker"}
            if data is _DEFAULT_DATA
            else data
        ),
        metadata={"response_status": 200},
    )


def test_analysis_finding_pipeline_creates_core_finding():
    result = AnalysisFindingPipeline().process(
        make_analysis(),
        AnalysisContext(
            target="https://example.com",
            request_url="https://example.com/item?id=4",
        ),
        FindingValidatorStub(),
    )

    assert result.status == FindingProcessingStatus.CREATED
    assert isinstance(result.finding, Finding)
    assert result.finding.target == "https://example.com"
    assert result.finding.endpoint == "https://example.com/item?id=4"
    assert result.finding.metadata["analysis"]["analyzer_name"] == (
        "test-analyzer"
    )


def test_analysis_finding_pipeline_keeps_informational_result_non_finding():
    result = AnalysisFindingPipeline().process(
        make_analysis(),
        AnalysisContext(target="https://example.com"),
        InformationalValidatorStub(),
    )

    assert result.status == FindingProcessingStatus.INFORMATIONAL
    assert result.finding is None


def test_analysis_finding_pipeline_preserves_explicit_invalid_decision():
    result = AnalysisFindingPipeline().process(
        make_analysis(),
        AnalysisContext(target="https://example.com"),
        InvalidValidatorStub(),
    )

    assert result.status == FindingProcessingStatus.INVALID
    assert result.errors == ("validator rejected signal",)


def test_analysis_finding_pipeline_handles_validator_exception():
    result = AnalysisFindingPipeline().process(
        make_analysis(),
        AnalysisContext(target="https://example.com"),
        BrokenValidatorStub(),
    )

    assert result.status == FindingProcessingStatus.VALIDATION_FAILED
    assert result.errors == (
        "validator failed: validation backend unavailable",
    )


def test_analysis_finding_pipeline_rejects_incomplete_analysis():
    result = AnalysisFindingPipeline().process(
        make_analysis(data=None),
        AnalysisContext(target="https://example.com"),
        FindingValidatorStub(),
    )

    assert result.status == FindingProcessingStatus.INVALID
    assert result.errors == ("analysis data is incomplete",)


def test_scan_engine_exposes_analysis_validation_path():
    engine = ScanEngine(auto_discover=False)

    result = engine.validate_analysis(
        make_analysis(),
        AnalysisContext(target="https://example.com"),
        FindingValidatorStub(),
    )

    assert result.status == FindingProcessingStatus.CREATED
    assert isinstance(result.finding, Finding)
