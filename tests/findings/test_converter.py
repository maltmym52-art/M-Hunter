from dataclasses import dataclass, field

from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.finding import Finding
from m_hunter.findings.adapters import LegacyFindingAdapter
from m_hunter.findings.converter import (
    FindingConverter,
    FindingProcessingStatus,
)
from m_hunter.validation.analysis import (
    AnalysisValidation,
    FindingCandidate,
)


def make_inputs(**candidate_fields):
    analysis = AnalysisResult(
        analyzer_name="example",
        data={"signals": ["s1"]},
        metadata={"source": "header", "request_id": "req-1"},
        errors=["non-blocking analyzer note"],
    )
    candidate_data = {
        "title": "Header issue",
        "severity": "Medium",
        "confidence": "High",
        "evidence": "Header-Example was absent",
    }
    candidate_data.update(candidate_fields)
    candidate = FindingCandidate(**candidate_data)
    context = AnalysisContext(
        target="https://example.com",
        metadata={"scan_id": "scan-1"},
    )
    return analysis, AnalysisValidation.finding(candidate), context


def test_converter_preserves_finding_data_and_metadata():
    analysis, validation, context = make_inputs(
        endpoint="https://example.com/",
        parameter="id",
        description="Validated issue",
        remediation="Set the header",
        cwe="CWE-693",
        owasp="A05:2021",
        metadata={"validator_rule": "missing-header"},
    )
    validation = AnalysisValidation.finding(
        validation.candidate,
        metadata={"confidence_reason": "direct response evidence"},
    )

    result = FindingConverter().convert(analysis, validation, context)

    assert result.status == FindingProcessingStatus.CREATED
    finding = result.finding
    assert isinstance(finding, Finding)
    assert finding.title == "Header issue"
    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.target == "https://example.com"
    assert finding.endpoint == "https://example.com/"
    assert finding.parameter == "id"
    assert finding.description == "Validated issue"
    assert finding.evidence == "Header-Example was absent"
    assert finding.remediation == "Set the header"
    assert finding.cwe == "CWE-693"
    assert finding.owasp == "A05:2021"
    assert finding.status == "open"
    assert finding.metadata["analysis"]["metadata"] == analysis.metadata
    assert finding.metadata["analysis"]["errors"] == analysis.errors
    assert finding.metadata["context"]["metadata"] == {
        "scan_id": "scan-1"
    }
    assert finding.metadata["validation"]["metadata"] == {
        "confidence_reason": "direct response evidence"
    }
    assert finding.metadata["validation"]["candidate"] == {
        "validator_rule": "missing-header"
    }


def test_converter_uses_target_from_response_when_context_target_absent():
    analysis, validation, _ = make_inputs()
    context = AnalysisContext(
        response=type(
            "ResponseStub",
            (),
            {"url": "https://response.example/"},
        )()
    )

    result = FindingConverter().convert(analysis, validation, context)

    assert result.finding.target == "https://response.example/"


def test_informational_validation_does_not_create_finding():
    analysis, _, context = make_inputs()

    result = FindingConverter().convert(
        analysis,
        AnalysisValidation.informational(),
        context,
    )

    assert result.status == FindingProcessingStatus.INFORMATIONAL
    assert result.finding is None


def test_invalid_validation_does_not_create_finding():
    analysis, _, context = make_inputs()

    result = FindingConverter().convert(
        analysis,
        AnalysisValidation.invalid("insufficient evidence"),
        context,
    )

    assert result.status == FindingProcessingStatus.INVALID
    assert result.errors == ("insufficient evidence",)


def test_incomplete_candidate_reports_missing_required_values():
    analysis = AnalysisResult(analyzer_name="example", data={"signal": True})
    validation = AnalysisValidation.finding(
        FindingCandidate(severity="Medium", confidence="High")
    )

    result = FindingConverter().convert(
        analysis,
        validation,
        AnalysisContext(),
    )

    assert result.status == FindingProcessingStatus.INVALID
    assert result.finding is None
    assert result.errors == (
        "title is required to create a finding",
        "target is required to create a finding",
        "evidence is required to create a finding",
    )


def test_unknown_severity_is_rejected_by_structural_validator():
    analysis, validation, context = make_inputs(severity="Urgent")

    result = FindingConverter().convert(analysis, validation, context)

    assert result.status == FindingProcessingStatus.VALIDATION_FAILED
    assert result.errors == ("invalid severity: Urgent",)


def test_unknown_confidence_is_rejected_by_structural_validator():
    analysis, validation, context = make_inputs(confidence="Certain")

    result = FindingConverter().convert(analysis, validation, context)

    assert result.status == FindingProcessingStatus.VALIDATION_FAILED
    assert result.errors == ("invalid confidence: Certain",)


def test_duplicate_finding_is_suppressed():
    analysis, validation, context = make_inputs()
    converter = FindingConverter()

    first = converter.convert(analysis, validation, context)
    second = converter.convert(analysis, validation, context)

    assert first.status == FindingProcessingStatus.CREATED
    assert second.status == FindingProcessingStatus.DUPLICATE
    assert second.finding is not None


def test_legacy_finding_adapter_preserves_canonical_finding_identity():
    finding = Finding(
        title="Legacy",
        severity="Low",
        confidence="High",
        target="https://example.com",
    )

    assert LegacyFindingAdapter.to_core(finding) is finding


@dataclass
class LegacyFindingLike:
    title: str = "Old finding"
    severity: str = "Low"
    confidence: str = "Medium"
    target: str = "https://example.com"
    evidence: str = "legacy evidence"
    metadata: dict = field(default_factory=dict)


def test_legacy_finding_adapter_normalizes_legacy_shape():
    adapted = LegacyFindingAdapter.to_core(LegacyFindingLike())

    assert isinstance(adapted, Finding)
    assert adapted.title == "Old finding"
    assert adapted.evidence == "legacy evidence"
    assert adapted.metadata == {}


def test_legacy_finding_adapter_accepts_pipeline_result_without_changing_it():
    finding = Finding(
        title="Legacy pipeline result",
        severity="Low",
        confidence="High",
        target="https://example.com",
    )

    class OldPipelineResult:
        findings = (finding,)

    adapted = LegacyFindingAdapter.from_pipeline_output(OldPipelineResult())

    assert adapted == [finding]
    assert adapted[0] is finding
