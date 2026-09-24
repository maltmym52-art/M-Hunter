from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.finding import FindingValidator
from m_hunter.validation.pipeline import (
    FindingPipeline,
    PipelineResult,
)


def make_pipeline():
    return FindingPipeline(
        finding_analyzer=FindingAnalyzer(),
        validator=FindingValidator(),
    )


def valid_analysis():
    return {
        "detected": True,
        "evidence": "Test evidence",
    }


def test_pipeline_result_defaults():
    result = PipelineResult()

    assert result.findings == []
    assert result.rejected == []
    assert result.errors == []
    assert result.valid_count == 0
    assert result.rejected_count == 0


def test_pipeline_can_be_created():
    pipeline = FindingPipeline()

    assert isinstance(pipeline, FindingPipeline)


def test_pipeline_accepts_custom_components():
    finding_analyzer = FindingAnalyzer()
    validator = FindingValidator()

    pipeline = FindingPipeline(
        finding_analyzer=finding_analyzer,
        validator=validator,
    )

    assert pipeline.finding_analyzer is finding_analyzer
    assert pipeline.validator is validator


def test_process_returns_pipeline_result():
    pipeline = make_pipeline()

    result = pipeline.process(
        analysis=valid_analysis(),
        title="Test Finding",
        severity="Medium",
        confidence="High",
        target="https://example.com",
        evidence="Evidence",
    )

    assert isinstance(result, PipelineResult)


def test_process_returns_valid_finding():
    pipeline = make_pipeline()

    result = pipeline.process(
        analysis=valid_analysis(),
        title="Test Finding",
        severity="Medium",
        confidence="High",
        target="https://example.com",
        evidence="Evidence",
    )

    assert result.valid_count == 1
    assert result.rejected_count == 0
    assert result.errors == []

    assert isinstance(
        result.findings[0],
        Finding,
    )


def test_process_preserves_finding_metadata():
    pipeline = make_pipeline()

    result = pipeline.process(
        analysis=valid_analysis(),
        title="Security Issue",
        severity="High",
        confidence="High",
        target="https://example.com",
        endpoint="https://example.com/login",
        parameter="id",
        description="Test description",
        evidence="Test evidence",
        remediation="Fix the issue",
        cwe="CWE-79",
        owasp="A03:2021",
    )

    finding = result.findings[0]

    assert finding.title == "Security Issue"
    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.target == "https://example.com"
    assert finding.endpoint == "https://example.com/login"
    assert finding.parameter == "id"
    assert finding.description == "Test description"
    assert finding.evidence == "Test evidence"
    assert finding.remediation == "Fix the issue"
    assert finding.cwe == "CWE-79"
    assert finding.owasp == "A03:2021"


def test_process_rejects_invalid_finding():
    pipeline = make_pipeline()

    result = pipeline.process(
        analysis=valid_analysis(),
        title="",
        severity="Medium",
        confidence="High",
        target="https://example.com",
        evidence="Evidence",
    )

    assert result.valid_count == 0
    assert result.rejected_count == 1
    assert "title must not be empty" in result.errors


def test_process_rejects_invalid_severity():
    pipeline = make_pipeline()

    result = pipeline.process(
        analysis=valid_analysis(),
        title="Test",
        severity="Invalid",
        confidence="High",
        target="https://example.com",
        evidence="Evidence",
    )

    assert result.valid_count == 0
    assert result.rejected_count == 1
    assert "invalid severity: Invalid" in result.errors


def test_process_rejects_invalid_confidence():
    pipeline = make_pipeline()

    result = pipeline.process(
        analysis=valid_analysis(),
        title="Test",
        severity="Medium",
        confidence="Invalid",
        target="https://example.com",
        evidence="Evidence",
    )

    assert result.valid_count == 0
    assert result.rejected_count == 1
    assert "invalid confidence: Invalid" in result.errors


def test_process_returns_empty_result_for_empty_analysis():
    pipeline = make_pipeline()

    result = pipeline.process(
        analysis={},
        title="Test",
        severity="Medium",
        confidence="High",
        target="https://example.com",
        evidence="Evidence",
    )

    assert result.valid_count == 0
    assert result.rejected_count == 0
    assert result.errors == []


def test_process_many_processes_multiple_analyses():
    pipeline = make_pipeline()

    analyses = [
        {"issue": "first"},
        {"issue": "second"},
        {"issue": "third"},
    ]

    result = pipeline.process_many(
        analyses,
        title="Detected Issue",
        severity="Low",
        confidence="High",
        target="https://example.com",
        evidence="Evidence",
    )

    assert result.valid_count == 3
    assert result.rejected_count == 0
    assert len(result.findings) == 3


def test_process_many_preserves_order():
    pipeline = make_pipeline()

    analyses = [
        {"index": 1},
        {"index": 2},
        {"index": 3},
    ]

    result = pipeline.process_many(
        analyses,
        title="Issue",
        severity="Low",
        confidence="High",
        target="https://example.com",
        evidence="Evidence",
    )

    assert len(result.findings) == 3

    assert [
        finding.id
        for finding in result.findings
    ] != [
        result.findings[1].id,
        result.findings[2].id,
        result.findings[0].id,
    ]


def test_process_many_collects_rejected_findings():
    pipeline = make_pipeline()

    result = pipeline.process_many(
        [
            {"issue": "valid"},
            {"issue": "invalid"},
        ],
        title="Issue",
        severity="Invalid",
        confidence="High",
        target="https://example.com",
        evidence="Evidence",
    )

    assert result.valid_count == 0
    assert result.rejected_count == 2
    assert len(result.errors) == 2


def test_pipeline_instances_are_independent():
    first = FindingPipeline()
    second = FindingPipeline()

    assert first.finding_analyzer is not second.finding_analyzer
    assert first.validator is not second.validator
