import pytest

from m_hunter.analyzers.ssti import (
    SSTIAnalysis,
    SSTIAnalyzer,
)
from m_hunter.analyzers.ssti_finding import SSTIFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.ssti import SSTIValidator
from m_hunter.validation.ssti_pipeline import (
    SSTIPipeline,
    SSTIPipelineResult,
)


def response(
    status_code=200,
    content=b"same",
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/render",
        headers={},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def test_pipeline_returns_result():
    result = SSTIPipeline().run(
        response(),
        response(),
        SSTIAnalysis(),
        target="https://example.com",
    )

    assert isinstance(result, SSTIPipelineResult)


def test_pipeline_no_indicator():
    result = SSTIPipeline().run(
        response(),
        response(),
        SSTIAnalysis(),
        target="https://example.com",
    )

    assert result.validation.status == "no_indicator"
    assert result.findings == []
    assert not result.potential_ssti


def test_pipeline_detects_potential_ssti():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_ssti
    assert result.validation.status == "potential_ssti"


def test_pipeline_generates_findings():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.findings
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )


def test_pipeline_finding_count():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == len(result.findings)


def test_pipeline_passes_endpoint_to_findings():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
        endpoint="/render",
    )

    assert result.findings
    assert all(
        finding.endpoint == "/render"
        for finding in result.findings
    )


def test_pipeline_passes_target_to_findings():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://target.example",
    )

    assert result.findings
    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_pipeline_passes_evaluation_evidence():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
        evaluation_evidence=True,
    )

    assert result.validation.evaluation_evidence
    assert result.validation.status == "evaluation_evidence"


def test_pipeline_does_not_infer_evaluation_evidence():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert not result.validation.evaluation_evidence
    assert result.validation.status == "potential_ssti"


def test_pipeline_does_not_confirm_execution():
    analysis = SSTIAnalyzer().analyze(
        "{{ 7 * 7 }}"
    )

    result = SSTIPipeline().run(
        response(content=b"before"),
        response(content=b"49"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_ssti
    assert not result.validation.evaluation_evidence


def test_pipeline_uses_default_components():
    pipeline = SSTIPipeline()

    assert isinstance(pipeline.validator, SSTIValidator)
    assert isinstance(
        pipeline.finding_analyzer,
        SSTIFindingAnalyzer,
    )


def test_pipeline_accepts_custom_validator():
    validator = SSTIValidator()
    pipeline = SSTIPipeline(
        validator=validator,
    )

    assert pipeline.validator is validator


def test_pipeline_accepts_custom_finding_analyzer():
    analyzer = SSTIFindingAnalyzer()
    pipeline = SSTIPipeline(
        finding_analyzer=analyzer,
    )

    assert pipeline.finding_analyzer is analyzer


def test_pipeline_rejects_invalid_analysis():
    with pytest.raises(TypeError):
        SSTIPipeline().run(
            response(),
            response(),
            {},
            target="https://example.com",
        )


def test_pipeline_preserves_validation():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(status_code=200),
        response(status_code=500),
        analysis,
        target="https://example.com",
    )

    assert result.validation.baseline_status == 200
    assert result.validation.candidate_status == 500
    assert result.validation.status_changed


def test_pipeline_can_generate_multiple_findings():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }} UNIQUE",
        marker="UNIQUE",
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert len(result.findings) >= 2


def test_pipeline_finding_titles_are_non_empty():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert all(
        finding.title.strip()
        for finding in result.findings
    )


def test_pipeline_finding_metadata_is_preserved():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.findings
    assert all(
        finding.cwe == "CWE-1336"
        for finding in result.findings
    )


def test_pipeline_validation_and_findings_are_independent():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.findings
    assert not result.potential_ssti
    assert result.validation.status == "indicator_detected"


def test_pipeline_no_network_side_effects():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert isinstance(result, SSTIPipelineResult)


def test_pipeline_result_exposes_finding_count():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == len(result.findings)


def test_pipeline_potential_property_matches_validation():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(content=b"a"),
        response(content=b"b"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_ssti == result.validation.potential_ssti


def test_pipeline_same_responses_do_not_mark_potential():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
        target="https://example.com",
    )

    assert not result.potential_ssti
    assert result.validation.status == "indicator_detected"


def test_pipeline_preserves_none_endpoint():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert all(
        finding.endpoint is None
        for finding in result.findings
    )


def test_pipeline_evaluation_evidence_without_response_change():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
        evaluation_evidence=True,
    )

    assert result.validation.status == "evaluation_evidence"
    assert not result.validation.response_changed


def test_pipeline_returns_validation_evidence():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIPipeline().run(
        response(),
        response(content=b"changed"),
        analysis,
        target="https://example.com",
    )

    assert result.validation.evidence
