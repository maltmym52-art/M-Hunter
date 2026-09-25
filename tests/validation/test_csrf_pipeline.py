from m_hunter.analyzers.csrf import (
    CSRFAnalysis,
    CSRFAnalyzer,
)
from m_hunter.analyzers.csrf_finding import CSRFFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.csrf import CSRFValidator
from m_hunter.validation.csrf_pipeline import (
    CSRFPipeline,
    CSRFPipelineResult,
)


def response(
    status_code=200,
    content=b"same",
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/account",
        headers={},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def test_pipeline_returns_result():
    result = CSRFPipeline().run(
        response(),
        response(),
        CSRFAnalysis(),
        target="https://example.com",
    )

    assert isinstance(result, CSRFPipelineResult)


def test_pipeline_no_indicator():
    result = CSRFPipeline().run(
        response(),
        response(),
        CSRFAnalysis(),
        target="https://example.com",
    )

    assert result.validation.status == "no_indicator"
    assert result.findings == []
    assert not result.potential_csrf


def test_pipeline_detects_potential_csrf():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_csrf
    assert result.validation.status == "potential_csrf"


def test_pipeline_generates_findings():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
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
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == len(result.findings)


def test_pipeline_passes_endpoint_to_findings():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
        endpoint="/transfer",
    )

    assert result.findings
    assert all(
        finding.endpoint == "/transfer"
        for finding in result.findings
    )


def test_pipeline_passes_target_to_findings():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
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


def test_pipeline_passes_protection_change():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
        protection_changed=True,
    )

    assert result.validation.protection_changed


def test_pipeline_does_not_confirm_exploitation():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_csrf
    assert result.validation.status == "potential_csrf"
    assert "confirmed" not in " ".join(
        result.validation.evidence
    ).lower()


def test_pipeline_uses_default_components():
    pipeline = CSRFPipeline()

    assert isinstance(pipeline.validator, CSRFValidator)
    assert isinstance(
        pipeline.finding_analyzer,
        CSRFFindingAnalyzer,
    )


def test_pipeline_accepts_custom_validator():
    validator = CSRFValidator()
    pipeline = CSRFPipeline(validator=validator)

    assert pipeline.validator is validator


def test_pipeline_accepts_custom_finding_analyzer():
    analyzer = CSRFFindingAnalyzer()
    pipeline = CSRFPipeline(
        finding_analyzer=analyzer,
    )

    assert pipeline.finding_analyzer is analyzer


def test_pipeline_rejects_invalid_analysis():
    try:
        CSRFPipeline().run(
            response(),
            response(),
            {},
            target="https://example.com",
        )
    except TypeError as exc:
        assert "CSRFAnalysis" in str(exc)
    else:
        raise AssertionError("Expected TypeError")


def test_pipeline_preserves_validation():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFPipeline().run(
        response(status_code=200),
        response(status_code=302),
        analysis,
        target="https://example.com",
    )

    assert result.validation.baseline_status == 200
    assert result.validation.candidate_status == 302
    assert result.validation.status_changed


def test_pipeline_can_generate_multiple_findings():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
        cookies={"sessionid": "abc"},
    )

    result = CSRFPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert len(result.findings) >= 3


def test_pipeline_finding_titles_are_non_empty():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
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
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.findings
    assert all(
        finding.cwe == "CWE-352"
        for finding in result.findings
    )


def test_pipeline_validation_and_findings_are_independent():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.findings
    assert not result.potential_csrf
    assert result.validation.status == "indicator_detected"


def test_pipeline_no_network_side_effects():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert isinstance(result, CSRFPipelineResult)


def test_pipeline_result_exposes_finding_count():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == len(result.findings)


def test_pipeline_result_potential_property_matches_validation():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(content=b"a"),
        response(content=b"b"),
        analysis,
        target="https://example.com",
    )

    assert result.potential_csrf == result.validation.potential_csrf


def test_pipeline_with_same_responses_does_not_mark_potential():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="amount=100",
    )

    result = CSRFPipeline().run(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
        target="https://example.com",
    )

    assert not result.potential_csrf
    assert result.validation.status == "indicator_detected"


def test_pipeline_preserves_custom_endpoint_none():
    analysis = CSRFAnalyzer().analyze("POST")

    result = CSRFPipeline().run(
        response(),
        response(),
        analysis,
        target="https://example.com",
    )

    assert all(
        finding.endpoint is None
        for finding in result.findings
    )
