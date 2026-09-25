from m_hunter.analyzers.request_smuggling import (
    RequestSmugglingAnalysis,
    SmugglingIndicator,
    SmugglingIndicatorType,
    SmugglingType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.request_smuggling_pipeline import (
    RequestSmugglingPipeline,
)


def make_response(
    *,
    status_code: int = 200,
    content: bytes = b"same",
    content_length: int | None = None,
) -> HttpResponse:
    if content_length is None:
        content_length = len(content)

    return HttpResponse(
        status_code=status_code,
        url="https://example.com/",
        headers={"Content-Type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=content_length,
    )


def make_analysis(
    *,
    detected: bool = True,
    indicator_type: SmugglingIndicatorType = (
        SmugglingIndicatorType.CONFLICTING_FRAMING
    ),
) -> RequestSmugglingAnalysis:
    indicator = SmugglingIndicator(
        type=indicator_type,
        evidence="Test smuggling indicator",
        smuggling_type=SmugglingType.CL_TE,
    )

    return RequestSmugglingAnalysis(
        detected=detected,
        indicator_count=1 if detected else 0,
        smuggling_types=(
            [SmugglingType.CL_TE] if detected else []
        ),
        types=[indicator_type] if detected else [],
        names=[indicator_type.value] if detected else [],
        indicators=[indicator] if detected else [],
    )


def test_pipeline_returns_validation_result():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation is not None
    assert result.potential_smuggling is True


def test_pipeline_creates_findings_for_detected_indicator():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.finding_count == 1
    assert result.findings[0].title
    assert result.findings[0].severity == "High"


def test_pipeline_uses_endpoint():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
        endpoint="/api/test",
    )

    assert result.findings[0].endpoint == "/api/test"


def test_pipeline_detects_parser_behavior_change():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(),
        make_analysis(),
        target="https://example.com",
        parser_behavior_changed=True,
    )

    assert result.potential_smuggling is True
    assert result.validation.status == "parser_behavior_changed"


def test_pipeline_without_response_change_is_indicator_only():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(),
        make_analysis(),
        target="https://example.com",
    )

    assert result.potential_smuggling is False
    assert result.validation.status == "indicator_detected"
    assert result.finding_count == 1


def test_pipeline_without_indicator_has_no_finding():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(detected=False),
        target="https://example.com",
    )

    assert result.potential_smuggling is False
    assert result.validation.status == "no_indicator"
    assert result.finding_count == 0


def test_pipeline_detects_status_change():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(status_code=200),
        make_response(status_code=400),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.status_changed is True
    assert result.potential_smuggling is True


def test_pipeline_detects_content_length_change():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(content=b"abc"),
        make_response(content=b"abcdef"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.content_length_changed is True
    assert result.potential_smuggling is True


def test_pipeline_detects_duplicate_content_length():
    pipeline = RequestSmugglingPipeline()

    analysis = make_analysis(
        indicator_type=(
            SmugglingIndicatorType.DUPLICATE_CONTENT_LENGTH
        )
    )
    analysis.smuggling_types = [
        SmugglingType.DUPLICATE_CONTENT_LENGTH
    ]
    analysis.indicators[0] = SmugglingIndicator(
        type=SmugglingIndicatorType.DUPLICATE_CONTENT_LENGTH,
        evidence="Multiple Content-Length values detected",
        smuggling_type=SmugglingType.DUPLICATE_CONTENT_LENGTH,
    )

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == 1
    assert result.findings[0].cwe == "CWE-444"


def test_pipeline_detects_ambiguous_transfer_encoding():
    pipeline = RequestSmugglingPipeline()

    analysis = make_analysis(
        indicator_type=(
            SmugglingIndicatorType.AMBIGUOUS_TRANSFER_ENCODING
        )
    )
    analysis.smuggling_types = [SmugglingType.TE_TE]
    analysis.indicators[0] = SmugglingIndicator(
        type=SmugglingIndicatorType.AMBIGUOUS_TRANSFER_ENCODING,
        evidence="Ambiguous Transfer-Encoding detected",
        smuggling_type=SmugglingType.TE_TE,
    )

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == 1
    assert result.findings[0].severity == "Medium"


def test_pipeline_preserves_validation_evidence():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.evidence
    assert any(
        "Baseline status" in item
        for item in result.validation.evidence
    )


def test_pipeline_rejects_invalid_analysis():
    pipeline = RequestSmugglingPipeline()

    try:
        pipeline.run(
            make_response(),
            make_response(),
            object(),
            target="https://example.com",
        )
    except TypeError as exc:
        assert "analysis" in str(exc)
    else:
        raise AssertionError("Expected TypeError")


def test_pipeline_accepts_cl_te_analysis():
    pipeline = RequestSmugglingPipeline()

    analysis = make_analysis()
    analysis.smuggling_types = [SmugglingType.CL_TE]

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        analysis,
        target="https://example.com",
    )

    assert result.finding_count == 1


def test_pipeline_result_finding_count():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.finding_count == len(result.findings)


def test_pipeline_target_is_preserved_in_finding():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://target.example",
    )

    assert result.findings[0].target == "https://target.example"


def test_pipeline_result_exposes_potential_smuggling():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.potential_smuggling is True


def test_pipeline_no_indicator_no_finding_even_with_parser_change():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(),
        make_analysis(detected=False),
        target="https://example.com",
        parser_behavior_changed=True,
    )

    assert result.potential_smuggling is False
    assert result.finding_count == 0


def test_pipeline_finding_has_request_smuggling_metadata():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    finding = result.findings[0]

    assert finding.cwe == "CWE-444"
    assert finding.owasp == "A05:2021"


def test_pipeline_finding_contains_evidence():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert "Test smuggling indicator" in result.findings[0].evidence


def test_pipeline_finding_contains_remediation():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.findings[0].remediation


def test_pipeline_finding_status_is_open():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.findings[0].status == "open"


def test_pipeline_handles_endpoint_none():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(content=b"changed"),
        make_analysis(),
        target="https://example.com",
    )

    assert result.findings[0].endpoint is None


def test_pipeline_returns_correct_baseline_status():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(status_code=201),
        make_response(status_code=201),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.baseline_status == 201


def test_pipeline_returns_correct_candidate_status():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(status_code=200),
        make_response(status_code=418),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.candidate_status == 418


def test_pipeline_detects_response_change():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(status_code=500),
        make_analysis(),
        target="https://example.com",
    )

    assert result.validation.response_changed is True


def test_pipeline_returns_empty_findings_for_clean_analysis():
    pipeline = RequestSmugglingPipeline()

    result = pipeline.run(
        make_response(),
        make_response(),
        RequestSmugglingAnalysis(),
        target="https://example.com",
    )

    assert result.findings == []
    assert result.finding_count == 0
    assert result.potential_smuggling is False
