import pytest

from m_hunter.analyzers.corp import (
    CORPAnalysis,
    CORPIndicator,
    CORPIndicatorType,
)
from m_hunter.analyzers.corp_finding import CORPFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.corp import (
    CORPValidationResult,
    CORPValidator,
)
from m_hunter.validation.corp_pipeline import (
    CORPPipeline,
    CORPPipelineResult,
)


def analysis(*types):
    return CORPAnalysis(
        detected=True,
        indicators=tuple(
            CORPIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_name():
    assert CORPPipeline.name == "corp_pipeline"


def test_result_type():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert isinstance(result, CORPPipelineResult)


def test_validation_exposed():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert isinstance(
        result.validation,
        CORPValidationResult,
    )


def test_clean_policy_rejected():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_cross_origin_without_change_rejected():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_cross_origin_with_status_change_accepted():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )


def test_invalid_policy_with_change_accepted():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.INVALID_POLICY),
        baseline_status=200,
        candidate_status=500,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_multiple_policy_with_change_accepted():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.MULTIPLE_POLICIES),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_content_change_accepted():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_changed=True,
    )

    assert result.accepted
    assert result.findings


def test_content_length_change_accepted():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_length_changed=True,
    )

    assert result.accepted


def test_headers_change_accepted():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        headers_changed=True,
    )

    assert result.accepted


def test_missing_policy_not_accepted():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.POLICY_MISSING),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_same_site_not_accepted():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.SAME_SITE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_same_origin_not_accepted():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_target_preserved():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
        target="https://target.example",
    )

    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_endpoint_preserved():
    result = CORPPipeline().process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
        endpoint="/resource.js",
    )

    assert all(
        finding.endpoint == "/resource.js"
        for finding in result.findings
    )


def test_multiple_findings():
    result = CORPPipeline().process(
        analysis(
            CORPIndicatorType.CROSS_ORIGIN,
            CORPIndicatorType.INVALID_POLICY,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 2


def test_reusable_pipeline():
    pipeline = CORPPipeline()

    first = pipeline.process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    second = pipeline.process(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert first.accepted
    assert not second.accepted


def test_invalid_analysis():
    with pytest.raises(TypeError):
        CORPPipeline().process(
            object(),
            baseline_status=200,
            candidate_status=200,
            target="https://example.com",
        )


def test_invalid_target():
    with pytest.raises(ValueError):
        CORPPipeline().process(
            analysis(CORPIndicatorType.SAME_ORIGIN),
            baseline_status=200,
            candidate_status=200,
            target="",
        )


def test_invalid_endpoint():
    with pytest.raises(TypeError):
        CORPPipeline().process(
            analysis(CORPIndicatorType.SAME_ORIGIN),
            baseline_status=200,
            candidate_status=200,
            target="https://example.com",
            endpoint=123,
        )


def test_custom_validator():
    class CustomValidator(CORPValidator):
        def validate(self, *args, **kwargs):
            return super().validate(*args, **kwargs)

    pipeline = CORPPipeline(
        validator=CustomValidator()
    )

    result = pipeline.process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted


def test_custom_finding_analyzer():
    class CustomFindingAnalyzer(CORPFindingAnalyzer):
        def analyze(self, *args, **kwargs):
            return super().analyze(*args, **kwargs)

    pipeline = CORPPipeline(
        finding_analyzer=CustomFindingAnalyzer()
    )

    result = pipeline.process(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings
