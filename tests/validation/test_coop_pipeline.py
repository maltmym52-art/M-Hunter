from m_hunter.analyzers.coop import (
    COOPAnalysis,
    COOPIndicator,
    COOPIndicatorType,
)
from m_hunter.analyzers.coop_finding import COOPFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.coop import (
    COOPValidationResult,
    COOPValidator,
)
from m_hunter.validation.coop_pipeline import (
    COOPPipeline,
    COOPPipelineResult,
)


def analysis(*types):
    return COOPAnalysis(
        detected=True,
        indicators=tuple(
            COOPIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_name():
    assert COOPPipeline.name == "coop_pipeline"


def test_result_type():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert isinstance(result, COOPPipelineResult)


def test_validation_exposed():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert isinstance(
        result.validation,
        COOPValidationResult,
    )


def test_clean_policy_rejected():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_unsafe_none_without_change_rejected():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_unsafe_none_with_status_change_accepted():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
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
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.INVALID_POLICY),
        baseline_status=200,
        candidate_status=500,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_multiple_policy_with_change_accepted():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.MULTIPLE_POLICIES),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_content_change_accepted():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_changed=True,
    )

    assert result.accepted
    assert result.findings


def test_content_length_change_accepted():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_length_changed=True,
    )

    assert result.accepted


def test_headers_change_accepted():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        headers_changed=True,
    )

    assert result.accepted


def test_missing_policy_not_accepted():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.POLICY_MISSING),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_same_origin_not_accepted():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_same_origin_allow_popups_not_accepted():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.SAME_ORIGIN_ALLOW_POPUPS),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_target_preserved():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://target.example",
    )

    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_endpoint_preserved():
    result = COOPPipeline().process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
        endpoint="/account",
    )

    assert all(
        finding.endpoint == "/account"
        for finding in result.findings
    )


def test_multiple_findings():
    result = COOPPipeline().process(
        analysis(
            COOPIndicatorType.UNSAFE_NONE,
            COOPIndicatorType.INVALID_POLICY,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 2


def test_reusable_pipeline():
    pipeline = COOPPipeline()

    first = pipeline.process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    second = pipeline.process(
        analysis(COOPIndicatorType.SAME_ORIGIN),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert first.accepted
    assert not second.accepted


def test_invalid_analysis():
    try:
        COOPPipeline().process(
            object(),
            baseline_status=200,
            candidate_status=200,
            target="https://example.com",
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_invalid_target():
    try:
        COOPPipeline().process(
            analysis(COOPIndicatorType.SAME_ORIGIN),
            baseline_status=200,
            candidate_status=200,
            target="",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")


def test_invalid_endpoint():
    try:
        COOPPipeline().process(
            analysis(COOPIndicatorType.SAME_ORIGIN),
            baseline_status=200,
            candidate_status=200,
            target="https://example.com",
            endpoint=123,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_custom_validator():
    class CustomValidator(COOPValidator):
        def validate(self, *args, **kwargs):
            return super().validate(*args, **kwargs)

    pipeline = COOPPipeline(
        validator=CustomValidator()
    )

    result = pipeline.process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted


def test_custom_finding_analyzer():
    class CustomFindingAnalyzer(COOPFindingAnalyzer):
        def analyze(self, *args, **kwargs):
            return super().analyze(*args, **kwargs)

    pipeline = COOPPipeline(
        finding_analyzer=CustomFindingAnalyzer()
    )

    result = pipeline.process(
        analysis(COOPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings
