from m_hunter.analyzers.coep import (
    COEPAnalysis,
    COEPIndicator,
    COEPIndicatorType,
)
from m_hunter.analyzers.coep_finding import COEPFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.coep import (
    COEPValidationResult,
    COEPValidator,
)
from m_hunter.validation.coep_pipeline import (
    COEPPipeline,
    COEPPipelineResult,
)


def analysis(*types):
    return COEPAnalysis(
        detected=True,
        indicators=tuple(
            COEPIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_name():
    assert COEPPipeline.name == "coep_pipeline"


def test_result_type():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert isinstance(result, COEPPipelineResult)


def test_validation_exposed():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert isinstance(
        result.validation,
        COEPValidationResult,
    )


def test_clean_policy_rejected():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_unsafe_none_without_change_rejected():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_unsafe_none_with_status_change_accepted():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
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
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.INVALID_POLICY),
        baseline_status=200,
        candidate_status=500,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_multiple_policy_with_change_accepted():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.MULTIPLE_POLICIES),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_content_change_accepted():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_changed=True,
    )

    assert result.accepted
    assert result.findings


def test_content_length_change_accepted():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_length_changed=True,
    )

    assert result.accepted


def test_headers_change_accepted():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        headers_changed=True,
    )

    assert result.accepted


def test_missing_policy_not_accepted():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.POLICY_MISSING),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_require_corp_not_accepted():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_credentialless_not_accepted():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.CREDENTIALLESS),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_target_preserved():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://target.example",
    )

    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_endpoint_preserved():
    result = COEPPipeline().process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
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
    result = COEPPipeline().process(
        analysis(
            COEPIndicatorType.UNSAFE_NONE,
            COEPIndicatorType.INVALID_POLICY,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 2


def test_reusable_pipeline():
    pipeline = COEPPipeline()

    first = pipeline.process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    second = pipeline.process(
        analysis(COEPIndicatorType.REQUIRE_CORP),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert first.accepted
    assert not second.accepted


def test_invalid_analysis():
    try:
        COEPPipeline().process(
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
        COEPPipeline().process(
            analysis(COEPIndicatorType.REQUIRE_CORP),
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
        COEPPipeline().process(
            analysis(COEPIndicatorType.REQUIRE_CORP),
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
    class CustomValidator(COEPValidator):
        def validate(self, *args, **kwargs):
            return super().validate(*args, **kwargs)

    pipeline = COEPPipeline(
        validator=CustomValidator()
    )

    result = pipeline.process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted


def test_custom_finding_analyzer():
    class CustomFindingAnalyzer(COEPFindingAnalyzer):
        def analyze(self, *args, **kwargs):
            return super().analyze(*args, **kwargs)

    pipeline = COEPPipeline(
        finding_analyzer=CustomFindingAnalyzer()
    )

    result = pipeline.process(
        analysis(COEPIndicatorType.UNSAFE_NONE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings
