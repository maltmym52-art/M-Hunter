from m_hunter.analyzers.permissions_policy import (
    PermissionsPolicyAnalysis,
    PermissionsPolicyIndicator,
    PermissionsPolicyIndicatorType,
)
from m_hunter.analyzers.permissions_policy_finding import (
    PermissionsPolicyFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.permissions_policy import (
    PermissionsPolicyValidationResult,
    PermissionsPolicyValidator,
)
from m_hunter.validation.permissions_policy_pipeline import (
    PermissionsPolicyPipeline,
    PermissionsPolicyPipelineResult,
)


def analysis(*types):
    return PermissionsPolicyAnalysis(
        detected=True,
        indicators=tuple(
            PermissionsPolicyIndicator(
                type=kind,
                name=kind.value,
                value="camera *"
                if kind
                == PermissionsPolicyIndicatorType.WILDCARD_SOURCE
                else None,
            )
            for kind in types
        ),
    )


def test_name():
    assert PermissionsPolicyPipeline.name == "permissions_policy_pipeline"


def test_result_type():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.POLICY_PRESENT),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert isinstance(result, PermissionsPolicyPipelineResult)


def test_validation_exposed():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert isinstance(
        result.validation,
        PermissionsPolicyValidationResult,
    )


def test_clean_policy_rejected():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.POLICY_PRESENT),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_wildcard_without_change_rejected():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_wildcard_with_status_change_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
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


def test_content_change_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_changed=True,
    )

    assert result.accepted
    assert result.findings


def test_content_length_change_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_length_changed=True,
    )

    assert result.accepted


def test_headers_change_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        headers_changed=True,
    )

    assert result.accepted


def test_missing_policy_not_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.POLICY_MISSING),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_self_source_not_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.SELF_SOURCE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_origin_source_not_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.ORIGIN_SOURCE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_feature_context_not_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.CAMERA),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_invalid_directive_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.INVALID_DIRECTIVE),
        baseline_status=200,
        candidate_status=500,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_invalid_source_accepted():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.INVALID_SOURCE),
        baseline_status=200,
        candidate_status=500,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_target_preserved():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
        target="https://target.example",
    )

    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_endpoint_preserved():
    result = PermissionsPolicyPipeline().process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
        endpoint="/api/profile",
    )

    assert all(
        finding.endpoint == "/api/profile"
        for finding in result.findings
    )


def test_multiple_findings():
    result = PermissionsPolicyPipeline().process(
        analysis(
            PermissionsPolicyIndicatorType.WILDCARD_SOURCE,
            PermissionsPolicyIndicatorType.INVALID_SOURCE,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 2


def test_reusable_pipeline():
    pipeline = PermissionsPolicyPipeline()

    first = pipeline.process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    second = pipeline.process(
        analysis(PermissionsPolicyIndicatorType.POLICY_PRESENT),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert first.accepted
    assert not second.accepted


def test_invalid_analysis():
    try:
        PermissionsPolicyPipeline().process(
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
        PermissionsPolicyPipeline().process(
            analysis(PermissionsPolicyIndicatorType.CAMERA),
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
        PermissionsPolicyPipeline().process(
            analysis(PermissionsPolicyIndicatorType.CAMERA),
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
    class CustomValidator(PermissionsPolicyValidator):
        def validate(self, *args, **kwargs):
            return super().validate(*args, **kwargs)

    pipeline = PermissionsPolicyPipeline(
        validator=CustomValidator()
    )

    result = pipeline.process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted


def test_custom_finding_analyzer():
    class CustomFindingAnalyzer(PermissionsPolicyFindingAnalyzer):
        def analyze(self, *args, **kwargs):
            return super().analyze(*args, **kwargs)

    pipeline = PermissionsPolicyPipeline(
        finding_analyzer=CustomFindingAnalyzer()
    )

    result = pipeline.process(
        analysis(PermissionsPolicyIndicatorType.WILDCARD_SOURCE),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings
