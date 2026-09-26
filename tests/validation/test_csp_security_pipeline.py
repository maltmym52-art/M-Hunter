import pytest

from m_hunter.analyzers.csp_security import (
    CSPAnalysis,
    CSPIndicator,
    CSPIndicatorType,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.csp_security_pipeline import (
    CSPPipeline,
    CSPPipelineResult,
)


def make_analysis(*types):
    indicators = tuple(
        CSPIndicator(
            type=indicator_type,
            evidence=f"evidence: {indicator_type.value}",
            value=indicator_type.value,
        )
        for indicator_type in types
    )

    unique_types = tuple(dict.fromkeys(types))

    return CSPAnalysis(
        detected=bool(indicators),
        indicators=indicators,
        count=len(indicators),
        types=unique_types,
        names=tuple(
            item.value for item in unique_types
        ),
    )


@pytest.fixture
def pipeline():
    return CSPPipeline()


def test_pipeline_can_be_created(pipeline):
    assert isinstance(pipeline, CSPPipeline)


def test_pipeline_name():
    assert CSPPipeline.name == "csp_security_pipeline"


def test_result_type():
    result = CSPPipeline().process(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert isinstance(result, CSPPipelineResult)


def test_clean_analysis_is_rejected(pipeline):
    result = pipeline.process(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_security_indicator_without_change_is_rejected(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_status_change_is_accepted(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_content_change_is_accepted(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.UNSAFE_EVAL
        ),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_content_length_change_is_accepted(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.DATA_SOURCE
        ),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
        target="https://example.com",
    )

    assert result.accepted is True


def test_header_change_is_accepted(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.BLOB_SOURCE
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
        target="https://example.com",
    )

    assert result.accepted is True


def test_findings_are_finding_instances(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.SCRIPT_SRC_WILDCARD
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )


def test_target_is_preserved(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://target.example",
    )

    assert result.findings[0].target == (
        "https://target.example"
    )


def test_endpoint_is_preserved(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.UNSAFE_EVAL
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
        endpoint="/admin",
    )

    assert result.findings[0].endpoint == "/admin"


def test_validation_is_exposed(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.WILDCARD_SOURCE
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.validation.potential_csp_issue is True
    assert result.validation.status == "potential"


def test_multiple_indicators_create_multiple_findings(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE,
            CSPIndicatorType.UNSAFE_EVAL,
            CSPIndicatorType.DATA_SOURCE,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True
    assert len(result.findings) == 3


def test_csp_presence_alone_is_not_accepted(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.CSP_PRESENT
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_secure_directives_are_not_accepted(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.CSP_PRESENT,
            CSPIndicatorType.OBJECT_NONE,
            CSPIndicatorType.BASE_NONE,
            CSPIndicatorType.FRAME_ANCESTORS_NONE,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_missing_directives_are_not_accepted(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.SCRIPT_SRC_MISSING,
            CSPIndicatorType.DEFAULT_SRC_MISSING,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_requires_analysis(pipeline):
    with pytest.raises(TypeError):
        pipeline.process(
            object(),
            baseline_status=200,
            candidate_status=403,
            target="https://example.com",
        )


def test_requires_target(pipeline):
    with pytest.raises(ValueError):
        pipeline.process(
            make_analysis(
                CSPIndicatorType.UNSAFE_INLINE
            ),
            baseline_status=200,
            candidate_status=403,
            target="",
        )


def test_rejects_invalid_endpoint(pipeline):
    with pytest.raises(TypeError):
        pipeline.process(
            make_analysis(
                CSPIndicatorType.UNSAFE_INLINE
            ),
            baseline_status=200,
            candidate_status=403,
            target="https://example.com",
            endpoint=123,
        )


def test_pipeline_is_reusable(pipeline):
    accepted = pipeline.process(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    rejected = pipeline.process(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert accepted.accepted is True
    assert rejected.accepted is False
    assert rejected.findings == []


def test_high_severity_finding_is_preserved(pipeline):
    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.SCRIPT_SRC_WILDCARD
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.findings[0].severity == "High"


def test_custom_validator_can_force_acceptance():
    class Validator:
        def validate(
            self,
            analysis,
            *,
            baseline_status,
            candidate_status,
            content_changed=False,
            content_length_changed=False,
            headers_changed=False,
        ):
            from m_hunter.validation.csp_security import (
                CSPValidationResult,
            )

            return CSPValidationResult(
                baseline_status=baseline_status,
                candidate_status=candidate_status,
                status_changed=False,
                content_changed=False,
                content_length_changed=False,
                headers_changed=False,
                response_changed=False,
                security_indicator_present=True,
                dangerous_policy_present=True,
                potential_csp_issue=True,
                status="potential",
                evidence="custom",
            )

    pipeline = CSPPipeline(
        validator=Validator()
    )

    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_custom_finding_analyzer_can_be_used():
    class FindingAnalyzer:
        def analyze(
            self,
            analysis,
            *,
            target,
            endpoint=None,
        ):
            return []

    pipeline = CSPPipeline(
        finding_analyzer=FindingAnalyzer()
    )

    result = pipeline.process(
        make_analysis(
            CSPIndicatorType.UNSAFE_INLINE
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings == []
