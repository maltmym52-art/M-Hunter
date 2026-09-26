import pytest

from m_hunter.analyzers.cors_advanced import (
    CORSAdvancedAnalysis,
    CORSAdvancedIndicator,
    CORSAdvancedIndicatorType,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.cors_advanced_pipeline import (
    CORSAdvancedPipeline,
    CORSAdvancedPipelineResult,
)


def make_analysis(*types):
    indicators = tuple(
        CORSAdvancedIndicator(
            type=indicator_type,
            evidence=f"evidence: {indicator_type.value}",
            value=indicator_type.value,
        )
        for indicator_type in types
    )

    return CORSAdvancedAnalysis(
        detected=bool(indicators),
        indicators=indicators,
        count=len(indicators),
        types=tuple(dict.fromkeys(types)),
        names=tuple(
            indicator_type.value
            for indicator_type in dict.fromkeys(types)
        ),
    )


@pytest.fixture
def pipeline():
    return CORSAdvancedPipeline()


def test_pipeline_can_be_created(pipeline):
    assert isinstance(
        pipeline,
        CORSAdvancedPipeline,
    )


def test_pipeline_name():
    assert CORSAdvancedPipeline.name == "cors_advanced_pipeline"


def test_clean_analysis_is_rejected(pipeline):
    result = pipeline.process(
        make_analysis(),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert isinstance(
        result,
        CORSAdvancedPipelineResult,
    )
    assert result.accepted is False
    assert result.findings == []


def test_security_indicator_with_status_change_is_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )


def test_security_indicator_with_content_change_is_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
        ),
        baseline_status=200,
        candidate_status=200,
        content_changed=True,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_security_indicator_with_content_length_change_is_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.PREFIX_TRUST,
        ),
        baseline_status=200,
        candidate_status=200,
        content_length_changed=True,
        target="https://example.com",
    )

    assert result.accepted is True


def test_security_indicator_with_header_change_is_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.SUFFIX_TRUST,
        ),
        baseline_status=200,
        candidate_status=200,
        headers_changed=True,
        target="https://example.com",
    )

    assert result.accepted is True


def test_credentialed_reflection_is_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType
            .CREDENTIALED_ORIGIN_REFLECTION,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings[0].severity == "High"


def test_null_origin_reflection_is_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType
            .NULL_ORIGIN_REFLECTION,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True


def test_wildcard_credentials_are_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType
            .WILDCARD_CREDENTIALS,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_origin_reflection_alone_is_not_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.ORIGIN_REFLECTION,
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_credentials_alone_is_not_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.CREDENTIALS_ENABLED,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_allow_origin_presence_is_not_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType
            .ACCESS_CONTROL_ALLOW_ORIGIN_PRESENT,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is False


def test_preflight_methods_are_not_accepted(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.PREFLIGHT_METHODS,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is False


def test_findings_preserve_target(pipeline):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://target.example",
    )

    assert result.findings[0].target == (
        "https://target.example"
    )


def test_findings_preserve_endpoint(pipeline):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
        endpoint="/api/account",
    )

    assert result.findings[0].endpoint == "/api/account"


def test_validation_is_exposed(pipeline):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.validation.potential_cors_issue is True
    assert result.validation.status == "potential"


def test_multiple_indicators_create_multiple_findings(
    pipeline,
):
    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
            CORSAdvancedIndicatorType
            .CREDENTIALED_ORIGIN_REFLECTION,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True
    assert len(result.findings) == 2


def test_pipeline_is_reusable(pipeline):
    accepted = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType
            .REFLECTED_ARBITRARY_ORIGIN,
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


def test_invalid_analysis_is_rejected(pipeline):
    with pytest.raises(TypeError):
        pipeline.process(
            object(),
            baseline_status=200,
            candidate_status=403,
            target="https://example.com",
        )


def test_empty_target_is_rejected(pipeline):
    with pytest.raises(ValueError):
        pipeline.process(
            make_analysis(
                CORSAdvancedIndicatorType
                .SUBDOMAIN_TRUST,
            ),
            baseline_status=200,
            candidate_status=403,
            target="",
        )


def test_invalid_endpoint_is_rejected(pipeline):
    with pytest.raises(TypeError):
        pipeline.process(
            make_analysis(
                CORSAdvancedIndicatorType
                .SUBDOMAIN_TRUST,
            ),
            baseline_status=200,
            candidate_status=403,
            target="https://example.com",
            endpoint=123,
        )


def test_custom_validator_can_be_used():
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
            from m_hunter.validation.cors_advanced import (
                CORSAdvancedValidationResult,
            )

            return CORSAdvancedValidationResult(
                baseline_status=baseline_status,
                candidate_status=candidate_status,
                status_changed=False,
                content_changed=False,
                content_length_changed=False,
                headers_changed=False,
                response_changed=False,
                security_indicator_present=True,
                origin_reflection_present=False,
                credentials_present=False,
                potential_cors_issue=True,
                status="potential",
                evidence="custom",
            )

    pipeline = CORSAdvancedPipeline(
        validator=Validator()
    )

    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
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

    pipeline = CORSAdvancedPipeline(
        finding_analyzer=FindingAnalyzer()
    )

    result = pipeline.process(
        make_analysis(
            CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings == []
