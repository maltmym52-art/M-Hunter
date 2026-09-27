import pytest

from m_hunter.analyzers.security_reporting import (
    SecurityReportingAnalysis,
    SecurityReportingIndicator,
    SecurityReportingIndicatorType,
)
from m_hunter.analyzers.security_reporting_finding import (
    SecurityReportingFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.security_reporting import (
    SecurityReportingValidationResult,
    SecurityReportingValidator,
)
from m_hunter.validation.security_reporting_pipeline import (
    SecurityReportingPipeline,
    SecurityReportingPipelineResult,
)


def analysis(*types):
    return SecurityReportingAnalysis(
        detected=True,
        indicators=tuple(
            SecurityReportingIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_name():
    assert (
        SecurityReportingPipeline.name
        == "security_reporting_pipeline"
    )


def test_result_type():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert isinstance(result, SecurityReportingPipelineResult)


def test_validation_exposed():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert isinstance(
        result.validation,
        SecurityReportingValidationResult,
    )


def test_valid_configuration_rejected():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_invalid_reporting_endpoints_without_change_rejected():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_invalid_reporting_endpoints_with_change_accepted():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS
        ),
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


def test_invalid_report_to_with_change_accepted():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=500,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_multiple_reporting_endpoints_with_change_accepted():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.MULTIPLE_REPORTING_ENDPOINTS
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_multiple_report_to_with_change_accepted():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.MULTIPLE_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_content_change_accepted():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_changed=True,
    )

    assert result.accepted
    assert result.findings


def test_content_length_change_accepted():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        content_length_changed=True,
    )

    assert result.accepted


def test_headers_change_accepted():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
        headers_changed=True,
    )

    assert result.accepted


def test_endpoint_not_security_indicator():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


def test_group_not_security_indicator():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.GROUP_PRESENT
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_csp_report_only_not_security_indicator():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.CSP_REPORT_ONLY
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert not result.accepted


def test_target_preserved():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://target.example",
    )

    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_endpoint_preserved():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
        endpoint="/security",
    )

    assert all(
        finding.endpoint == "/security"
        for finding in result.findings
    )


def test_multiple_findings():
    result = SecurityReportingPipeline().process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO,
            SecurityReportingIndicatorType.MULTIPLE_REPORT_TO,
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 2


def test_reusable_pipeline():
    pipeline = SecurityReportingPipeline()

    first = pipeline.process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    second = pipeline.process(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        baseline_status=200,
        candidate_status=200,
        target="https://example.com",
    )

    assert first.accepted
    assert not second.accepted


def test_invalid_analysis():
    with pytest.raises(TypeError):
        SecurityReportingPipeline().process(
            object(),
            baseline_status=200,
            candidate_status=200,
            target="https://example.com",
        )


def test_invalid_target():
    with pytest.raises(ValueError):
        SecurityReportingPipeline().process(
            analysis(
                SecurityReportingIndicatorType.ENDPOINT_PRESENT
            ),
            baseline_status=200,
            candidate_status=200,
            target="",
        )


def test_invalid_endpoint():
    with pytest.raises(TypeError):
        SecurityReportingPipeline().process(
            analysis(
                SecurityReportingIndicatorType.ENDPOINT_PRESENT
            ),
            baseline_status=200,
            candidate_status=200,
            target="https://example.com",
            endpoint=123,
        )


def test_custom_validator():
    class CustomValidator(SecurityReportingValidator):
        def validate(self, *args, **kwargs):
            return super().validate(*args, **kwargs)

    pipeline = SecurityReportingPipeline(
        validator=CustomValidator()
    )

    result = pipeline.process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted


def test_custom_finding_analyzer():
    class CustomFindingAnalyzer(SecurityReportingFindingAnalyzer):
        def analyze(self, *args, **kwargs):
            return super().analyze(*args, **kwargs)

    pipeline = SecurityReportingPipeline(
        finding_analyzer=CustomFindingAnalyzer()
    )

    result = pipeline.process(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        baseline_status=200,
        candidate_status=403,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings
