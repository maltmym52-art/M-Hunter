import pytest

from m_hunter.analyzers.http_method_security import (
    HTTPMethodSecurityAnalysis,
    HTTPMethodSecurityIndicator,
    HTTPMethodSecurityIndicatorType,
)
from m_hunter.analyzers.http_method_security_finding import (
    HTTPMethodSecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.http_method_security import (
    HTTPMethodSecurityValidator,
)
from m_hunter.validation.http_method_security_pipeline import (
    HTTPMethodSecurityPipelineResult,
    HTTPMethodSecurityValidationPipeline,
)


def make_response(
    *,
    status_code=200,
    content=b"OK",
    headers=None,
    content_length=None,
    repeated_headers=None,
):
    if content_length is None:
        content_length = len(content)

    return HttpResponse(
        status_code=status_code,
        url="https://example.com/",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=content_length,
        repeated_headers=repeated_headers or {},
    )


def make_analysis(
    *indicator_types,
):
    return HTTPMethodSecurityAnalysis(
        indicators=tuple(
            HTTPMethodSecurityIndicator(
                type=indicator_type,
                evidence=f"Evidence for {indicator_type.value}",
                name="method",
                value="TRACE",
            )
            for indicator_type in indicator_types
        )
    )


@pytest.fixture
def pipeline():
    return HTTPMethodSecurityValidationPipeline()


@pytest.fixture
def security_analysis():
    return make_analysis(
        HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
    )


@pytest.fixture
def informational_analysis():
    return make_analysis(
        HTTPMethodSecurityIndicatorType.OPTIONS_EXPOSURE,
    )


@pytest.fixture
def clean_analysis():
    return HTTPMethodSecurityAnalysis(
        indicators=(),
    )


def test_identical_response_without_indicator_is_not_accepted(
    pipeline,
    clean_analysis,
):
    response = make_response()

    result = pipeline.process(
        baseline=response,
        candidate=response,
        analysis=clean_analysis,
        target="https://example.com",
    )

    assert isinstance(
        result,
        HTTPMethodSecurityPipelineResult,
    )
    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "no_indicator"


def test_security_indicator_without_change_is_not_accepted(
    pipeline,
    security_analysis,
):
    response = make_response()

    result = pipeline.process(
        baseline=response,
        candidate=response,
        analysis=security_analysis,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
    assert (
        result.validation.status
        == "indicator_detected"
    )


def test_security_indicator_with_response_change_is_accepted(
    pipeline,
    security_analysis,
):
    baseline = make_response(
        headers={"X-Test": "one"},
    )
    candidate = make_response(
        headers={"X-Test": "two"},
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=security_analysis,
        target="https://example.com",
        endpoint="/api/test",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )
    assert (
        result.validation
        .potential_http_method_security_issue
    )


def test_security_indicator_with_behavior_change_is_accepted(
    pipeline,
    security_analysis,
):
    response = make_response()

    result = pipeline.process(
        baseline=response,
        candidate=response,
        analysis=security_analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert result.findings
    assert result.validation.behavior_changed


def test_informational_indicator_is_not_accepted(
    pipeline,
    informational_analysis,
):
    baseline = make_response()
    candidate = make_response(
        content=b"changed",
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=informational_analysis,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
    assert (
        result.validation.status
        == "informational_indicator"
    )


def test_response_change_without_indicator_is_not_accepted(
    pipeline,
    clean_analysis,
):
    baseline = make_response(content=b"before")
    candidate = make_response(content=b"after")

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=clean_analysis,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_status_change_with_security_indicator_is_accepted(
    pipeline,
    security_analysis,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=403)

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=security_analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.status_changed
    assert result.findings


def test_content_change_with_security_indicator_is_accepted(
    pipeline,
    security_analysis,
):
    baseline = make_response(content=b"before")
    candidate = make_response(content=b"after")

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=security_analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.content_changed


def test_header_change_with_security_indicator_is_accepted(
    pipeline,
    security_analysis,
):
    baseline = make_response(
        headers={"X-Test": "one"},
    )
    candidate = make_response(
        headers={"X-Test": "two"},
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=security_analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.headers_changed


def test_multiple_indicators_create_multiple_findings(
    pipeline,
):
    analysis = make_analysis(
        HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER,
    )

    baseline = make_response()
    candidate = make_response(
        content=b"changed",
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) == 2


@pytest.mark.parametrize(
    "indicator_type",
    list(HTTPMethodSecurityIndicatorType),
)
def test_all_indicator_types_flow_through_pipeline(
    pipeline,
    indicator_type,
):
    analysis = make_analysis(indicator_type)

    baseline = make_response()
    candidate = make_response(
        content=b"changed",
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=analysis,
        target="https://example.com",
    )

    if indicator_type in (
        HTTPMethodSecurityValidator.SECURITY_RELEVANT_TYPES
    ):
        assert result.accepted
        assert result.findings
    else:
        assert result.accepted is False
        assert result.findings == []


def test_endpoint_is_passed_to_findings(
    pipeline,
    security_analysis,
):
    baseline = make_response()
    candidate = make_response(
        headers={"X-Test": "changed"},
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=security_analysis,
        target="https://example.com",
        endpoint="/admin",
    )

    assert result.findings
    assert all(
        finding.endpoint == "/admin"
        for finding in result.findings
    )


def test_target_is_passed_to_findings(
    pipeline,
    security_analysis,
):
    baseline = make_response()
    candidate = make_response(
        content=b"changed",
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=security_analysis,
        target="https://target.example",
    )

    assert result.findings
    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_custom_validator_is_used(
    security_analysis,
):
    class MockValidator:
        def __init__(self):
            self.called = False

        def compare(
            self,
            *,
            baseline,
            candidate,
            analysis,
            behavior_changed,
        ):
            self.called = True

            return HTTPMethodSecurityValidator().compare(
                baseline=baseline,
                candidate=candidate,
                analysis=analysis,
                behavior_changed=behavior_changed,
            )

    validator = MockValidator()

    pipeline = HTTPMethodSecurityValidationPipeline(
        validator=validator,
    )

    pipeline.process(
        baseline=make_response(),
        candidate=make_response(
            content=b"changed",
        ),
        analysis=security_analysis,
        target="https://example.com",
    )

    assert validator.called


def test_custom_finding_analyzer_is_used(
    security_analysis,
):
    class MockFindingAnalyzer:
        def __init__(self):
            self.called = False

        def analyze(
            self,
            *,
            analysis,
            target,
            endpoint,
        ):
            self.called = True

            return [
                Finding(
                    title="Mock HTTP method finding",
                    severity="Low",
                    confidence="High",
                    target=target,
                    endpoint=endpoint,
                )
            ]

    finding_analyzer = MockFindingAnalyzer()

    pipeline = HTTPMethodSecurityValidationPipeline(
        finding_analyzer=finding_analyzer,
    )

    result = pipeline.process(
        baseline=make_response(),
        candidate=make_response(
            content=b"changed",
        ),
        analysis=security_analysis,
        target="https://example.com",
    )

    assert finding_analyzer.called
    assert result.findings
    assert result.findings[0].title == (
        "Mock HTTP method finding"
    )


def test_requires_baseline_response(
    pipeline,
    security_analysis,
):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline="invalid",
            candidate=make_response(),
            analysis=security_analysis,
            target="https://example.com",
        )


def test_requires_candidate_response(
    pipeline,
    security_analysis,
):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline=make_response(),
            candidate="invalid",
            analysis=security_analysis,
            target="https://example.com",
        )


def test_requires_analysis(pipeline):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline=make_response(),
            candidate=make_response(),
            analysis="invalid",
            target="https://example.com",
        )


def test_requires_target(
    pipeline,
    security_analysis,
):
    with pytest.raises(ValueError):
        pipeline.process(
            baseline=make_response(),
            candidate=make_response(
                content=b"changed",
            ),
            analysis=security_analysis,
            target="",
        )


def test_endpoint_must_be_string(
    pipeline,
    security_analysis,
):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline=make_response(),
            candidate=make_response(
                content=b"changed",
            ),
            analysis=security_analysis,
            target="https://example.com",
            endpoint=123,
        )


def test_behavior_changed_must_be_boolean(
    pipeline,
    security_analysis,
):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline=make_response(),
            candidate=make_response(),
            analysis=security_analysis,
            target="https://example.com",
            behavior_changed="yes",
        )
