import pytest

from m_hunter.analyzers.session import (
    SessionAnalysis,
    SessionAnalyzer,
    SessionIndicator,
    SessionIndicatorType,
)
from m_hunter.analyzers.session_finding import SessionFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.session import SessionValidator
from m_hunter.validation.session_pipeline import (
    SessionPipelineResult,
    SessionValidationPipeline,
)


def make_response(
    *,
    status_code=200,
    content=b"OK",
    headers=None,
    cookies=None,
    content_length=None,
    repeated_headers=None,
):
    if content_length is None:
        content_length = len(content)

    return HttpResponse(
        status_code=status_code,
        url="https://example.com/session",
        headers=headers or {},
        content=content,
        cookies=cookies or {},
        response_time=0.1,
        content_length=content_length,
        repeated_headers=repeated_headers or {},
    )


def make_analysis(
    indicator_type=SessionIndicatorType.SESSION_COOKIE,
):
    return SessionAnalysis(
        indicators=(
            SessionIndicator(
                type=indicator_type,
                evidence="Session indicator detected",
            ),
        )
    )


@pytest.fixture
def pipeline():
    return SessionValidationPipeline()


@pytest.fixture
def clean_analysis():
    return SessionAnalysis(indicators=())


@pytest.fixture
def session_analysis():
    return make_analysis()


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

    assert isinstance(result, SessionPipelineResult)
    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "no_indicator"


def test_indicator_without_behavior_change_is_not_accepted(
    pipeline,
    session_analysis,
):
    response = make_response()

    result = pipeline.process(
        baseline=response,
        candidate=response,
        analysis=session_analysis,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "indicator_detected"


def test_indicator_with_response_change_is_accepted(
    pipeline,
    session_analysis,
):
    baseline = make_response(
        headers={"X-Session": "one"},
    )
    candidate = make_response(
        headers={"X-Session": "two"},
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=session_analysis,
        target="https://example.com",
        endpoint="/login",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )
    assert result.validation.potential_session_issue


def test_indicator_with_behavior_change_is_accepted(
    pipeline,
    session_analysis,
):
    response = make_response()

    result = pipeline.process(
        baseline=response,
        candidate=response,
        analysis=session_analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert result.findings
    assert result.validation.behavior_changed


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


def test_status_change_with_indicator_is_accepted(
    pipeline,
    session_analysis,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=401)

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=session_analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.status_changed
    assert result.findings


def test_content_change_with_indicator_is_accepted(
    pipeline,
    session_analysis,
):
    baseline = make_response(content=b"one")
    candidate = make_response(content=b"two-two")

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=session_analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.content_changed


def test_header_change_with_indicator_is_accepted(
    pipeline,
    session_analysis,
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
        analysis=session_analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.headers_changed


def test_multiple_indicators_create_multiple_findings(
    pipeline,
):
    analysis = SessionAnalysis(
        indicators=(
            SessionIndicator(
                type=SessionIndicatorType.SESSION_COOKIE,
                evidence="Cookie detected",
            ),
            SessionIndicator(
                type=SessionIndicatorType.TOKEN_EXPOSURE,
                evidence="Token exposed",
            ),
        )
    )

    baseline = make_response()
    candidate = make_response(
        headers={"X-Test": "changed"},
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
    list(SessionIndicatorType),
)
def test_all_indicator_types_flow_through_pipeline(
    pipeline,
    indicator_type,
):
    analysis = make_analysis(indicator_type)

    baseline = make_response()
    candidate = make_response(
        content=b"changed-response",
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )


def test_endpoint_is_passed_to_findings(
    pipeline,
    session_analysis,
):
    baseline = make_response()
    candidate = make_response(
        headers={"X-Test": "changed"},
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=session_analysis,
        target="https://example.com",
        endpoint="/account",
    )

    assert result.findings
    assert all(
        finding.endpoint == "/account"
        for finding in result.findings
    )


def test_target_is_passed_to_findings(
    pipeline,
    session_analysis,
):
    baseline = make_response()
    candidate = make_response(
        headers={"X-Test": "changed"},
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=session_analysis,
        target="https://target.example",
    )

    assert result.findings
    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_custom_validator_is_used(
    session_analysis,
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
            return SessionValidator().compare(
                baseline=baseline,
                candidate=candidate,
                analysis=analysis,
                behavior_changed=behavior_changed,
            )

    validator = MockValidator()
    pipeline = SessionValidationPipeline(
        validator=validator,
    )

    baseline = make_response()
    candidate = make_response(
        content=b"changed",
    )

    pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=session_analysis,
        target="https://example.com",
    )

    assert validator.called


def test_custom_finding_analyzer_is_used(
    session_analysis,
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
                    title="Mock session finding",
                    severity="Low",
                    confidence="High",
                    target=target,
                    endpoint=endpoint,
                )
            ]

    finding_analyzer = MockFindingAnalyzer()

    pipeline = SessionValidationPipeline(
        finding_analyzer=finding_analyzer,
    )

    baseline = make_response()
    candidate = make_response(
        content=b"changed",
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=session_analysis,
        target="https://example.com",
        endpoint="/login",
    )

    assert finding_analyzer.called
    assert len(result.findings) == 1
    assert result.findings[0].title == "Mock session finding"


def test_invalid_baseline_raises_type_error(
    pipeline,
    session_analysis,
):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline="invalid",
            candidate=make_response(),
            analysis=session_analysis,
            target="https://example.com",
        )


def test_invalid_candidate_raises_type_error(
    pipeline,
    session_analysis,
):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline=make_response(),
            candidate="invalid",
            analysis=session_analysis,
            target="https://example.com",
        )


def test_invalid_analysis_raises_type_error(
    pipeline,
):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline=make_response(),
            candidate=make_response(),
            analysis="invalid",
            target="https://example.com",
        )


def test_invalid_target_raises_value_error(
    pipeline,
    session_analysis,
):
    with pytest.raises(ValueError):
        pipeline.process(
            baseline=make_response(),
            candidate=make_response(),
            analysis=session_analysis,
            target="",
        )


def test_invalid_endpoint_raises_type_error(
    pipeline,
    session_analysis,
):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline=make_response(),
            candidate=make_response(),
            analysis=session_analysis,
            target="https://example.com",
            endpoint=123,
        )


def test_invalid_behavior_changed_raises_type_error(
    pipeline,
    session_analysis,
):
    with pytest.raises(TypeError):
        pipeline.process(
            baseline=make_response(),
            candidate=make_response(),
            analysis=session_analysis,
            target="https://example.com",
            behavior_changed="yes",
        )


def test_default_dependencies_are_created():
    pipeline = SessionValidationPipeline()

    assert isinstance(pipeline.validator, SessionValidator)
    assert isinstance(
        pipeline.finding_analyzer,
        SessionFindingAnalyzer,
    )


def test_result_contains_validation_object(
    pipeline,
    session_analysis,
):
    baseline = make_response()
    candidate = make_response(
        headers={"X-Test": "changed"},
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=session_analysis,
        target="https://example.com",
    )

    assert isinstance(
        result.validation,
        type(pipeline.validator.compare(
            baseline=baseline,
            candidate=candidate,
            analysis=session_analysis,
        )),
    )


def test_no_findings_when_not_accepted(
    pipeline,
    session_analysis,
):
    response = make_response()

    result = pipeline.process(
        baseline=response,
        candidate=response,
        analysis=session_analysis,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_findings_are_only_created_after_validation(
    pipeline,
    session_analysis,
):
    baseline = make_response()
    candidate = make_response(
        headers={"X-Changed": "yes"},
    )

    result = pipeline.process(
        baseline=baseline,
        candidate=candidate,
        analysis=session_analysis,
        target="https://example.com",
    )

    assert result.validation.potential_session_issue
    assert result.accepted
    assert result.findings
