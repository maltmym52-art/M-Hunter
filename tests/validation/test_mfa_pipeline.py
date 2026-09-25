import pytest

from m_hunter.analyzers.mfa import MFAAnalyzer
from m_hunter.analyzers.mfa_finding import MFAFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.mfa_pipeline import (
    MFAPipelineResult,
    MFAValidationPipeline,
)


@pytest.fixture
def analyzer():
    return MFAAnalyzer()


@pytest.fixture
def finding_analyzer():
    return MFAFindingAnalyzer()


@pytest.fixture
def pipeline(finding_analyzer):
    return MFAValidationPipeline(
        finding_analyzer=finding_analyzer,
    )


def make_response(
    *,
    status_code=200,
    url="https://example.com/login",
    headers=None,
    content=b"OK",
):
    return HttpResponse(
        status_code=status_code,
        url=url,
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def test_pipeline_result_type(
    pipeline,
    analyzer,
):
    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(),
        target="https://example.com",
    )

    assert isinstance(result, MFAPipelineResult)


def test_no_indicator_is_not_accepted(
    pipeline,
    analyzer,
):
    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "no_indicator"


def test_indicator_without_change_is_not_accepted(
    pipeline,
    analyzer,
):
    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(mfa=True),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "indicator_detected"


def test_status_change_accepts_indicator(
    pipeline,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=403)

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(mfa=True),
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.validation.potential_mfa_issue
    assert result.findings


def test_content_change_accepts_indicator(
    pipeline,
    analyzer,
):
    baseline = make_response(content=b"normal")
    candidate = make_response(content=b"MFA required")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(verification=True),
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_header_change_accepts_indicator(
    pipeline,
    analyzer,
):
    baseline = make_response(
        headers={"content-type": "text/html"}
    )
    candidate = make_response(
        headers={
            "content-type": "text/html",
            "x-mfa": "required",
        }
    )

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(mfa=True),
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_behavior_change_accepts_indicator(
    pipeline,
    analyzer,
):
    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(
            bypass_indicator=True,
        ),
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert result.validation.behavior_changed
    assert result.findings


def test_behavior_change_without_indicator_is_not_accepted(
    pipeline,
    analyzer,
):
    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(),
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is False
    assert result.findings == []


def test_findings_are_finding_objects(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(otp=True),
        target="https://example.com",
    )

    assert result.accepted
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )


def test_target_is_preserved(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(mfa=True),
        target="https://target.example",
    )

    assert result.findings
    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_endpoint_is_preserved(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(otp=True),
        target="https://example.com",
        endpoint="/login/verify",
    )

    assert result.findings
    assert all(
        finding.endpoint == "/login/verify"
        for finding in result.findings
    )


@pytest.mark.parametrize(
    "indicator",
    [
        "mfa",
        "otp",
        "totp",
        "sms_mfa",
        "email_mfa",
        "recovery_code",
        "backup_code",
        "remember_device",
        "trusted_device",
        "bypass_indicator",
        "enrollment",
        "disable",
        "verification",
    ],
)
def test_each_indicator_can_reach_pipeline(
    pipeline,
    analyzer,
    indicator,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    analysis = analyzer.analyze(**{indicator: True})

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.com",
    )

    assert analysis.detected
    assert result.accepted
    assert result.findings


def test_multiple_indicators(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(
        status_code=403,
        content=b"MFA required",
    )

    analysis = analyzer.analyze(
        mfa=True,
        otp=True,
        totp=True,
        verification=True,
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) >= 1


def test_pipeline_uses_custom_validator(
    analyzer,
):
    class CustomValidator:
        def compare(
            self,
            baseline,
            candidate,
            analysis,
            *,
            behavior_changed=False,
        ):
            from m_hunter.validation.mfa import MFAValidationResult

            return MFAValidationResult(
                baseline_status=baseline.status_code,
                candidate_status=candidate.status_code,
                status_changed=False,
                content_changed=False,
                content_length_changed=False,
                headers_changed=False,
                response_changed=False,
                behavior_changed=True,
                potential_mfa_issue=True,
                status="behavior_changed",
                evidence="custom validator",
            )

    pipeline = MFAValidationPipeline(
        validator=CustomValidator(),
    )

    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(mfa=True),
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.evidence == "custom validator"


def test_pipeline_uses_custom_finding_analyzer(
    analyzer,
):
    class CustomFindingAnalyzer:
        def analyze(
            self,
            *,
            analysis,
            target,
            endpoint=None,
        ):
            return []

    pipeline = MFAValidationPipeline(
        finding_analyzer=CustomFindingAnalyzer(),
    )

    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(mfa=True),
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings == []


@pytest.mark.parametrize(
    "target",
    ["", "   ", None, 123],
)
def test_invalid_target(
    pipeline,
    analyzer,
    target,
):
    response = make_response()

    with pytest.raises((TypeError, ValueError)):
        pipeline.process(
            response,
            response,
            analyzer.analyze(),
            target=target,
        )


@pytest.mark.parametrize(
    "endpoint",
    [123, [], {}, True],
)
def test_invalid_endpoint(
    pipeline,
    analyzer,
    endpoint,
):
    response = make_response()

    with pytest.raises(TypeError):
        pipeline.process(
            response,
            response,
            analyzer.analyze(),
            target="https://example.com",
            endpoint=endpoint,
        )


def test_invalid_baseline(
    pipeline,
    analyzer,
):
    with pytest.raises(TypeError):
        pipeline.process(
            "invalid",
            make_response(),
            analyzer.analyze(),
            target="https://example.com",
        )


def test_invalid_candidate(
    pipeline,
    analyzer,
):
    with pytest.raises(TypeError):
        pipeline.process(
            make_response(),
            "invalid",
            analyzer.analyze(),
            target="https://example.com",
        )


def test_invalid_analysis(
    pipeline,
):
    response = make_response()

    with pytest.raises(TypeError):
        pipeline.process(
            response,
            response,
            object(),
            target="https://example.com",
        )


def test_custom_validator_can_return_behavior_change(
    analyzer,
):
    class Validator:
        def compare(
            self,
            baseline,
            candidate,
            analysis,
            *,
            behavior_changed=False,
        ):
            from m_hunter.validation.mfa import MFAValidationResult

            return MFAValidationResult(
                baseline_status=200,
                candidate_status=200,
                status_changed=False,
                content_changed=False,
                content_length_changed=False,
                headers_changed=False,
                response_changed=False,
                behavior_changed=True,
                potential_mfa_issue=True,
                status="behavior_changed",
                evidence="behavior",
            )

    pipeline = MFAValidationPipeline(
        validator=Validator(),
    )

    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(mfa=True),
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.behavior_changed
    assert result.findings
