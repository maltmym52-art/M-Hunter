import pytest

from m_hunter.analyzers.hpp import HPPAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.hpp_pipeline import (
    HPPPipelineResult,
    HPPValidationPipeline,
)


def make_response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/api/test",
        headers=headers or {"content-type": "application/json"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def analyzer():
    return HPPAnalyzer()


@pytest.fixture
def pipeline():
    return HPPValidationPipeline()


def test_no_indicator_rejected(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(),
        make_response(),
        analyzer.analyze(),
        target="https://example.com",
    )

    assert isinstance(result, HPPPipelineResult)
    assert not result.accepted
    assert result.findings == []
    assert result.validation.status == "no_indicator"


def test_indicator_without_change_rejected(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    result = pipeline.process(
        make_response(),
        make_response(),
        analysis,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []
    assert result.validation.status == "indicator_detected"


def test_response_change_accepts(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    result = pipeline.process(
        make_response(content=b"before"),
        make_response(content=b"after"),
        analysis,
        target="https://example.com",
        endpoint="/search",
    )

    assert result.accepted
    assert result.findings
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )
    assert all(
        finding.target == "https://example.com"
        for finding in result.findings
    )
    assert all(
        finding.endpoint == "/search"
        for finding in result.findings
    )


def test_behavior_change_accepts(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        body="role=user&role=admin"
    )

    result = pipeline.process(
        make_response(),
        make_response(),
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted
    assert result.validation.behavior_changed
    assert result.findings


@pytest.mark.parametrize(
    "analysis_input",
    [
        {"url": "https://example.com/?id=1&id=2"},
        {"body": "role=user&role=admin"},
        {"params": {"id": ["1", "2"]}},
        {"url": "https://example.com/?a=1&a=2"},
    ],
)
def test_hpp_indicators_can_be_accepted(
    pipeline,
    analyzer,
    analysis_input,
):
    analysis = analyzer.analyze(**analysis_input)

    result = pipeline.process(
        make_response(content=b"before"),
        make_response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_status_change_accepts(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    result = pipeline.process(
        make_response(status_code=200),
        make_response(status_code=400),
        analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.potential_hpp_issue


def test_findings_not_created_when_rejected(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    result = pipeline.process(
        make_response(),
        make_response(),
        analysis,
        target="https://example.com",
    )

    assert not result.accepted
    assert result.findings == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"baseline": object()},
        {"candidate": object()},
        {"analysis": object()},
    ],
)
def test_invalid_arguments_rejected(
    pipeline,
    analyzer,
    kwargs,
):
    values = {
        "baseline": make_response(),
        "candidate": make_response(),
        "analysis": analyzer.analyze(),
        "target": "https://example.com",
    }
    values.update(kwargs)

    with pytest.raises(TypeError):
        pipeline.process(**values)


@pytest.mark.parametrize(
    "target",
    ["", "   "],
)
def test_empty_target_rejected(
    pipeline,
    analyzer,
    target,
):
    with pytest.raises(ValueError):
        pipeline.process(
            make_response(),
            make_response(),
            analyzer.analyze(),
            target=target,
        )


def test_endpoint_optional(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    result = pipeline.process(
        make_response(content=b"one"),
        make_response(content=b"two"),
        analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings
    assert all(
        finding.endpoint is None
        for finding in result.findings
    )


def test_multiple_indicators_produce_multiple_findings(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2",
        params={"role": ["user", "admin"]},
        body="token=a&token=b",
    )

    result = pipeline.process(
        make_response(content=b"before"),
        make_response(content=b"after"),
        analysis,
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) >= 4


def test_custom_validator_and_finding_analyzer(
    analyzer,
):
    class MockValidator:
        def compare(
            self,
            baseline,
            candidate,
            analysis,
            *,
            behavior_changed=False,
        ):
            from m_hunter.validation.hpp import HPPValidationResult

            return HPPValidationResult(
                baseline_status=200,
                candidate_status=200,
                status_changed=False,
                content_changed=False,
                content_length_changed=False,
                headers_changed=False,
                response_changed=False,
                behavior_changed=behavior_changed,
                potential_hpp_issue=behavior_changed,
                status=(
                    "potential_hpp_issue"
                    if behavior_changed
                    else "indicator_detected"
                ),
                evidence=[],
            )

    class MockFindingAnalyzer:
        def analyze(
            self,
            analysis,
            *,
            target,
            endpoint=None,
        ):
            return []

    pipeline = HPPValidationPipeline(
        validator=MockValidator(),
        finding_analyzer=MockFindingAnalyzer(),
    )

    result = pipeline.process(
        make_response(),
        make_response(),
        analyzer.analyze(
            url="https://example.com/?id=1&id=2"
        ),
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted
    assert result.findings == []
