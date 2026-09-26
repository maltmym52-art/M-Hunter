import pytest

from m_hunter.analyzers.crlf_injection import (
    CRLFInjectionAnalyzer,
)
from m_hunter.analyzers.crlf_injection_finding import (
    CRLFInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.crlf_injection import (
    CRLFInjectionValidator,
)
from m_hunter.validation.crlf_injection_pipeline import (
    CRLFInjectionPipelineResult,
    CRLFInjectionValidationPipeline,
)


def make_response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.test",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def analyzer():
    return CRLFInjectionAnalyzer()


@pytest.fixture
def finding_analyzer():
    return CRLFInjectionFindingAnalyzer()


@pytest.fixture
def pipeline():
    return CRLFInjectionValidationPipeline()


def test_no_indicator_not_accepted(pipeline, analyzer):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze()

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
    )

    assert isinstance(result, CRLFInjectionPipelineResult)
    assert result.accepted is False
    assert result.findings == []


def test_indicator_without_change_not_accepted(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
    )

    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "indicator_detected"


def test_response_change_accepts_indicator(
    pipeline,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=302)
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )


def test_content_change_accepts_indicator(
    pipeline,
    analyzer,
):
    baseline = make_response(content=b"before")
    candidate = make_response(content=b"after-content")
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.validation.content_changed is True


def test_header_change_accepts_indicator(
    pipeline,
    analyzer,
):
    baseline = make_response(
        headers={"X-Test": "one"},
    )
    candidate = make_response(
        headers={"X-Test": "two"},
    )
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.validation.headers_changed is True


def test_behavior_change_accepts_indicator(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert result.validation.behavior_changed is True
    assert result.findings


def test_behavior_change_without_indicator_not_accepted(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze()

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
        behavior_changed=True,
    )

    assert result.accepted is False
    assert result.findings == []


def test_findings_use_target_and_endpoint(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(
        status_code=302,
    )
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
        endpoint="/redirect",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        finding.target == "https://example.test"
        for finding in result.findings
    )
    assert all(
        finding.endpoint == "/redirect"
        for finding in result.findings
    )


def test_custom_validator_is_used(
    analyzer,
    finding_analyzer,
):
    class CustomValidator(CRLFInjectionValidator):
        def compare(
            self,
            baseline,
            candidate,
            analysis,
            *,
            behavior_changed=False,
        ):
            return super().compare(
                baseline,
                candidate,
                analysis,
                behavior_changed=behavior_changed,
            )

    custom = CustomValidator()

    pipeline = CRLFInjectionValidationPipeline(
        validator=custom,
        finding_analyzer=finding_analyzer,
    )

    result = pipeline.process(
        make_response(),
        make_response(status_code=302),
        analyzer.analyze(params={"next": "%0d%0a"}),
        target="https://example.test",
    )

    assert result.accepted is True


def test_custom_finding_analyzer_is_used(
    analyzer,
):
    class CustomFindingAnalyzer(CRLFInjectionFindingAnalyzer):
        def analyze(self, analysis, *, target, endpoint=None):
            return []

    pipeline = CRLFInjectionValidationPipeline(
        finding_analyzer=CustomFindingAnalyzer(),
    )

    result = pipeline.process(
        make_response(),
        make_response(status_code=302),
        analyzer.analyze(params={"next": "%0d%0a"}),
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.findings == []


def test_invalid_baseline(pipeline, analyzer):
    with pytest.raises(TypeError):
        pipeline.process(
            "invalid",
            make_response(),
            analyzer.analyze(),
            target="https://example.test",
        )


def test_invalid_candidate(pipeline, analyzer):
    with pytest.raises(TypeError):
        pipeline.process(
            make_response(),
            "invalid",
            analyzer.analyze(),
            target="https://example.test",
        )


def test_invalid_analysis(pipeline):
    with pytest.raises(TypeError):
        pipeline.process(
            make_response(),
            make_response(),
            "invalid",
            target="https://example.test",
        )


def test_empty_target(pipeline, analyzer):
    with pytest.raises(ValueError):
        pipeline.process(
            make_response(),
            make_response(),
            analyzer.analyze(
                params={"next": "%0d%0a"},
            ),
            target="",
        )


def test_invalid_endpoint(pipeline, analyzer):
    with pytest.raises(TypeError):
        pipeline.process(
            make_response(),
            make_response(),
            analyzer.analyze(
                params={"next": "%0d%0a"},
            ),
            target="https://example.test",
            endpoint=123,
        )


def test_invalid_behavior_flag(pipeline, analyzer):
    with pytest.raises(TypeError):
        pipeline.process(
            make_response(),
            make_response(),
            analyzer.analyze(
                params={"next": "%0d%0a"},
            ),
            target="https://example.test",
            behavior_changed="yes",
        )


def test_location_indicator_pipeline(
    pipeline,
    analyzer,
):
    baseline = make_response(
        headers={"Location": "https://example.test/a"},
    )
    candidate = make_response(
        headers={"Location": "https://example.test/b"},
    )
    analysis = analyzer.analyze(
        location="https://example.test/a",
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.findings


def test_set_cookie_indicator_pipeline(
    pipeline,
    analyzer,
):
    baseline = make_response(
        headers={"Set-Cookie": "a=1"},
    )
    candidate = make_response(
        headers={"Set-Cookie": "b=2"},
    )
    analysis = analyzer.analyze(
        set_cookie="a=1",
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.findings


def test_result_contains_validation(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(),
        make_response(status_code=302),
        analyzer.analyze(
            params={"next": "%0d%0a"},
        ),
        target="https://example.test",
    )

    assert isinstance(
        result.validation,
        type(
            pipeline.validator.compare(
                make_response(),
                make_response(),
                analyzer.analyze(),
            )
        ),
    )


def test_pipeline_does_not_create_findings_without_acceptance(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(),
        make_response(),
        analyzer.analyze(
            params={"next": "%0d%0a"},
        ),
        target="https://example.test",
    )

    assert result.accepted is False
    assert result.findings == []


def test_pipeline_accepts_response_header_change(
    pipeline,
    analyzer,
):
    baseline = make_response(
        headers={"Location": "https://example.test/a"},
    )
    candidate = make_response(
        headers={"Location": "https://example.test/b"},
    )
    analysis = analyzer.analyze(
        response_headers={
            "Location": "https://example.test/a",
        },
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.validation.headers_changed is True


def test_pipeline_accepts_content_length_change(
    pipeline,
    analyzer,
):
    baseline = make_response(content=b"one")
    candidate = make_response(content=b"changed")
    analysis = analyzer.analyze(
        params={"next": "%0d%0a"},
    )

    result = pipeline.process(
        baseline,
        candidate,
        analysis,
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.validation.content_length_changed is True


def test_pipeline_accepts_status_change(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(status_code=200),
        make_response(status_code=302),
        analyzer.analyze(
            params={"next": "%0d%0a"},
        ),
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.validation.status_changed is True


def test_pipeline_result_findings_are_list(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(status_code=200),
        make_response(status_code=302),
        analyzer.analyze(
            params={"next": "%0d%0a"},
        ),
        target="https://example.test",
    )

    assert isinstance(result.findings, list)
