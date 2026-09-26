import pytest

from m_hunter.analyzers.host_header_injection import (
    HostHeaderInjectionAnalyzer,
)
from m_hunter.analyzers.host_header_injection_finding import (
    HostHeaderInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.host_header_injection import (
    HostHeaderInjectionValidator,
)
from m_hunter.validation.host_header_injection_pipeline import (
    HostHeaderInjectionPipelineResult,
    HostHeaderInjectionValidationPipeline,
)


def make_response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
    repeated_headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.test",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
        repeated_headers=repeated_headers or {},
    )


@pytest.fixture
def analyzer():
    return HostHeaderInjectionAnalyzer()


@pytest.fixture
def pipeline():
    return HostHeaderInjectionValidationPipeline()


def test_no_indicator_not_accepted(pipeline, analyzer):
    result = pipeline.process(
        make_response(),
        make_response(),
        analyzer.analyze(),
        target="https://example.test",
    )

    assert isinstance(result, HostHeaderInjectionPipelineResult)
    assert result.accepted is False
    assert result.findings == []


def test_indicator_without_change_not_accepted(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(),
        make_response(),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
        target="https://example.test",
    )

    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "indicator_detected"


def test_response_change_accepts_indicator(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(status_code=200),
        make_response(status_code=302),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
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
    result = pipeline.process(
        make_response(content=b"before"),
        make_response(content=b"after-content"),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.validation.content_changed is True


def test_header_change_accepts_indicator(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(
            headers={"X-Test": "one"},
        ),
        make_response(
            headers={"X-Test": "two"},
        ),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.validation.headers_changed is True


def test_behavior_change_accepts_indicator(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(),
        make_response(),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
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
    result = pipeline.process(
        make_response(),
        make_response(),
        analyzer.analyze(),
        target="https://example.test",
        behavior_changed=True,
    )

    assert result.accepted is False
    assert result.findings == []


def test_findings_use_target_and_endpoint(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(),
        make_response(status_code=302),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
        target="https://example.test",
        endpoint="/reset",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        finding.target == "https://example.test"
        for finding in result.findings
    )
    assert all(
        finding.endpoint == "/reset"
        for finding in result.findings
    )


def test_custom_validator_is_used(analyzer):
    class CustomValidator(HostHeaderInjectionValidator):
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

    pipeline = HostHeaderInjectionValidationPipeline(
        validator=CustomValidator(),
    )

    result = pipeline.process(
        make_response(),
        make_response(status_code=302),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
        target="https://example.test",
    )

    assert result.accepted is True


def test_custom_finding_analyzer_is_used(analyzer):
    class CustomFindingAnalyzer(HostHeaderInjectionFindingAnalyzer):
        def analyze(self, analysis, *, target, endpoint=None):
            return []

    pipeline = HostHeaderInjectionValidationPipeline(
        finding_analyzer=CustomFindingAnalyzer(),
    )

    result = pipeline.process(
        make_response(),
        make_response(status_code=302),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
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
                headers={"Host": "attacker.test"},
            ),
            target="",
        )


def test_invalid_endpoint(pipeline, analyzer):
    with pytest.raises(TypeError):
        pipeline.process(
            make_response(),
            make_response(),
            analyzer.analyze(
                headers={"Host": "attacker.test"},
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
                headers={"Host": "attacker.test"},
            ),
            target="https://example.test",
            behavior_changed="yes",
        )


def test_location_indicator_pipeline(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(
            headers={
                "Location": "https://example.test/a",
            },
        ),
        make_response(
            headers={
                "Location": "https://example.test/b",
            },
        ),
        analyzer.analyze(
            response_headers={
                "Location": "https://example.test/a",
            },
        ),
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.findings


def test_password_reset_indicator_pipeline(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(),
        make_response(
            content=b"Password reset link changed",
        ),
        analyzer.analyze(
            response_body="Password reset link",
        ),
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.findings


def test_external_host_indicator_pipeline(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(),
        make_response(),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
            expected_host="example.test",
        ),
        target="https://example.test",
        behavior_changed=True,
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
            headers={"Host": "attacker.test"},
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
            headers={"Host": "attacker.test"},
        ),
        target="https://example.test",
    )

    assert result.accepted is False
    assert result.findings == []


def test_pipeline_accepts_response_header_change(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(
            headers={
                "Location": "https://example.test/a",
            },
        ),
        make_response(
            headers={
                "Location": "https://example.test/b",
            },
        ),
        analyzer.analyze(
            response_headers={
                "Location": "https://example.test/a",
            },
        ),
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.validation.headers_changed is True


def test_pipeline_accepts_content_length_change(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(content=b"one"),
        make_response(content=b"changed"),
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
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
            headers={"Host": "attacker.test"},
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
            headers={"Host": "attacker.test"},
        ),
        target="https://example.test",
    )

    assert isinstance(result.findings, list)


def test_repeated_header_change_accepts_indicator(
    pipeline,
    analyzer,
):
    baseline = make_response(
        repeated_headers={"Set-Cookie": ["a=1"]},
    )
    candidate = make_response(
        repeated_headers={"Set-Cookie": ["a=1", "b=2"]},
    )

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            headers={"Host": "attacker.test"},
        ),
        target="https://example.test",
    )

    assert result.accepted is True
    assert result.validation.headers_changed is True
