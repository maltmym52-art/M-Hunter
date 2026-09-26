import pytest

from m_hunter.analyzers.open_redirect import OpenRedirectAnalyzer
from m_hunter.core.response import HttpResponse
from m_hunter.validation.open_redirect import OpenRedirectValidator
from m_hunter.validation.open_redirect_pipeline import (
    OpenRedirectPipeline,
    OpenRedirectPipelineResult,
)


def make_response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/test",
        headers=headers or {"content-type": "application/json"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def analyzer():
    return OpenRedirectAnalyzer()


@pytest.fixture
def validator():
    return OpenRedirectValidator()


@pytest.fixture
def pipeline():
    return OpenRedirectPipeline()


def test_no_findings(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze()

    result = pipeline.run(
        analysis,
        target="https://example.com",
    )

    assert isinstance(result, OpenRedirectPipelineResult)
    assert result.findings == []
    assert result.validation is None
    assert result.status == "no_findings"


def test_findings_without_validation(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example"}
    )

    result = pipeline.run(
        analysis,
        target="https://example.com",
        endpoint="/login",
    )

    assert result.findings
    assert result.validation is None
    assert result.status == "findings"


def test_potential_open_redirect(
    pipeline,
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example"}
    )

    validation = validator.compare(
        make_response(status_code=200),
        make_response(status_code=302),
        analysis,
    )

    result = pipeline.run(
        analysis,
        target="https://example.com",
        endpoint="/login",
        validation=validation,
    )

    assert result.findings
    assert result.validation is validation
    assert result.status == "potential_open_redirect"


def test_behavior_changed(
    pipeline,
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        params={"next": "https://other.example"}
    )

    validation = validator.compare(
        make_response(),
        make_response(),
        analysis,
        behavior_changed=True,
    )

    assert validation.potential_open_redirect

    result = pipeline.run(
        analysis,
        target="https://example.com",
        validation=validation,
    )

    assert result.status == "potential_open_redirect"


def test_response_changed_without_indicator(
    pipeline,
    analyzer,
    validator,
):
    analysis = analyzer.analyze()

    validation = validator.compare(
        make_response(content=b"before"),
        make_response(content=b"after"),
        analysis,
    )

    result = pipeline.run(
        analysis,
        target="https://example.com",
        validation=validation,
    )

    assert result.findings == []
    assert result.status == "response_changed"


def test_findings_with_indicator_but_no_validation_change(
    pipeline,
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://other.example"}
    )

    validation = validator.compare(
        make_response(),
        make_response(),
        analysis,
    )

    result = pipeline.run(
        analysis,
        target="https://example.com",
        validation=validation,
    )

    assert result.findings
    assert result.status == "findings"


def test_endpoint_is_preserved(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"return_url": "https://other.example"}
    )

    result = pipeline.run(
        analysis,
        target="https://example.com",
        endpoint="/redirect",
    )

    assert result.findings
    assert all(
        finding.endpoint == "/redirect"
        for finding in result.findings
    )


@pytest.mark.parametrize(
    "bad_analysis",
    [None, object(), "analysis"],
)
def test_invalid_analysis(
    pipeline,
    bad_analysis,
):
    with pytest.raises(TypeError):
        pipeline.run(
            bad_analysis,
            target="https://example.com",
        )


@pytest.mark.parametrize(
    "bad_target",
    [None, "", "   ", 123],
)
def test_invalid_target(
    pipeline,
    analyzer,
    bad_target,
):
    with pytest.raises(TypeError):
        pipeline.run(
            analyzer.analyze(),
            target=bad_target,
        )


@pytest.mark.parametrize(
    "bad_endpoint",
    [123, object(), False],
)
def test_invalid_endpoint(
    pipeline,
    analyzer,
    bad_endpoint,
):
    with pytest.raises(TypeError):
        pipeline.run(
            analyzer.analyze(),
            target="https://example.com",
            endpoint=bad_endpoint,
        )


@pytest.mark.parametrize(
    "bad_validation",
    [object(), "validation", 123],
)
def test_invalid_validation(
    pipeline,
    analyzer,
    bad_validation,
):
    with pytest.raises(TypeError):
        pipeline.run(
            analyzer.analyze(),
            target="https://example.com",
            validation=bad_validation,
        )


@pytest.mark.parametrize(
    "params",
    [
        {"redirect": "https://other.example"},
        {"url": "https://other.example"},
        {"return_url": "https://other.example"},
        {"next": "https://other.example"},
        {"continue": "https://other.example"},
        {"destination": "https://other.example"},
    ],
)
def test_pipeline_creates_findings_for_redirect_parameters(
    pipeline,
    analyzer,
    params,
):
    analysis = analyzer.analyze(params=params)

    result = pipeline.run(
        analysis,
        target="https://example.com",
        endpoint="/redirect",
    )

    assert result.findings
    assert result.status == "findings"
    assert all(finding.target == "https://example.com" for finding in result.findings)


def test_external_host_with_validation(
    pipeline,
    analyzer,
    validator,
):
    analysis = analyzer.analyze(
        params={"redirect": "https://evil.example"},
        target_host="example.com",
    )

    validation = validator.compare(
        make_response(),
        make_response(
            status_code=302,
            headers={
                "content-type": "text/html",
                "location": "https://evil.example",
            },
        ),
        analysis,
    )

    result = pipeline.run(
        analysis,
        target="https://example.com",
        endpoint="/redirect",
        validation=validation,
    )

    assert result.findings
    assert result.status == "potential_open_redirect"
    assert result.validation is validation
