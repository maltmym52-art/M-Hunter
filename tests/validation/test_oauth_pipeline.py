import pytest

from m_hunter.analyzers.oauth import OAuthAnalyzer
from m_hunter.analyzers.oauth_finding import OAuthFindingAnalyzer
from m_hunter.validation.oauth import OAuthValidator
from m_hunter.validation.oauth_pipeline import (
    OAuthPipelineResult,
    OAuthValidationPipeline,
)


@pytest.fixture
def analyzer():
    return OAuthAnalyzer()


@pytest.fixture
def pipeline():
    return OAuthValidationPipeline()


def test_empty_analysis_is_not_accepted(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze()

    result = pipeline.process(
        analysis,
        target="https://example.com",
    )

    assert isinstance(result, OAuthPipelineResult)
    assert result.accepted is False
    assert result.findings == ()
    assert result.validation.status == "no_indicator"


def test_indicator_without_behavior_is_not_accepted(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == ()
    assert result.validation.status == "indicator_detected"


def test_behavior_change_accepts_result(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        state="random-state-value",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        endpoint="/oauth/authorize",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert result.validation.potential_oauth_issue is True
    assert result.findings


def test_status_change_accepts_result(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        redirect_uri="https://client.example/callback",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        baseline_status=302,
        candidate_status=200,
    )

    assert result.accepted is True
    assert result.validation.status_changed is True
    assert result.findings


def test_content_change_accepts_result(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        response_type="code",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        baseline_content="authorization page",
        candidate_content="different response",
    )

    assert result.accepted is True
    assert result.validation.content_changed is True
    assert result.findings


def test_header_change_accepts_result(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        baseline_headers={
            "Location": "https://client.example/callback"
        },
        candidate_headers={
            "Location": "https://other.example/callback"
        },
    )

    assert result.accepted is True
    assert result.validation.headers_changed is True
    assert result.findings


def test_findings_have_target(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        fragment="access_token=secret",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        endpoint="/oauth/callback",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert result.findings

    for finding in result.findings:
        assert finding.target == "https://example.com"


def test_findings_have_endpoint(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        endpoint="/oauth/authorize",
        behavior_changed=True,
    )

    assert result.findings

    for finding in result.findings:
        assert finding.endpoint == "/oauth/authorize"


def test_token_in_url_produces_finding(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        fragment="access_token=secret",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert any(
        finding.cwe == "CWE-598"
        for finding in result.findings
    )


def test_weak_state_produces_finding(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        state="abc",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert any(
        finding.cwe == "CWE-330"
        for finding in result.findings
    )


def test_missing_nonce_produces_finding(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        response_type="id_token",
        expected_nonce=True,
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert any(
        finding.cwe == "CWE-352"
        for finding in result.findings
    )


def test_multiple_indicators_produce_multiple_findings(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
        state="abc",
        fragment="access_token=secret",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert len(result.findings) >= 3


def test_pipeline_does_not_generate_findings_without_acceptance(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
        state="abc",
        fragment="access_token=secret",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == ()


def test_same_status_and_content_are_not_accepted(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        baseline_status=302,
        candidate_status=302,
        baseline_content="same",
        candidate_content="same",
        baseline_headers={"Location": "/callback"},
        candidate_headers={"Location": "/callback"},
    )

    assert result.accepted is False
    assert result.findings == ()


def test_behavior_change_overrides_missing_response_data(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        response_type="code",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert result.findings


def test_pipeline_accepts_custom_validator(
    analyzer,
):
    validator = OAuthValidator()
    finding_analyzer = OAuthFindingAnalyzer()

    pipeline = OAuthValidationPipeline(
        validator=validator,
        finding_analyzer=finding_analyzer,
    )

    analysis = analyzer.analyze(
        client_id="client",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert result.findings


def test_pipeline_result_is_immutable(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
    )

    with pytest.raises(AttributeError):
        result.accepted = True


def test_invalid_analysis_type(pipeline):
    with pytest.raises(TypeError):
        pipeline.process(
            object(),
            target="https://example.com",
        )


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        None,
        123,
    ],
)
def test_invalid_target(
    analyzer,
    pipeline,
    target,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    with pytest.raises(
        ValueError if isinstance(target, str)
        else (ValueError, TypeError)
    ):
        pipeline.process(
            analysis,
            target=target,
            behavior_changed=True,
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        123,
        [],
        {},
    ],
)
def test_invalid_endpoint(
    analyzer,
    pipeline,
    endpoint,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    with pytest.raises(TypeError):
        pipeline.process(
            analysis,
            target="https://example.com",
            endpoint=endpoint,
            behavior_changed=True,
        )


def test_pipeline_validation_is_exposed(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        baseline_status=302,
        candidate_status=200,
    )

    assert result.validation is not None
    assert result.validation.status_changed is True


def test_pipeline_findings_are_tuple(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert isinstance(result.findings, tuple)


def test_pipeline_is_deterministic(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        client_id="client",
        state="abc",
    )

    first = pipeline.process(
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )
    second = pipeline.process(
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert first.accepted == second.accepted
    assert first.validation.status == second.validation.status
    assert [
        (
            finding.title,
            finding.severity,
            finding.confidence,
            finding.cwe,
            finding.evidence,
        )
        for finding in first.findings
    ] == [
        (
            finding.title,
            finding.severity,
            finding.confidence,
            finding.cwe,
            finding.evidence,
        )
        for finding in second.findings
    ]


def test_pipeline_handles_all_oauth_indicators(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        url=(
            "https://example.com/authorize"
            "?client_id=client"
            "&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback"
            "&response_type=token"
            "&scope=openid"
            "&state=abc"
        ),
        nonce=None,
        expected_nonce=True,
        fragment="access_token=secret",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        endpoint="/authorize",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert len(result.findings) >= 5


def test_pipeline_preserves_validation_evidence(
    analyzer,
    pipeline,
):
    analysis = analyzer.analyze(
        state="abc",
    )

    result = pipeline.process(
        analysis,
        target="https://example.com",
        baseline_status=302,
        candidate_status=200,
    )

    assert result.validation.evidence
    assert any(
        "status codes differ" in item
        for item in result.validation.evidence
    )
