import pytest

from m_hunter.analyzers.saml import SAMLAnalyzer
from m_hunter.analyzers.saml_finding import SAMLFindingAnalyzer
from m_hunter.core.response import HttpResponse
from m_hunter.validation.saml import SAMLValidator
from m_hunter.validation.saml_pipeline import (
    SAMLPipelineResult,
    SAMLValidationPipeline,
)


@pytest.fixture
def analyzer():
    return SAMLAnalyzer()


@pytest.fixture
def pipeline():
    return SAMLValidationPipeline()


def make_response(
    *,
    status_code=200,
    url="https://example.com/sso",
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


def test_pipeline_returns_result(
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

    assert isinstance(result, SAMLPipelineResult)


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


def test_indicator_without_behavior_change_is_not_accepted(
    pipeline,
    analyzer,
):
    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(
            issuer="idp.example",
        ),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "indicator_detected"


def test_response_change_accepts_saml_issue(
    pipeline,
    analyzer,
):
    baseline = make_response(content=b"baseline")
    candidate = make_response(content=b"candidate")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            issuer="idp.example",
        ),
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings
    assert result.validation.potential_saml_issue


def test_status_change_accepts(
    pipeline,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=403)

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            assertion="assertion",
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_header_change_accepts(
    pipeline,
    analyzer,
):
    baseline = make_response(
        headers={"content-type": "text/html"}
    )
    candidate = make_response(
        headers={
            "content-type": "text/html",
            "x-test": "changed",
        }
    )

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            issuer="idp",
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings


def test_behavior_change_accepts(
    pipeline,
    analyzer,
):
    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(
            assertion="assertion",
            signed_assertion=False,
        ),
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted
    assert result.findings
    assert result.validation.behavior_changed


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


def test_unsigned_assertion_finding(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            assertion="assertion",
            signed_assertion=False,
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert any(
        finding.cwe == "CWE-347"
        and finding.severity == "High"
        for finding in result.findings
    )


def test_weak_signature_algorithm_finding(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            signature_algorithm="rsa-sha1",
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert any(
        finding.cwe == "CWE-327"
        and finding.severity == "High"
        for finding in result.findings
    )


def test_endpoint_is_passed_to_findings(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            issuer="idp",
        ),
        target="https://example.com",
        endpoint="/saml/acs",
    )

    assert result.accepted
    assert result.findings
    assert all(
        finding.endpoint == "/saml/acs"
        for finding in result.findings
    )


def test_target_is_passed_to_findings(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            audience="sp",
        ),
        target="https://target.example",
    )

    assert result.findings
    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_multiple_indicators_create_multiple_findings(
    pipeline,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            issuer="idp",
            audience="sp",
            name_id="user",
            assertion="assertion",
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert len(result.findings) >= 4


def test_pipeline_uses_default_validator(
    pipeline,
):
    assert isinstance(pipeline.validator, SAMLValidator)


def test_pipeline_uses_default_finding_analyzer(
    pipeline,
):
    assert isinstance(
        pipeline.finding_analyzer,
        SAMLFindingAnalyzer,
    )


def test_custom_validator_is_used(
    analyzer,
):
    class CustomValidator(SAMLValidator):
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
                behavior_changed=True,
            )

    pipeline = SAMLValidationPipeline(
        validator=CustomValidator(),
    )

    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(
            issuer="idp",
        ),
        target="https://example.com",
    )

    assert result.validation.behavior_changed
    assert result.accepted


def test_custom_finding_analyzer_is_used(
    analyzer,
):
    class CustomFindingAnalyzer(SAMLFindingAnalyzer):
        def analyze(
            self,
            analysis,
            *,
            target,
            endpoint=None,
        ):
            return []

    pipeline = SAMLValidationPipeline(
        finding_analyzer=CustomFindingAnalyzer(),
    )

    baseline = make_response()
    candidate = make_response(content=b"changed")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            issuer="idp",
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert result.findings == []


def test_content_length_change_accepts(
    pipeline,
    analyzer,
):
    baseline = make_response(content=b"a")
    candidate = make_response(content=b"this is longer")

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            assertion="assertion",
        ),
        target="https://example.com",
    )

    assert result.accepted
    assert result.validation.content_length_changed


def test_identical_response_with_weak_algorithm_not_accepted(
    pipeline,
    analyzer,
):
    response = make_response()

    result = pipeline.process(
        response,
        response,
        analyzer.analyze(
            signature_algorithm="rsa-sha1",
        ),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_pipeline_preserves_validation_result(
    pipeline,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=302)

    result = pipeline.process(
        baseline,
        candidate,
        analyzer.analyze(
            issuer="idp",
        ),
        target="https://example.com",
    )

    assert result.validation.baseline_status == 200
    assert result.validation.candidate_status == 302
    assert result.validation.status_changed
    assert result.accepted


def test_invalid_analysis_type(
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
    pipeline,
    analyzer,
    target,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    with pytest.raises((ValueError, TypeError)):
        pipeline.process(
            baseline,
            candidate,
            analyzer.analyze(issuer="idp"),
            target=target,
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
    pipeline,
    analyzer,
    endpoint,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    with pytest.raises(TypeError):
        pipeline.process(
            baseline,
            candidate,
            analyzer.analyze(issuer="idp"),
            target="https://example.com",
            endpoint=endpoint,
        )


@pytest.mark.parametrize(
    "value",
    [None, 1, "true", [], {}],
)
def test_invalid_behavior_changed(
    pipeline,
    analyzer,
    value,
):
    baseline = make_response()
    candidate = make_response(content=b"changed")

    with pytest.raises(TypeError):
        pipeline.process(
            baseline,
            candidate,
            analyzer.analyze(issuer="idp"),
            target="https://example.com",
            behavior_changed=value,
        )
