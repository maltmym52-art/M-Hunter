import pytest

from m_hunter.analyzers.ldap_injection import LDAPInjectionAnalyzer
from m_hunter.analyzers.ldap_injection_finding import (
    LDAPInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.ldap_injection import (
    LDAPInjectionValidator,
)
from m_hunter.validation.ldap_injection_pipeline import (
    LDAPInjectionPipelineResult,
    LDAPInjectionValidationPipeline,
)


def make_response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/search",
        headers=headers or {"content-type": "text/plain"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def analyzer():
    return LDAPInjectionAnalyzer()


@pytest.fixture
def pipeline():
    return LDAPInjectionValidationPipeline()


def test_no_indicator_is_rejected(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze()

    result = pipeline.process(
        make_response(),
        make_response(),
        analysis,
        target="https://example.com",
    )

    assert isinstance(result, LDAPInjectionPipelineResult)
    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "no_indicator"


def test_indicator_without_change_is_rejected(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    result = pipeline.process(
        make_response(),
        make_response(),
        analysis,
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []
    assert result.validation.status == "indicator_detected"


def test_response_change_is_accepted(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    result = pipeline.process(
        make_response(content=b"before"),
        make_response(content=b"after-changed"),
        analysis,
        target="https://example.com",
        endpoint="/search",
    )

    assert result.accepted is True
    assert result.findings
    assert all(
        isinstance(finding, Finding)
        for finding in result.findings
    )


def test_status_change_is_accepted(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"ldap_filter": "(uid=admin)"}
    )

    result = pipeline.process(
        make_response(status_code=200),
        make_response(status_code=500),
        analysis,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_behavior_change_is_accepted(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    result = pipeline.process(
        make_response(),
        make_response(),
        analysis,
        target="https://example.com",
        endpoint="/search",
        behavior_changed=True,
    )

    assert result.accepted is True
    assert result.validation.behavior_changed is True
    assert result.findings


def test_behavior_change_without_indicator_is_rejected(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze()

    result = pipeline.process(
        make_response(),
        make_response(),
        analysis,
        target="https://example.com",
        behavior_changed=True,
    )

    assert result.accepted is False
    assert result.findings == []


@pytest.mark.parametrize(
    "params",
    [
        {"filter": "(uid=admin)"},
        {"ldap_filter": "(&(uid=test)(objectClass=*))"},
        {"search": "(uid~=test)"},
        {"dn": "(uid>=test)"},
        {"uid": "(uid<=test)"},
    ],
)
def test_ldap_indicators_can_be_accepted(
    pipeline,
    analyzer,
    params,
):
    analysis = analyzer.analyze(params=params)

    result = pipeline.process(
        make_response(),
        make_response(content=b"changed-content"),
        analysis,
        target="https://example.com",
    )

    assert analysis.detected
    assert result.accepted is True
    assert result.findings


def test_ldap_query_is_accepted(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        ldap_query="(&(uid=admin)(objectClass=*))"
    )

    result = pipeline.process(
        make_response(),
        make_response(status_code=500),
        analysis,
        target="https://example.com",
        endpoint="/ldap",
    )

    assert result.accepted is True
    assert result.findings


def test_response_ldap_error_is_accepted(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        response_body="LDAPException: invalid filter"
    )

    result = pipeline.process(
        make_response(),
        make_response(content=b"error-response"),
        analysis,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_endpoint_is_passed_to_findings(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    result = pipeline.process(
        make_response(),
        make_response(content=b"changed"),
        analysis,
        target="https://example.com",
        endpoint="/ldap/search",
    )

    assert result.findings
    assert all(
        finding.endpoint == "/ldap/search"
        for finding in result.findings
    )


def test_target_is_passed_to_findings(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    result = pipeline.process(
        make_response(),
        make_response(content=b"changed"),
        analysis,
        target="https://target.example",
    )

    assert result.findings
    assert all(
        finding.target == "https://target.example"
        for finding in result.findings
    )


def test_multiple_indicator_types_produce_findings(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={
            "filter": "(&(uid=admin)(objectClass=*))"
        }
    )

    result = pipeline.process(
        make_response(),
        make_response(content=b"changed-content"),
        analysis,
        target="https://example.com",
    )

    assert result.accepted is True
    assert len(result.findings) >= 4


def test_headers_change_is_accepted(
    pipeline,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    result = pipeline.process(
        make_response(
            headers={"content-type": "text/plain"}
        ),
        make_response(
            headers={
                "content-type": "text/plain",
                "x-ldap-test": "changed",
            }
        ),
        analysis,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_custom_validator():
    class MockValidator:
        def compare(
            self,
            baseline,
            candidate,
            analysis,
            *,
            behavior_changed=False,
        ):
            from m_hunter.validation.ldap_injection import (
                LDAPInjectionValidationResult,
            )

            return LDAPInjectionValidationResult(
                baseline_status=200,
                candidate_status=200,
                status_changed=False,
                content_changed=False,
                content_length_changed=False,
                headers_changed=False,
                response_changed=False,
                behavior_changed=True,
                potential_ldap_injection=True,
                status="potential_ldap_injection",
                evidence="mock",
            )

    pipeline = LDAPInjectionValidationPipeline(
        validator=MockValidator()
    )

    analysis = LDAPInjectionAnalyzer().analyze(
        params={"filter": "(uid=admin)"}
    )

    result = pipeline.process(
        make_response(),
        make_response(),
        analysis,
        target="https://example.com",
    )

    assert result.accepted is True
    assert result.findings


def test_custom_finding_analyzer():
    class MockFindingAnalyzer:
        def analyze(self, *, analysis, target, endpoint=None):
            return [
                Finding(
                    title="Mock",
                    severity="Low",
                    confidence="High",
                    target=target,
                    endpoint=endpoint,
                )
            ]

    pipeline = LDAPInjectionValidationPipeline(
        finding_analyzer=MockFindingAnalyzer()
    )

    analysis = LDAPInjectionAnalyzer().analyze(
        params={"filter": "(uid=admin)"}
    )

    result = pipeline.process(
        make_response(),
        make_response(content=b"changed"),
        analysis,
        target="https://example.com",
        endpoint="/test",
    )

    assert result.accepted is True
    assert len(result.findings) == 1
    assert result.findings[0].title == "Mock"


@pytest.mark.parametrize(
    "bad_baseline",
    [None, object(), "response"],
)
def test_invalid_baseline(
    pipeline,
    analyzer,
    bad_baseline,
):
    with pytest.raises(TypeError):
        pipeline.process(
            bad_baseline,
            make_response(),
            analyzer.analyze(),
            target="https://example.com",
        )


@pytest.mark.parametrize(
    "bad_candidate",
    [None, object(), "response"],
)
def test_invalid_candidate(
    pipeline,
    analyzer,
    bad_candidate,
):
    with pytest.raises(TypeError):
        pipeline.process(
            make_response(),
            bad_candidate,
            analyzer.analyze(),
            target="https://example.com",
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
        pipeline.process(
            make_response(),
            make_response(),
            bad_analysis,
            target="https://example.com",
        )


@pytest.mark.parametrize(
    "bad_target",
    [None, "", "   "],
)
def test_invalid_target(
    pipeline,
    analyzer,
    bad_target,
):
    with pytest.raises(ValueError):
        pipeline.process(
            make_response(),
            make_response(),
            analyzer.analyze(),
            target=bad_target,
        )


@pytest.mark.parametrize(
    "bad_endpoint",
    [123, [], {}],
)
def test_invalid_endpoint(
    pipeline,
    analyzer,
    bad_endpoint,
):
    with pytest.raises(TypeError):
        pipeline.process(
            make_response(),
            make_response(),
            analyzer.analyze(),
            target="https://example.com",
            endpoint=bad_endpoint,
        )


@pytest.mark.parametrize(
    "bad_behavior",
    [None, "true", 1, [], {}],
)
def test_invalid_behavior_changed(
    pipeline,
    analyzer,
    bad_behavior,
):
    with pytest.raises(TypeError):
        pipeline.process(
            make_response(),
            make_response(),
            analyzer.analyze(),
            target="https://example.com",
            behavior_changed=bad_behavior,
        )


def test_validation_object_is_preserved(
    pipeline,
    analyzer,
):
    result = pipeline.process(
        make_response(),
        make_response(content=b"changed"),
        analyzer.analyze(
            params={"filter": "(uid=admin)"}
        ),
        target="https://example.com",
    )

    assert result.validation is not None
    assert result.validation.potential_ldap_injection is True
