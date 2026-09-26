import pytest

from m_hunter.analyzers.http_method_security import (
    HTTPMethodSecurityAnalysis,
    HTTPMethodSecurityAnalyzer,
    HTTPMethodSecurityIndicator,
    HTTPMethodSecurityIndicatorType,
)
from m_hunter.analyzers.http_method_security_finding import (
    HTTPMethodSecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return HTTPMethodSecurityFindingAnalyzer()


def make_analysis(*types):
    indicators = tuple(
        HTTPMethodSecurityIndicator(
            type=indicator_type,
            evidence=f"Evidence for {indicator_type.value}",
            name="method",
            value="DELETE",
        )
        for indicator_type in types
    )

    return HTTPMethodSecurityAnalysis(
        indicators=indicators,
    )


def test_empty_analysis_returns_no_findings(analyzer):
    result = analyzer.analyze(
        analysis=HTTPMethodSecurityAnalysis(
            indicators=(),
        ),
        target="https://example.com",
    )

    assert result == []


def test_requires_analysis(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis="invalid",
            target="https://example.com",
        )


def test_requires_target(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            analysis=HTTPMethodSecurityAnalysis(
                indicators=(),
            ),
            target="",
        )


def test_endpoint_must_be_string(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis=make_analysis(
                HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
            ),
            target="https://example.com",
            endpoint=123,
        )


@pytest.mark.parametrize(
    "indicator_type",
    list(HTTPMethodSecurityIndicatorType),
)
def test_each_indicator_generates_finding(
    analyzer,
    indicator_type,
):
    findings = analyzer.analyze(
        analysis=make_analysis(indicator_type),
        target="https://example.com",
        endpoint="/api/test",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.title
    assert finding.severity
    assert finding.confidence
    assert finding.target == "https://example.com"
    assert finding.endpoint == "/api/test"
    assert finding.description
    assert finding.evidence
    assert finding.remediation


def test_trace_enabled_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-693"


def test_track_enabled_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.TRACK_ENABLED,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "High"


def test_connect_enabled_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.CONNECT_ENABLED,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-441"


def test_override_header_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-436"


def test_override_parameter_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_PARAMETER,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Medium"


def test_options_is_not_critical(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.OPTIONS_EXPOSURE,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_allow_header_is_informational(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.ALLOW_HEADER,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_method_not_allowed_is_informational(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.METHOD_NOT_ALLOWED,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_multiple_types_create_multiple_findings(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
            HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER,
            HTTPMethodSecurityIndicatorType.ALLOW_HEADER,
        ),
        target="https://example.com",
    )

    assert len(findings) == 3


def test_same_type_is_grouped(analyzer):
    analysis = HTTPMethodSecurityAnalysis(
        indicators=(
            HTTPMethodSecurityIndicator(
                type=HTTPMethodSecurityIndicatorType.ALLOW_HEADER,
                evidence="Allow one",
                value="GET",
            ),
            HTTPMethodSecurityIndicator(
                type=HTTPMethodSecurityIndicatorType.ALLOW_HEADER,
                evidence="Allow two",
                value="GET, POST",
            ),
        )
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert len(findings) == 1
    assert "Allow one" in findings[0].evidence
    assert "Allow two" in findings[0].evidence


def test_indicator_details_are_preserved(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER,
        ),
        target="https://example.com",
    )[0]

    assert "name=method" in finding.evidence
    assert "value=DELETE" in finding.evidence


def test_description_contains_validation_disclaimer(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
        ),
        target="https://example.com",
    )[0]

    assert (
        "does not by itself prove a vulnerability"
        in finding.description
    )


def test_remediation_is_present(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.DANGEROUS_METHOD,
        ),
        target="https://example.com",
    )[0]

    assert "Restrict HTTP methods" in finding.remediation


def test_all_supported_types_have_metadata(analyzer):
    assert set(analyzer.METADATA) == set(
        HTTPMethodSecurityIndicatorType
    )


def test_findings_have_unique_ids(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
            HTTPMethodSecurityIndicatorType.CONNECT_ENABLED,
        ),
        target="https://example.com",
    )

    assert len({finding.id for finding in findings}) == 2


def test_real_analyzer_output_can_be_converted(analyzer):
    http_analyzer = HTTPMethodSecurityAnalyzer()

    from m_hunter.core.request import HttpRequest
    from m_hunter.core.response import HttpResponse

    analysis = http_analyzer.analyze(
        request=HttpRequest(
            method="TRACE",
            url="https://example.com/",
        ),
        response=HttpResponse(
            status_code=200,
            url="https://example.com/",
            headers={},
            content=b"OK",
            cookies={},
            response_time=0.1,
            content_length=2,
        ),
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
        endpoint="/",
    )

    assert findings
    assert all(
        isinstance(finding, Finding)
        for finding in findings
    )


def test_finding_target_and_endpoint(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
            HTTPMethodSecurityIndicatorType.ALLOW_HEADER,
        ),
        target="https://target.example",
        endpoint="/admin",
    )

    assert all(
        finding.target == "https://target.example"
        for finding in findings
    )
    assert all(
        finding.endpoint == "/admin"
        for finding in findings
    )


def test_dangerous_method_is_not_marked_critical(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            HTTPMethodSecurityIndicatorType.DANGEROUS_METHOD,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity != "Critical"
