import pytest

from m_hunter.analyzers.session import (
    SessionAnalysis,
    SessionAnalyzer,
    SessionIndicator,
    SessionIndicatorType,
)
from m_hunter.analyzers.session_finding import SessionFindingAnalyzer
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return SessionFindingAnalyzer()


@pytest.fixture
def session_analyzer():
    return SessionAnalyzer()


def make_analysis(*types):
    indicators = tuple(
        SessionIndicator(
            type=indicator_type,
            evidence=f"Evidence for {indicator_type.value}",
            name="sessionid",
            value="abc123",
        )
        for indicator_type in types
    )
    return SessionAnalysis(indicators=indicators)


def test_empty_analysis_returns_no_findings(analyzer):
    result = analyzer.analyze(
        analysis=SessionAnalysis(indicators=()),
        target="https://example.com",
    )
    assert result == []


def test_requires_session_analysis(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis="invalid",
            target="https://example.com",
        )


def test_requires_target(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            analysis=SessionAnalysis(indicators=()),
            target="",
        )


def test_endpoint_must_be_string(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis=SessionAnalysis(indicators=()),
            target="https://example.com",
            endpoint=123,
        )


@pytest.mark.parametrize(
    "indicator_type",
    list(SessionIndicatorType),
)
def test_each_indicator_generates_finding(analyzer, indicator_type):
    analysis = make_analysis(indicator_type)

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
        endpoint="/login",
    )

    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.target == "https://example.com"
    assert finding.endpoint == "/login"
    assert finding.title
    assert finding.severity
    assert finding.confidence
    assert finding.description
    assert finding.evidence
    assert finding.remediation


def test_session_id_in_url_metadata(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            SessionIndicatorType.SESSION_ID_IN_URL,
        ),
        target="https://example.com",
    )

    finding = findings[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-598"
    assert finding.owasp == "OWASP A07:2021"


def test_token_exposure_metadata(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            SessionIndicatorType.TOKEN_EXPOSURE,
        ),
        target="https://example.com",
    )

    finding = findings[0]

    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-598"


def test_fixation_metadata(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            SessionIndicatorType.SESSION_FIXATION_INDICATOR,
        ),
        target="https://example.com",
    )

    finding = findings[0]

    assert finding.severity == "High"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-384"


def test_long_lived_session_metadata(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            SessionIndicatorType.LONG_LIVED_SESSION,
        ),
        target="https://example.com",
    )

    finding = findings[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-613"


def test_weak_cookie_name_metadata(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            SessionIndicatorType.WEAK_SESSION_COOKIE_NAME,
        ),
        target="https://example.com",
    )

    finding = findings[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Medium"


def test_multiple_indicator_types_create_multiple_findings(analyzer):
    analysis = make_analysis(
        SessionIndicatorType.SESSION_COOKIE,
        SessionIndicatorType.SESSION_ID_IN_URL,
        SessionIndicatorType.TOKEN_EXPOSURE,
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert len(findings) == 3
    assert {
        finding.title
        for finding in findings
    } == {
        "Session cookie detected",
        "Session identifier exposed in URL",
        "Session token exposure indicator detected",
    }


def test_same_indicator_type_is_grouped(analyzer):
    analysis = SessionAnalysis(
        indicators=(
            SessionIndicator(
                type=SessionIndicatorType.SESSION_COOKIE,
                evidence="Cookie one",
                name="sessionid",
                value="abc",
            ),
            SessionIndicator(
                type=SessionIndicatorType.SESSION_COOKIE,
                evidence="Cookie two",
                name="JSESSIONID",
                value="def",
            ),
        )
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert len(findings) == 1
    assert "Cookie one" in findings[0].evidence
    assert "Cookie two" in findings[0].evidence


def test_finding_contains_indicator_details(analyzer):
    analysis = SessionAnalysis(
        indicators=(
            SessionIndicator(
                type=SessionIndicatorType.SESSION_COOKIE,
                evidence="Session cookie detected",
                name="sessionid",
                value="abc123",
            ),
        )
    )

    finding = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )[0]

    assert "Session cookie detected" in finding.evidence
    assert "name=sessionid" in finding.evidence
    assert "value=abc123" in finding.evidence


def test_description_contains_validation_disclaimer(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            SessionIndicatorType.SESSION_TOKEN,
        ),
        target="https://example.com",
    )[0]

    assert "does not by itself prove a vulnerability" in finding.description


def test_remediation_is_present(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            SessionIndicatorType.SESSION_TIMEOUT,
        ),
        target="https://example.com",
    )[0]

    assert "Rotate session identifiers" in finding.remediation
    assert "invalidate sessions on logout" in finding.remediation


def test_all_supported_types_have_metadata(analyzer):
    assert set(analyzer.METADATA) == set(SessionIndicatorType)


def test_findings_have_unique_ids(analyzer):
    analysis = make_analysis(
        SessionIndicatorType.SESSION_COOKIE,
        SessionIndicatorType.SESSION_TOKEN,
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert len({finding.id for finding in findings}) == 2


def test_real_analyzer_output_can_be_converted(analyzer, session_analyzer):
    analysis = session_analyzer.analyze(
        cookies={"sessionid": "abc123"},
        url="https://example.com/login?sessionid=abc123",
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
        endpoint="/login",
    )

    assert findings
    assert all(isinstance(finding, Finding) for finding in findings)
