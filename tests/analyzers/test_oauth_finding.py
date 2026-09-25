import pytest

from m_hunter.analyzers.oauth import (
    OAuthAnalysis,
    OAuthAnalyzer,
    OAuthIndicatorType,
)
from m_hunter.analyzers.oauth_finding import (
    OAuthFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return OAuthAnalyzer()


@pytest.fixture
def finding_analyzer():
    return OAuthFindingAnalyzer()


def test_empty_analysis_returns_no_findings(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze()

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings == []


@pytest.mark.parametrize(
    "kwargs, indicator_type, severity, confidence, cwe",
    [
        (
            {"redirect_uri": "https://client.example/callback"},
            OAuthIndicatorType.REDIRECT_URI,
            "Medium",
            "Medium",
            "CWE-601",
        ),
        (
            {"state": "abc"},
            OAuthIndicatorType.WEAK_STATE_INDICATOR,
            "Medium",
            "Medium",
            "CWE-330",
        ),
        (
            {"nonce": "random-nonce"},
            OAuthIndicatorType.NONCE_PARAMETER,
            "Info",
            "High",
            "CWE-352",
        ),
        (
            {
                "response_type": "code",
            },
            OAuthIndicatorType.RESPONSE_TYPE,
            "Info",
            "High",
            "CWE-287",
        ),
        (
            {
                "grant_type": "authorization_code",
            },
            OAuthIndicatorType.GRANT_TYPE,
            "Info",
            "High",
            "CWE-287",
        ),
        (
            {
                "client_id": "client-123",
            },
            OAuthIndicatorType.CLIENT_ID,
            "Info",
            "High",
            "CWE-200",
        ),
        (
            {
                "scope": "openid profile",
            },
            OAuthIndicatorType.SCOPE,
            "Info",
            "High",
            "CWE-200",
        ),
        (
            {
                "fragment": "access_token=secret",
            },
            OAuthIndicatorType.TOKEN_IN_URL,
            "High",
            "High",
            "CWE-598",
        ),
        (
            {
                "redirect_uri": "http://client.example/callback",
            },
            OAuthIndicatorType.OPEN_REDIRECT_INDICATOR,
            "Medium",
            "Medium",
            "CWE-601",
        ),
        (
            {
                "response_type": "id_token",
                "expected_nonce": True,
            },
            OAuthIndicatorType.MISSING_NONCE_INDICATOR,
            "Medium",
            "Medium",
            "CWE-352",
        ),
    ],
)
def test_indicator_metadata(
    analyzer,
    finding_analyzer,
    kwargs,
    indicator_type,
    severity,
    confidence,
    cwe,
):
    analysis = analyzer.analyze(**kwargs)

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    matching = [
        finding
        for finding in findings
        if finding.cwe == cwe
        and indicator_type in analysis.types
    ]

    assert matching

    finding = matching[0]

    assert isinstance(finding, Finding)
    assert finding.severity == severity
    assert finding.confidence == confidence
    assert finding.cwe == cwe
    assert finding.owasp == "OWASP A07:2021"


def test_findings_include_target_and_endpoint(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        client_id="client-123",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/oauth/authorize",
    )

    assert findings
    assert findings[0].target == "https://example.com"
    assert findings[0].endpoint == "/oauth/authorize"


def test_findings_include_description(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        client_id="client-123",
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.description
    assert "analytical indicator" in finding.description


def test_findings_include_evidence(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        token_in_url=True
    ) if False else analyzer.analyze(
        fragment="access_token=secret"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings
    assert findings[0].evidence
    assert "access_token" in findings[0].evidence


def test_findings_include_remediation(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        redirect_uri="https://client.example/callback",
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.remediation
    assert "redirect URI" in finding.remediation


def test_multiple_indicators_are_grouped(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        state="abc",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    weak_state_findings = [
        finding
        for finding in findings
        if finding.cwe == "CWE-330"
    ]

    assert len(weak_state_findings) == 1
    assert "state" in weak_state_findings[0].evidence.lower()


def test_multiple_indicator_types_produce_multiple_findings(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        client_id="client",
        state="abc",
        fragment="access_token=secret",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) >= 3


def test_duplicate_indicators_are_grouped(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        url=(
            "https://example.com/authorize"
            "?client_id=abc"
        ),
        client_id="abc",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    client_findings = [
        finding
        for finding in findings
        if finding.cwe == "CWE-200"
    ]

    assert len(client_findings) == 1


def test_findings_have_open_status(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.status == "open"


def test_findings_have_ids(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.id


def test_invalid_analysis_type(
    finding_analyzer,
):
    with pytest.raises(TypeError):
        finding_analyzer.analyze(
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
    finding_analyzer,
    target,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    with pytest.raises(
        ValueError if isinstance(target, str) else (ValueError, TypeError)
    ):
        finding_analyzer.analyze(
            analysis,
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
    analyzer,
    finding_analyzer,
    endpoint,
):
    analysis = analyzer.analyze(
        client_id="client",
    )

    with pytest.raises(TypeError):
        finding_analyzer.analyze(
            analysis,
            target="https://example.com",
            endpoint=endpoint,
        )


def test_finding_analyzer_is_deterministic(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        client_id="client",
        scope="openid",
    )

    first = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )
    second = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert [
        (
            item.title,
            item.severity,
            item.confidence,
            item.cwe,
            item.owasp,
            item.evidence,
        )
        for item in first
    ] == [
        (
            item.title,
            item.severity,
            item.confidence,
            item.cwe,
            item.owasp,
            item.evidence,
        )
        for item in second
    ]


def test_analysis_without_indicators_is_valid(
    finding_analyzer,
):
    analysis = OAuthAnalysis(
        detected=False,
        count=0,
        types=(),
        names=(),
        indicators=(),
    )

    assert finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    ) == []


@pytest.mark.parametrize(
    "indicator_type",
    list(OAuthIndicatorType),
)
def test_all_indicator_types_have_metadata(
    finding_analyzer,
    indicator_type,
):
    assert indicator_type in finding_analyzer.METADATA
