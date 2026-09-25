import pytest

from m_hunter.analyzers.saml import (
    SAMLAnalysis,
    SAMLAnalyzer,
    SAMLIndicatorType,
)
from m_hunter.analyzers.saml_finding import (
    SAMLFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return SAMLAnalyzer()


@pytest.fixture
def finding_analyzer():
    return SAMLFindingAnalyzer()


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
            {"saml_response": "response"},
            SAMLIndicatorType.SAML_RESPONSE,
            "Info",
            "High",
            "CWE-287",
        ),
        (
            {"relay_state": "relay"},
            SAMLIndicatorType.RELAY_STATE,
            "Low",
            "Medium",
            "CWE-601",
        ),
        (
            {"issuer": "idp.example"},
            SAMLIndicatorType.ISSUER,
            "Info",
            "High",
            "CWE-290",
        ),
        (
            {"audience": "sp.example"},
            SAMLIndicatorType.AUDIENCE,
            "Info",
            "High",
            "CWE-287",
        ),
        (
            {"destination": "https://sp.example/acs"},
            SAMLIndicatorType.DESTINATION,
            "Low",
            "Medium",
            "CWE-601",
        ),
        (
            {"acs_url": "https://sp.example/acs"},
            SAMLIndicatorType.ACS_URL,
            "Low",
            "Medium",
            "CWE-601",
        ),
        (
            {"signature": "signature"},
            SAMLIndicatorType.SIGNATURE,
            "Info",
            "High",
            "CWE-347",
        ),
        (
            {"signature_algorithm": "rsa-sha256"},
            SAMLIndicatorType.SIGNATURE_ALGORITHM,
            "Info",
            "High",
            "CWE-327",
        ),
        (
            {"assertion": "assertion"},
            SAMLIndicatorType.ASSERTION,
            "Info",
            "High",
            "CWE-287",
        ),
        (
            {"name_id": "user@example.com"},
            SAMLIndicatorType.NAME_ID,
            "Info",
            "High",
            "CWE-200",
        ),
        (
            {"not_before": "2026-01-01T00:00:00Z"},
            SAMLIndicatorType.NOT_BEFORE,
            "Info",
            "High",
            "CWE-613",
        ),
        (
            {"not_on_or_after": "2026-01-01T01:00:00Z"},
            SAMLIndicatorType.NOT_ON_OR_AFTER,
            "Info",
            "High",
            "CWE-613",
        ),
        (
            {"in_response_to": "_request"},
            SAMLIndicatorType.IN_RESPONSE_TO,
            "Info",
            "High",
            "CWE-352",
        ),
        (
            {"encryption": "AES256"},
            SAMLIndicatorType.ENCRYPTION,
            "Info",
            "High",
            "CWE-311",
        ),
        (
            {
                "assertion": "assertion",
                "signed_assertion": False,
            },
            SAMLIndicatorType.UNSIGNED_ASSERTION,
            "High",
            "High",
            "CWE-347",
        ),
        (
            {"signature_algorithm": "rsa-sha1"},
            SAMLIndicatorType.WEAK_SIGNATURE_ALGORITHM,
            "High",
            "High",
            "CWE-327",
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
        and finding.severity == severity
        and finding.confidence == confidence
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
        issuer="idp.example",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/sso/acs",
    )

    assert findings
    assert findings[0].target == "https://example.com"
    assert findings[0].endpoint == "/sso/acs"


def test_findings_include_description(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        issuer="idp.example",
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
        signature_algorithm="rsa-sha1",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings

    weak = [
        finding
        for finding in findings
        if finding.cwe == "CWE-327"
        and finding.severity == "High"
    ]

    assert weak
    assert weak[0].evidence
    assert "rsa-sha1" in weak[0].evidence


def test_findings_include_remediation(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        assertion="assertion",
        signed_assertion=False,
    )

    finding = [
        item
        for item in finding_analyzer.analyze(
            analysis,
            target="https://example.com",
        )
        if item.cwe == "CWE-347"
        and item.severity == "High"
    ][0]

    assert finding.remediation
    assert "signature" in finding.remediation.lower()


def test_multiple_indicators_produce_multiple_findings(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        issuer="idp",
        audience="sp",
        assertion="assertion",
        name_id="user",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) >= 4


def test_duplicate_indicators_are_grouped(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"issuer": "idp"},
        issuer="idp",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    issuer_findings = [
        finding
        for finding in findings
        if finding.cwe == "CWE-290"
    ]

    assert len(issuer_findings) == 1


def test_findings_have_open_status(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        issuer="idp",
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
        issuer="idp",
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
        issuer="idp",
    )

    with pytest.raises(
        ValueError
        if isinstance(target, str)
        else (ValueError, TypeError)
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
        issuer="idp",
    )

    with pytest.raises(TypeError):
        finding_analyzer.analyze(
            analysis,
            target="https://example.com",
            endpoint=endpoint,
        )


def test_all_indicator_types_have_metadata(
    finding_analyzer,
):
    for indicator_type in SAMLIndicatorType:
        assert indicator_type in finding_analyzer.METADATA


def test_analysis_without_indicators_is_valid(
    finding_analyzer,
):
    analysis = SAMLAnalysis(
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


def test_finding_analyzer_is_deterministic(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        issuer="idp",
        audience="sp",
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


def test_unsigned_and_weak_algorithm_are_separate_findings(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        assertion="assertion",
        signed_assertion=False,
        signature_algorithm="rsa-sha1",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.cwe == "CWE-347"
        and finding.severity == "High"
        for finding in findings
    )

    assert any(
        finding.cwe == "CWE-327"
        and finding.severity == "High"
        for finding in findings
    )
