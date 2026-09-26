import pytest

from m_hunter.analyzers.http2_security import (
    HTTP2SecurityAnalyzer,
    HTTP2SecurityIndicatorType,
)
from m_hunter.analyzers.http2_security_finding import (
    HTTP2SecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def analyzer():
    return HTTP2SecurityAnalyzer()


def finding_analyzer():
    return HTTP2SecurityFindingAnalyzer()


def indicator(indicator_type):
    result = analyzer().analyze(
        "https://example.com",
        protocol="h2",
    )

    return next(
        item
        for item in result.indicators
        if item.type == indicator_type
    )


@pytest.mark.parametrize(
    "indicator_type,expected_severity,expected_cwe",
    [
        (
            HTTP2SecurityIndicatorType.HTTP2_SCHEME,
            "Info",
            "CWE-16",
        ),
        (
            HTTP2SecurityIndicatorType.HTTP2_ALPN,
            "Info",
            "CWE-16",
        ),
        (
            HTTP2SecurityIndicatorType.HTTP2_PROTOCOL,
            "Info",
            "CWE-16",
        ),
        (
            HTTP2SecurityIndicatorType.AUTHORITY_HEADER,
            "Info",
            "CWE-20",
        ),
        (
            HTTP2SecurityIndicatorType.PSEUDO_HEADER,
            "Info",
            "CWE-16",
        ),
        (
            HTTP2SecurityIndicatorType.DUPLICATE_PSEUDO_HEADER,
            "Medium",
            "CWE-20",
        ),
        (
            HTTP2SecurityIndicatorType.INVALID_PSEUDO_HEADER_ORDER,
            "Medium",
            "CWE-20",
        ),
        (
            HTTP2SecurityIndicatorType.HTTP2_ERROR,
            "Medium",
            "CWE-400",
        ),
        (
            HTTP2SecurityIndicatorType.STREAM_ERROR,
            "Medium",
            "CWE-400",
        ),
        (
            HTTP2SecurityIndicatorType.GOAWAY_ERROR,
            "Medium",
            "CWE-400",
        ),
        (
            HTTP2SecurityIndicatorType.SETTINGS_EXPOSURE,
            "Low",
            "CWE-200",
        ),
        (
            HTTP2SecurityIndicatorType.H2C_UPGRADE,
            "Medium",
            "CWE-319",
        ),
        (
            HTTP2SecurityIndicatorType.PRIOR_KNOWLEDGE,
            "Info",
            "CWE-16",
        ),
    ],
)
def test_metadata(
    indicator_type,
    expected_severity,
    expected_cwe,
):
    result = analyzer().analyze(
        "h2://example.com",
        protocol="h2",
        alpn="h2",
        headers={
            ":authority": "example.com",
            ":method": "GET",
            "Upgrade": "h2c",
        },
        pseudo_headers=[
            ":method",
            "x-test",
            ":method",
        ],
        response_text="HTTP/2 protocol error stream error GOAWAY",
        settings={"max_frame_size": 16384},
        h2c_upgrade=True,
        prior_knowledge=True,
    )

    item = next(
        item
        for item in result.indicators
        if item.type == indicator_type
    )

    finding = finding_analyzer().create_finding(
        item,
        "https://example.com",
        "/test",
    )

    expected_confidence = (
        "Medium"
        if indicator_type
        in {
            HTTP2SecurityIndicatorType.HTTP2_ERROR,
            HTTP2SecurityIndicatorType.STREAM_ERROR,
            HTTP2SecurityIndicatorType.GOAWAY_ERROR,
        }
        else "High"
    )

    assert finding.severity == expected_severity
    assert finding.confidence == expected_confidence
    assert finding.cwe == expected_cwe
    assert finding.target == "https://example.com"
    assert finding.endpoint == "/test"


def test_create_finding_returns_finding():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    finding = finding_analyzer().create_finding(
        item,
        "https://example.com",
    )

    assert isinstance(finding, Finding)


def test_title_is_present():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    finding = finding_analyzer().create_finding(
        item,
        "https://example.com",
    )

    assert finding.title


def test_description_is_present():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    finding = finding_analyzer().create_finding(
        item,
        "https://example.com",
    )

    assert finding.description


def test_evidence_contains_indicator_evidence():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    finding = finding_analyzer().create_finding(
        item,
        "https://example.com",
    )

    assert item.evidence in finding.evidence


def test_evidence_contains_value():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    finding = finding_analyzer().create_finding(
        item,
        "https://example.com",
    )

    assert "h2" in finding.evidence


def test_remediation_is_present():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    finding = finding_analyzer().create_finding(
        item,
        "https://example.com",
    )

    assert finding.remediation


def test_owasp_is_present():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    finding = finding_analyzer().create_finding(
        item,
        "https://example.com",
    )

    assert finding.owasp


def test_endpoint_is_optional():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    finding = finding_analyzer().create_finding(
        item,
        "https://example.com",
    )

    assert finding.endpoint is None


def test_empty_target_rejected():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    with pytest.raises(ValueError):
        finding_analyzer().create_finding(
            item,
            "",
        )


def test_whitespace_target_rejected():
    item = indicator(
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL
    )

    with pytest.raises(ValueError):
        finding_analyzer().create_finding(
            item,
            "   ",
        )


def test_invalid_indicator_rejected():
    with pytest.raises(TypeError):
        finding_analyzer().create_finding(
            object(),
            "https://example.com",
        )


def test_invalid_analysis_rejected():
    with pytest.raises(TypeError):
        finding_analyzer().create_findings(
            object(),
            "https://example.com",
        )


def test_create_findings_returns_all_findings():
    result = analyzer().analyze(
        "h2://example.com",
        protocol="h2",
        alpn="h2",
    )

    findings = finding_analyzer().create_findings(
        result,
        "https://example.com",
    )

    assert len(findings) == len(result.indicators)
    assert all(
        isinstance(finding, Finding)
        for finding in findings
    )


def test_create_findings_empty_analysis():
    result = analyzer().analyze("https://example.com")

    findings = finding_analyzer().create_findings(
        result,
        "https://example.com",
    )

    assert findings == []


def test_duplicate_indicator_creates_separate_findings():
    result = analyzer().analyze(
        "https://example.com",
        pseudo_headers=[
            ":method",
            ":method",
        ],
    )

    findings = finding_analyzer().create_findings(
        result,
        "https://example.com",
    )

    assert len(findings) == len(result.indicators)


def test_h2c_finding_metadata():
    result = analyzer().analyze(
        "https://example.com",
        h2c_upgrade=True,
    )

    finding = finding_analyzer().create_findings(
        result,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-319"


def test_settings_finding_metadata():
    result = analyzer().analyze(
        "https://example.com",
        settings={"max_concurrent_streams": 100},
    )

    finding = finding_analyzer().create_findings(
        result,
        "https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.cwe == "CWE-200"


def test_error_finding_metadata():
    result = analyzer().analyze(
        "https://example.com",
        response_text="HTTP/2 protocol error",
    )

    finding = finding_analyzer().create_findings(
        result,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"


def test_findings_have_unique_ids():
    result = analyzer().analyze(
        "h2://example.com",
        protocol="h2",
        alpn="h2",
    )

    findings = finding_analyzer().create_findings(
        result,
        "https://example.com",
    )

    assert len({finding.id for finding in findings}) == len(findings)
