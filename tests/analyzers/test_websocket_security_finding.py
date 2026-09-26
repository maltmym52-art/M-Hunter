import pytest

from m_hunter.analyzers.websocket_security import (
    WebSocketSecurityAnalyzer,
    WebSocketSecurityIndicatorType,
)
from m_hunter.analyzers.websocket_security_finding import (
    WebSocketSecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def analyzer():
    return WebSocketSecurityAnalyzer()


def finding_analyzer():
    return WebSocketSecurityFindingAnalyzer()


def test_clean_analysis_creates_no_findings():
    analysis = analyzer().analyze(
        "https://example.com",
        headers={"accept": "text/html"},
    )

    assert finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    ) == []


def test_websocket_scheme_finding():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 2
    assert any(
        "WebSocket Endpoint" in item.title
        for item in findings
    )


def test_upgrade_header_metadata():
    analysis = analyzer().analyze(
        "https://example.com/socket",
        headers={"Upgrade": "websocket"},
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Upgrade Detected" in item.title
    )

    assert finding.severity == "Info"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-319"
    assert finding.owasp == "A05:2021"


def test_missing_origin_metadata():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Origin Header Missing" in item.title
    )

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-346"
    assert finding.owasp == "A07:2021"


def test_broad_origin_metadata():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "*"},
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Broad WebSocket Origin" in item.title
    )

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-346"


def test_null_origin_metadata():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "null"},
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Broad WebSocket Origin" in item.title
    )

    assert finding.severity == "Medium"


def test_origin_header_is_informational():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "https://app.example.com"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[1]

    assert finding.severity == "Info"


def test_subprotocol_metadata():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        subprotocol="chat",
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Subprotocol" in item.title
    )

    assert finding.severity == "Info"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-16"


def test_authentication_context_metadata():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        authenticated=True,
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Authentication Context" in item.title
    )

    assert finding.severity == "Info"
    assert finding.cwe == "CWE-287"


def test_session_context_metadata():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        session_present=True,
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Session Context" in item.title
    )

    assert finding.severity == "Info"
    assert finding.cwe == "CWE-384"


def test_sensitive_path_metadata():
    analysis = analyzer().analyze(
        "wss://example.com/admin/socket",
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Sensitive WebSocket Path" in item.title
    )

    assert finding.severity == "Low"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-200"


def test_websocket_error_metadata():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        response_text="Origin not allowed",
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Error Information" in item.title
    )

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-209"


def test_target_and_endpoint_are_preserved():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "*"},
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://target.example",
            endpoint="/socket",
        )
        if "Broad WebSocket Origin" in item.title
    )

    assert finding.target == "https://target.example"
    assert finding.endpoint == "/socket"
    assert finding.parameter == "origin"


def test_evidence_is_present():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "*"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[-1]

    assert finding.evidence


def test_remediation_is_present():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "*"},
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Broad WebSocket Origin" in item.title
    )

    assert finding.remediation
    assert "allowlist" in finding.remediation


def test_missing_origin_description_has_disclaimer():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Origin Header Missing" in item.title
    )

    assert "does not prove" in finding.description


def test_error_description_has_disclaimer():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        response_text="WebSocket handshake failed",
    )

    finding = next(
        item
        for item in finding_analyzer().create_findings(
            analysis,
            "https://example.com",
        )
        if "Error Information" in item.title
    )

    assert "does not establish" in finding.description


def test_analyze_alias_matches_create_findings():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "*"},
    )

    first = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )
    second = finding_analyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert len(first) == len(second)
    assert first[0].title == second[0].title


def test_invalid_analysis_type():
    with pytest.raises(TypeError):
        finding_analyzer().create_findings(
            object(),
            "https://example.com",
        )


def test_empty_target():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
    )

    with pytest.raises(ValueError):
        finding_analyzer().create_findings(
            analysis,
            "",
        )


def test_whitespace_target():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
    )

    with pytest.raises(ValueError):
        finding_analyzer().create_findings(
            analysis,
            "   ",
        )


def test_finding_ids_are_unique():
    analysis = analyzer().analyze(
        "wss://example.com/admin/socket",
        headers={
            "Origin": "*",
            "Upgrade": "websocket",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    ids = [item.id for item in findings]

    assert len(ids) == len(set(ids))


def test_all_findings_have_owasp():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        headers={
            "Origin": "*",
            "Upgrade": "websocket",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert all(item.owasp for item in findings)


def test_indicator_type_metadata_is_defined():
    for indicator_type in WebSocketSecurityIndicatorType:
        assert indicator_type in finding_analyzer()._METADATA


def test_multiple_indicators_create_multiple_findings():
    analysis = analyzer().analyze(
        "wss://example.com/admin/socket",
        headers={
            "Upgrade": "websocket",
            "Origin": "*",
            "Authorization": "Bearer token",
            "Cookie": "session=abc",
        },
        response_text="WebSocket handshake failed",
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert len(findings) >= 7


def test_websocket_scheme_is_not_high_severity():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_normal_origin_is_not_treated_as_broad_origin():
    analysis = analyzer().analyze(
        "wss://example.com/socket",
        headers={"Origin": "https://trusted.example"},
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert not any(
        "Broad WebSocket Origin" in item.title
        for item in findings
    )
