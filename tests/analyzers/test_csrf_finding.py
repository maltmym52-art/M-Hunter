from m_hunter.analyzers.csrf import (
    CSRFAnalysis,
    CSRFAnalyzer,
    CSRFIndicatorType,
)
from m_hunter.analyzers.csrf_finding import CSRFFindingAnalyzer


def test_missing_token_creates_finding():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
        "/account/update",
    )

    assert findings
    assert any(
        "CSRF" in finding.title
        for finding in findings
    )


def test_missing_token_metadata():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "missing CSRF token" in finding.title
    )

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-352"
    assert finding.owasp == "A01:2021"


def test_samesite_missing_creates_finding():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        cookies={"sessionid": "abc"},
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert any(
        "SameSite" in finding.title
        for finding in findings
    )


def test_origin_missing_creates_finding():
    analysis = CSRFAnalyzer().analyze("POST")

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert any(
        "Origin" in finding.title
        for finding in findings
    )


def test_referer_missing_creates_finding():
    analysis = CSRFAnalyzer().analyze("POST")

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert any(
        "Referer" in finding.title
        for finding in findings
    )


def test_state_changing_method_is_context_not_vulnerability():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        headers={
            "Origin": "https://example.com",
            "Referer": "https://example.com/",
        },
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    state_finding = next(
        finding
        for finding in findings
        if "State-changing request" in finding.title
    )

    assert state_finding.severity == "Info"
    assert "not evidence" in state_finding.description


def test_token_present_does_not_create_missing_token_finding():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body='<input name="csrf_token" value="abc">',
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert not any(
        "missing CSRF token" in finding.title
        for finding in findings
    )


def test_empty_analysis_returns_no_findings():
    analysis = CSRFAnalysis()

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings == []


def test_findings_include_endpoint():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
        "/profile",
    )

    assert findings
    assert all(
        finding.endpoint == "/profile"
        for finding in findings
    )


def test_findings_include_target_in_evidence():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings
    assert all(
        "https://example.com" in finding.evidence
        for finding in findings
    )


def test_findings_include_indicator_evidence():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings
    assert any(
        "Indicator:" in finding.evidence
        for finding in findings
    )


def test_missing_token_has_remediation():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "missing CSRF token" in finding.title
    )

    assert "CSRF tokens" in finding.remediation


def test_invalid_analysis_type_is_rejected():
    try:
        CSRFFindingAnalyzer().analyze(
            {},
            "https://example.com",
        )
    except TypeError as exc:
        assert "CSRFAnalysis" in str(exc)
    else:
        raise AssertionError("Expected TypeError")


def test_multiple_indicator_types_are_grouped():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
        cookies={"sessionid": "abc"},
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    types = {
        finding.title
        for finding in findings
    }

    assert len(types) >= 3


def test_findings_have_valid_severity_and_confidence():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert all(
        finding.severity in {
            "Info",
            "Low",
            "Medium",
            "High",
            "Critical",
        }
        for finding in findings
    )

    assert all(
        finding.confidence in {
            "Low",
            "Medium",
            "High",
        }
        for finding in findings
    )


def test_finding_is_not_claimed_as_confirmed_exploitation():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert findings
    assert all(
        "confirmed" not in finding.description.lower()
        for finding in findings
    )


def test_origin_finding_has_low_confidence():
    analysis = CSRFAnalyzer().analyze("POST")

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "Origin" in finding.title
    )

    assert finding.severity == "Low"
    assert finding.confidence == "Low"


def test_referer_finding_has_low_confidence():
    analysis = CSRFAnalyzer().analyze("POST")

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "Referer" in finding.title
    )

    assert finding.severity == "Low"
    assert finding.confidence == "Low"


def test_samesite_finding_has_medium_severity():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        cookies={"sessionid": "abc"},
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        finding
        for finding in findings
        if "SameSite" in finding.title
    )

    assert finding.severity == "Medium"


def test_finding_count_matches_unique_indicator_types():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
        cookies={"sessionid": "abc"},
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == len(set(analysis.types))


def test_finding_evidence_contains_count():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert any(
        "Evidence count:" in finding.evidence
        for finding in findings
    )


def test_finding_title_is_non_empty():
    analysis = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    findings = CSRFFindingAnalyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert all(finding.title.strip() for finding in findings)
