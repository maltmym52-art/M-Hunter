from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding


def test_finding_analyzer_can_be_created():
    analyzer = FindingAnalyzer()

    assert isinstance(analyzer, FindingAnalyzer)


def test_create_finding_returns_finding():
    analyzer = FindingAnalyzer()

    finding = analyzer.create_finding(
        title="Test Finding",
        severity="Medium",
        confidence="High",
        target="https://example.com",
    )

    assert isinstance(finding, Finding)


def test_create_finding_sets_required_fields():
    analyzer = FindingAnalyzer()

    finding = analyzer.create_finding(
        title="Test Finding",
        severity="High",
        confidence="High",
        target="https://example.com",
    )

    assert finding.title == "Test Finding"
    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.target == "https://example.com"


def test_create_finding_sets_endpoint():
    analyzer = FindingAnalyzer()

    finding = analyzer.create_finding(
        title="Test Finding",
        severity="Medium",
        confidence="High",
        target="https://example.com",
        endpoint="https://example.com/login",
    )

    assert finding.endpoint == "https://example.com/login"


def test_create_finding_sets_parameter():
    analyzer = FindingAnalyzer()

    finding = analyzer.create_finding(
        title="Test Finding",
        severity="High",
        confidence="High",
        target="https://example.com",
        parameter="id",
    )

    assert finding.parameter == "id"


def test_create_finding_sets_analysis_metadata():
    analyzer = FindingAnalyzer()

    finding = analyzer.create_finding(
        title="Missing Security Header",
        severity="Low",
        confidence="High",
        target="https://example.com",
        description="A security header is missing.",
        evidence="Content-Security-Policy is absent.",
        remediation="Configure an appropriate CSP.",
        cwe="CWE-693",
        owasp="A05:2021",
    )

    assert finding.description == "A security header is missing."
    assert finding.evidence == "Content-Security-Policy is absent."
    assert finding.remediation == "Configure an appropriate CSP."
    assert finding.cwe == "CWE-693"
    assert finding.owasp == "A05:2021"


def test_create_finding_preserves_optional_defaults():
    analyzer = FindingAnalyzer()

    finding = analyzer.create_finding(
        title="Test Finding",
        severity="Info",
        confidence="Low",
        target="https://example.com",
    )

    assert finding.endpoint is None
    assert finding.parameter is None
    assert finding.description == ""
    assert finding.evidence == ""
    assert finding.remediation == ""
    assert finding.cwe is None
    assert finding.owasp is None


def test_from_analysis_creates_finding():
    analyzer = FindingAnalyzer()

    finding = analyzer.from_analysis(
        analysis={
            "missing": [
                "content-security-policy",
            ],
            "count_missing": 1,
        },
        title="Missing Security Header",
        severity="Medium",
        confidence="High",
        target="https://example.com",
    )

    assert isinstance(finding, Finding)
    assert finding.title == "Missing Security Header"


def test_from_analysis_preserves_finding_metadata():
    analyzer = FindingAnalyzer()

    finding = analyzer.from_analysis(
        analysis={
            "missing": [
                "content-security-policy",
            ],
        },
        title="Missing Content-Security-Policy",
        severity="Medium",
        confidence="High",
        target="https://example.com",
        endpoint="https://example.com/",
        description="CSP is missing.",
        evidence="Content-Security-Policy was not present.",
        remediation="Configure a suitable Content-Security-Policy.",
        cwe="CWE-693",
        owasp="A05:2021",
    )

    assert finding is not None
    assert finding.endpoint == "https://example.com/"
    assert finding.description == "CSP is missing."
    assert finding.evidence == "Content-Security-Policy was not present."
    assert finding.remediation == (
        "Configure a suitable Content-Security-Policy."
    )
    assert finding.cwe == "CWE-693"
    assert finding.owasp == "A05:2021"


def test_from_analysis_returns_none_for_empty_analysis():
    analyzer = FindingAnalyzer()

    result = analyzer.from_analysis(
        analysis={},
        title="Test Finding",
        severity="Medium",
        confidence="High",
        target="https://example.com",
    )

    assert result is None


def test_from_analysis_accepts_different_analysis_shapes():
    analyzer = FindingAnalyzer()

    analysis = {
        "status_code": 200,
        "content_type": "text/html",
        "missing": [],
        "present": {
            "x-frame-options": "DENY",
        },
    }

    finding = analyzer.from_analysis(
        analysis=analysis,
        title="Example Analysis",
        severity="Info",
        confidence="High",
        target="https://example.com",
    )

    assert finding is not None
    assert finding.title == "Example Analysis"
