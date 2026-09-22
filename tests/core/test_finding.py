from datetime import datetime

from m_hunter.core.finding import Finding


def test_finding_defaults():
    finding = Finding(
        title="Test Finding",
        severity="Medium",
        confidence="High",
        target="https://example.com",
    )

    assert finding.title == "Test Finding"
    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.target == "https://example.com"

    assert finding.id
    assert finding.endpoint is None
    assert finding.parameter is None
    assert finding.description == ""
    assert finding.evidence == ""
    assert finding.remediation == ""
    assert finding.cwe is None
    assert finding.owasp is None
    assert finding.status == "open"
    assert isinstance(finding.created_at, datetime)


def test_finding_id_is_unique():
    finding_one = Finding(
        title="Finding One",
        severity="Low",
        confidence="High",
        target="https://example.com",
    )

    finding_two = Finding(
        title="Finding Two",
        severity="Low",
        confidence="High",
        target="https://example.com",
    )

    assert finding_one.id != finding_two.id


def test_finding_optional_fields():
    finding = Finding(
        title="XSS",
        severity="High",
        confidence="Medium",
        target="https://example.com",
        endpoint="https://example.com/search",
        parameter="q",
        description="Possible reflected XSS",
        evidence="Payload reflected in response",
        remediation="Encode user-controlled output",
        cwe="CWE-79",
        owasp="A03:2021",
    )

    assert finding.endpoint == "https://example.com/search"
    assert finding.parameter == "q"
    assert finding.description == "Possible reflected XSS"
    assert finding.evidence == "Payload reflected in response"
    assert finding.remediation == "Encode user-controlled output"
    assert finding.cwe == "CWE-79"
    assert finding.owasp == "A03:2021"


def test_finding_status():
    finding = Finding(
        title="Test Finding",
        severity="Critical",
        confidence="High",
        target="https://example.com",
    )

    assert finding.status == "open"

    finding.status = "confirmed"

    assert finding.status == "confirmed"


def test_finding_created_at_is_independent():
    finding_one = Finding(
        title="Finding One",
        severity="Low",
        confidence="High",
        target="https://example.com",
    )

    finding_two = Finding(
        title="Finding Two",
        severity="Low",
        confidence="High",
        target="https://example.com",
    )

    assert finding_one.created_at is not finding_two.created_at
