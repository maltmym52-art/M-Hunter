import pytest

from m_hunter.analyzers.host_header_injection import (
    HostHeaderInjectionAnalyzer,
    HostHeaderInjectionIndicatorType,
)
from m_hunter.analyzers.host_header_injection_finding import (
    HostHeaderInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return HostHeaderInjectionAnalyzer()


@pytest.fixture
def finding_analyzer():
    return HostHeaderInjectionFindingAnalyzer()


def test_no_findings_when_no_indicator(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze()

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert findings == []


def test_returns_finding_for_host_header(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"Host": "example.test"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert findings
    assert all(
        isinstance(finding, Finding)
        for finding in findings
    )


def test_host_header_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"Host": "example.test"},
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-16"
    assert finding.owasp == "A05:2021"


def test_forwarded_host_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"X-Forwarded-Host": "example.test"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "X-Forwarded-Host injection indicator"
    )

    assert finding.severity == "Low"
    assert finding.confidence == "High"


def test_x_host_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"X-Host": "example.test"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "X-Host injection indicator"
    )

    assert finding.cwe == "CWE-16"


def test_forwarded_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"Forwarded": "host=example.test"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Forwarded header injection indicator"
    )

    assert finding.owasp == "A05:2021"


def test_host_override_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"X-Original-Host": "example.test"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Host override header indicator"
    )

    assert finding.severity == "Low"


def test_external_host_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
        expected_host="example.test",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "External host trust indicator"
    )

    assert finding.severity == "High"
    assert finding.confidence == "Medium"


def test_absolute_url_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        response_headers={
            "Location": "https://example.test/reset",
        },
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Host-derived absolute URL indicator"
    )

    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-601"


def test_password_reset_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        response_body="Click here to reset password.",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Password reset link host indicator"
    )

    assert finding.severity == "High"
    assert finding.cwe == "CWE-640"


def test_email_link_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        response_body="An email link was generated.",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Email link host indicator"
    )

    assert finding.severity == "Medium"


def test_canonical_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        response_body='<link rel="canonical" href="https://example.test">',
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Canonical URL host indicator"
    )

    assert finding.severity == "Low"
    assert finding.cwe == "CWE-601"


def test_host_mismatch_metadata(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        request_host="example.test",
        response_host="attacker.test",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    finding = next(
        finding
        for finding in findings
        if finding.title == "Host mismatch indicator"
    )

    assert finding.severity == "Medium"


def test_target_and_endpoint(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"Host": "example.test"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
        endpoint="/reset",
    )

    assert findings[0].target == "https://example.test"
    assert findings[0].endpoint == "/reset"


def test_evidence_contains_value(
    finding_analyzer,
    analyzer,
):
    value = "attacker.test"

    analysis = analyzer.analyze(
        headers={"Host": value},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert any(
        value in finding.evidence
        for finding in findings
    )


def test_description_has_disclaimer(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
        expected_host="example.test",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert "does not prove" in findings[0].description


def test_remediation_present(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert findings[0].remediation


def test_findings_grouped_by_type(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={
            "Host": "attacker.test",
            "X-Host": "attacker.test",
        },
        expected_host="example.test",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    titles = {finding.title for finding in findings}

    assert "Host header injection indicator" in titles
    assert "X-Host injection indicator" in titles


def test_multiple_values_grouped(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={
            "Host": "attacker.test",
            "X-Host": "attacker.test",
        },
        expected_host="example.test",
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    external = next(
        finding
        for finding in findings
        if finding.title == "External host trust indicator"
    )

    assert "attacker.test" in external.evidence


def test_invalid_analysis_type(finding_analyzer):
    with pytest.raises(TypeError):
        finding_analyzer.analyze(
            "invalid",
            target="https://example.test",
        )


def test_empty_target(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        headers={"Host": "example.test"},
    )

    with pytest.raises(ValueError):
        finding_analyzer.analyze(
            analysis,
            target="",
        )


def test_invalid_endpoint(finding_analyzer, analyzer):
    analysis = analyzer.analyze(
        headers={"Host": "example.test"},
    )

    with pytest.raises(TypeError):
        finding_analyzer.analyze(
            analysis,
            target="https://example.test",
            endpoint=123,
        )


def test_all_types_have_metadata(finding_analyzer):
    assert set(finding_analyzer.METADATA) == set(
        HostHeaderInjectionIndicatorType
    )


def test_finding_status_is_open(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={"Host": "example.test"},
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )[0]

    assert finding.status == "open"


def test_findings_have_unique_ids(
    finding_analyzer,
    analyzer,
):
    analysis = analyzer.analyze(
        headers={
            "Host": "example.test",
            "X-Host": "example.test",
        },
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.test",
    )

    assert len({finding.id for finding in findings}) == len(findings)
