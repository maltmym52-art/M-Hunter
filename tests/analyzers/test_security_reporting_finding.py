import pytest

from m_hunter.analyzers.security_reporting import (
    SecurityReportingAnalysis,
    SecurityReportingIndicator,
    SecurityReportingIndicatorType,
)
from m_hunter.analyzers.security_reporting_finding import (
    SecurityReportingFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def analysis(*types):
    return SecurityReportingAnalysis(
        detected=True,
        indicators=tuple(
            SecurityReportingIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_name():
    assert (
        SecurityReportingFindingAnalyzer.name
        == "security_reporting_finding"
    )


def test_creates_finding():
    findings = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.REPORTING_ENDPOINTS_PRESENT
        ),
        target="https://example.com",
    )

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)


def test_target_preserved():
    findings = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        target="https://target.example",
    )

    assert findings[0].target == "https://target.example"


def test_endpoint_preserved():
    findings = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        target="https://example.com",
        endpoint="/",
    )

    assert findings[0].endpoint == "/"


def test_missing_reporting_endpoints_severity():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "High"


def test_missing_report_to_severity():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.REPORT_TO_MISSING
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "High"


def test_invalid_reporting_endpoints_severity():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_invalid_report_to_severity():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_multiple_reporting_endpoints_severity():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.MULTIPLE_REPORTING_ENDPOINTS
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Medium"


def test_multiple_report_to_severity():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.MULTIPLE_REPORT_TO
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Medium"


def test_endpoint_metadata():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        target="https://example.com",
    )[0]

    assert finding.cwe == "CWE-16"
    assert finding.owasp == "A05:2021"


def test_missing_header_metadata():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING
        ),
        target="https://example.com",
    )[0]

    assert finding.cwe == "CWE-693"
    assert finding.owasp == "A05:2021"


def test_missing_header_evidence():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING
        ),
        target="https://example.com",
    )[0]

    assert "missing" in finding.evidence.lower()


def test_value_evidence():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        target="https://example.com",
    )[0]

    assert "endpoint_present" in finding.evidence


def test_remediation():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.INVALID_REPORT_TO
        ),
        target="https://example.com",
    )[0]

    assert "reporting" in finding.remediation.lower()


def test_conservative_description():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.REPORTING_ENDPOINTS_PRESENT
        ),
        target="https://example.com",
    )[0]

    assert "vulnerable" not in finding.description.lower()


def test_csp_report_only_description():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.CSP_REPORT_ONLY
        ),
        target="https://example.com",
    )[0]

    assert "Report-Only" in finding.description


def test_all_indicators():
    findings = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.REPORTING_ENDPOINTS_PRESENT,
            SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING,
            SecurityReportingIndicatorType.REPORT_TO_PRESENT,
            SecurityReportingIndicatorType.REPORT_TO_MISSING,
            SecurityReportingIndicatorType.ENDPOINT_PRESENT,
            SecurityReportingIndicatorType.GROUP_PRESENT,
            SecurityReportingIndicatorType.CSP_REPORT_ONLY,
            SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS,
            SecurityReportingIndicatorType.INVALID_REPORT_TO,
            SecurityReportingIndicatorType.MULTIPLE_REPORTING_ENDPOINTS,
            SecurityReportingIndicatorType.MULTIPLE_REPORT_TO,
            SecurityReportingIndicatorType.REPORTING_ENDPOINT_URL,
        ),
        target="https://example.com",
    )

    assert len(findings) == 12


def test_multiple_findings_order():
    findings = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT,
            SecurityReportingIndicatorType.INVALID_REPORT_TO,
            SecurityReportingIndicatorType.CSP_REPORT_ONLY,
        ),
        target="https://example.com",
    )

    assert findings[0].title == (
        "Security reporting endpoint is configured"
    )
    assert findings[1].title == (
        "Report-To contains an invalid configuration"
    )
    assert findings[2].title == (
        "Content-Security-Policy-Report-Only is configured"
    )


def test_invalid_analysis():
    with pytest.raises(TypeError):
        SecurityReportingFindingAnalyzer().analyze(
            object(),
            target="https://example.com",
        )


def test_invalid_target():
    with pytest.raises(ValueError):
        SecurityReportingFindingAnalyzer().analyze(
            analysis(
                SecurityReportingIndicatorType.ENDPOINT_PRESENT
            ),
            target="",
        )


def test_invalid_endpoint():
    with pytest.raises(TypeError):
        SecurityReportingFindingAnalyzer().analyze(
            analysis(
                SecurityReportingIndicatorType.ENDPOINT_PRESENT
            ),
            target="https://example.com",
            endpoint=123,
        )


def test_status_defaults_to_open():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        target="https://example.com",
    )[0]

    assert finding.status == "open"


def test_finding_id_exists():
    finding = SecurityReportingFindingAnalyzer().analyze(
        analysis(
            SecurityReportingIndicatorType.ENDPOINT_PRESENT
        ),
        target="https://example.com",
    )[0]

    assert finding.id


def test_empty_analysis():
    findings = SecurityReportingFindingAnalyzer().analyze(
        SecurityReportingAnalysis(
            detected=False,
            indicators=(),
        ),
        target="https://example.com",
    )

    assert findings == []
