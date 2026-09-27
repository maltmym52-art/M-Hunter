from m_hunter.analyzers.http_response_security import (
    HttpResponseSecurityAnalyzer,
)
from m_hunter.findings.http_response_security import (
    HttpResponseSecurityFinding,
)


def test_server_version_disclosure():
    finding = HttpResponseSecurityFinding.build(
        "SERVER_VERSION_DISCLOSURE",
        "https://example.com",
        evidence="nginx/1.24.0",
    )

    assert finding.title == "Server Version Disclosure"
    assert finding.severity == "Low"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-200"


def test_x_powered_by():
    finding = HttpResponseSecurityFinding.build(
        "X_POWERED_BY",
        "https://example.com",
        endpoint="/",
        evidence="PHP/8.3",
    )

    assert finding.title == "Technology Disclosure via X-Powered-By"
    assert finding.severity == "Low"
    assert finding.evidence == "PHP/8.3"


def test_stack_trace():
    finding = HttpResponseSecurityFinding.build(
        "STACK_TRACE_DISCLOSURE",
        "https://example.com",
    )

    assert finding.title == "Stack Trace Disclosure"
    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-209"


def test_directory_listing():
    finding = HttpResponseSecurityFinding.build(
        "DIRECTORY_LISTING",
        "https://example.com",
        endpoint="/backup/",
    )

    assert finding.title == "Directory Listing Disclosure"
    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-548"


def test_from_analysis():
    analysis = HttpResponseSecurityAnalyzer().analyze(
        server="Apache/2.4.58",
        x_powered_by="PHP/8.3",
        stack_trace=True,
        internal_path=True,
        directory_listing=True,
    )

    findings = HttpResponseSecurityFinding.from_analysis(
        analysis,
        "https://example.com",
        endpoint="/error",
    )

    assert len(findings) == 6

    titles = {finding.title for finding in findings}

    assert "Server Version Disclosure" in titles
    assert "Technology Disclosure via X-Powered-By" in titles
    assert "Stack Trace Disclosure" in titles
    assert "Internal Filesystem Path Disclosure" in titles
    assert "Directory Listing Disclosure" in titles
    assert "Detailed Error Information Disclosure" in titles
