from m_hunter.analyzers.http_response_security import (
    HttpResponseSecurityAnalyzer,
)
from m_hunter.pipelines.http_response_security import (
    HttpResponseSecurityPipeline,
)


def test_pipeline_generates_findings():
    analysis = HttpResponseSecurityAnalyzer().analyze(
        server="Apache/2.4.58",
        x_powered_by="PHP/8.3",
        stack_trace=True,
        internal_path=True,
        directory_listing=True,
    )

    pipeline = HttpResponseSecurityPipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
        endpoint="/error",
    )

    assert len(findings) == 6

    titles = {finding.title for finding in findings}

    assert "Server Version Disclosure" in titles
    assert "Technology Disclosure via X-Powered-By" in titles
    assert "Stack Trace Disclosure" in titles
    assert "Detailed Error Information Disclosure" in titles
    assert "Internal Filesystem Path Disclosure" in titles
    assert "Directory Listing Disclosure" in titles


def test_pipeline_ignores_informational_indicators():
    analysis = HttpResponseSecurityAnalyzer().analyze(
        server="nginx",
    )

    pipeline = HttpResponseSecurityPipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
    )

    assert findings == []


def test_pipeline_handles_multiple_disclosures():
    analysis = HttpResponseSecurityAnalyzer().analyze(
        debug=True,
        exception_details=True,
        internal_ip=True,
    )

    pipeline = HttpResponseSecurityPipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
        endpoint="/debug",
    )

    assert len(findings) == 4

    titles = {finding.title for finding in findings}

    assert "Debug Information Disclosure" in titles
    assert "Exception Details Disclosure" in titles
    assert "Detailed Error Information Disclosure" in titles
    assert "Internal IP Address Disclosure" in titles
