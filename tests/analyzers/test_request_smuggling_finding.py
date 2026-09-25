import pytest

from m_hunter.analyzers.request_smuggling import (
    RequestSmugglingAnalysis,
    RequestSmugglingAnalyzer,
    SmugglingIndicatorType,
    SmugglingType,
)
from m_hunter.analyzers.request_smuggling_finding import (
    RequestSmugglingFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return RequestSmugglingFindingAnalyzer()


@pytest.fixture
def smuggling_analyzer():
    return RequestSmugglingAnalyzer()


def test_empty_analysis_returns_no_findings(analyzer):
    result = analyzer.analyze(
        RequestSmugglingAnalysis(),
        "https://example.com",
    )

    assert result == []


def test_invalid_analysis_type_raises(analyzer):
    with pytest.raises(
        TypeError,
        match="analysis must be a RequestSmugglingAnalysis instance",
    ):
        analyzer.analyze(
            object(),
            "https://example.com",
        )


def test_empty_target_raises(analyzer):
    with pytest.raises(
        ValueError,
        match="target must be a non-empty string",
    ):
        analyzer.analyze(
            RequestSmugglingAnalysis(),
            "",
        )


def test_whitespace_target_raises(analyzer):
    with pytest.raises(
        ValueError,
        match="target must be a non-empty string",
    ):
        analyzer.analyze(
            RequestSmugglingAnalysis(),
            "   ",
        )


def test_invalid_endpoint_type_raises(analyzer):
    with pytest.raises(
        TypeError,
        match="endpoint must be a string or None",
    ):
        analyzer.analyze(
            RequestSmugglingAnalysis(),
            "https://example.com",
            endpoint=123,
        )


def test_conflicting_framing_metadata(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
        "/api",
    )

    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.severity == "High"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-444"
    assert finding.owasp == "A05:2021"


def test_duplicate_content_length_metadata(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert findings[0].confidence == "Medium"


def test_ambiguous_transfer_encoding_metadata(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        item
        for item in findings
        if "ambiguous_transfer_encoding" in item.title
    )

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"


def test_finding_title_identifies_request_smuggling(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert findings[0].title.startswith(
        "Potential HTTP request smuggling indicator:"
    )


def test_description_does_not_claim_confirmation(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    description = findings[0].description.lower()

    assert "may be relevant" in description
    assert "confirmed" not in description


def test_remediation_mentions_message_framing(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    remediation = findings[0].remediation.lower()

    assert "message framing" in remediation
    assert "content-length" in remediation
    assert "transfer-encoding" in remediation


def test_target_and_endpoint_are_preserved(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
        "/upload",
    )

    assert findings[0].target == "https://example.com"
    assert findings[0].endpoint == "/upload"


def test_endpoint_defaults_to_none(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert findings[0].endpoint is None


def test_evidence_contains_indicator_type(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert (
        "Indicator type: conflicting_framing"
        in findings[0].evidence
    )


def test_evidence_contains_smuggling_type(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert "Smuggling type: cl_te" in findings[0].evidence


def test_evidence_contains_raw_indicator(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert "10" in findings[0].evidence
    assert "20" in findings[0].evidence


def test_evidence_contains_count(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert "Evidence count: 1" in findings[0].evidence


def test_multiple_indicator_types_create_multiple_findings(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == len(analysis.types)

    for indicator_type in analysis.types:
        assert any(
            indicator_type.value in finding.title
            for finding in findings
        )


def test_finding_ids_are_unique(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    ids = [finding.id for finding in findings]

    assert len(ids) == len(set(ids))


def test_finding_status_defaults_to_open(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert findings[0].status == "open"


def test_all_findings_use_cwe_444(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert all(
        finding.cwe == "CWE-444"
        for finding in findings
    )


def test_all_findings_use_owasp_a05(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert all(
        finding.owasp == "A05:2021"
        for finding in findings
    )


def test_duplicate_content_length_evidence_is_grouped(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert "Evidence count: 1" in findings[0].evidence
    assert "Smuggling type: duplicate_content_length" in (
        findings[0].evidence
    )


def test_invalid_transfer_encoding_evidence_is_preserved(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Transfer-Encoding": "gzip",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    finding = next(
        item
        for item in findings
        if "ambiguous_transfer_encoding" in item.title
    )

    assert (
        "Smuggling type: invalid_transfer_encoding"
        in finding.evidence
    )
    assert "gzip" in finding.evidence


def test_te_te_evidence_is_preserved(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    assert any(
        "Smuggling type: te_te" in finding.evidence
        for finding in findings
    )


def test_no_findings_for_clean_request(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Host": "example.com",
            "Content-Length": "10",
        }
    )

    assert analyzer.analyze(
        analysis,
        "https://example.com",
    ) == []


def test_finding_description_is_indicator_based(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    finding = analyzer.analyze(
        analysis,
        "https://example.com",
    )[0]

    assert "parser" in finding.description.lower()
    assert "may" in finding.description.lower()


def test_finding_contains_remediation(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    finding = analyzer.analyze(
        analysis,
        "https://example.com",
    )[0]

    assert finding.remediation.strip()


def test_all_findings_have_required_core_fields(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    findings = analyzer.analyze(
        analysis,
        "https://example.com",
    )

    for finding in findings:
        assert finding.title
        assert finding.severity
        assert finding.confidence
        assert finding.target
        assert finding.description
        assert finding.evidence
        assert finding.remediation


def test_conflicting_framing_is_high_severity(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    finding = analyzer.analyze(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "High"


def test_duplicate_content_length_is_high_severity(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
        }
    )

    finding = analyzer.analyze(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "High"


def test_ambiguous_transfer_encoding_is_medium_severity(
    analyzer,
    smuggling_analyzer,
):
    analysis = smuggling_analyzer.analyze(
        {
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    finding = analyzer.analyze(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
