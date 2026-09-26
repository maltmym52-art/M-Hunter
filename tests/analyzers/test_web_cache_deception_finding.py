import pytest

from m_hunter.analyzers.web_cache_deception import (
    WebCacheDeceptionAnalysis,
    WebCacheDeceptionAnalyzer,
    WebCacheDeceptionIndicator,
    WebCacheDeceptionIndicatorType,
)
from m_hunter.analyzers.web_cache_deception_finding import (
    WebCacheDeceptionFindingAnalyzer,
)


def analyzer():
    return WebCacheDeceptionFindingAnalyzer()


def make_analysis(
    indicator_type,
    name="X-Cache",
    value="HIT",
):
    indicator = WebCacheDeceptionIndicator(
        type=indicator_type,
        evidence=f"{name}: {value}",
        name=name,
        value=value,
    )

    return WebCacheDeceptionAnalysis(
        detected=True,
        count=1,
        types=[indicator_type.value],
        names=[name],
        indicators=[indicator],
    )


def test_empty_analysis_returns_no_findings():
    analysis = WebCacheDeceptionAnalysis(
        detected=False,
        count=0,
        types=[],
        names=[],
        indicators=[],
    )

    assert analyzer().create_findings(
        analysis,
        "https://example.com",
    ) == []


def test_invalid_analysis_type():
    with pytest.raises(TypeError):
        analyzer().create_findings(
            "invalid",
            "https://example.com",
        )


def test_empty_target():
    with pytest.raises(ValueError):
        analyzer().create_findings(
            make_analysis(WebCacheDeceptionIndicatorType.CACHE_STATUS),
            "",
        )


@pytest.mark.parametrize(
    "indicator_type,expected_severity,expected_confidence",
    [
        (WebCacheDeceptionIndicatorType.CACHE_HEADER, "Info", "High"),
        (WebCacheDeceptionIndicatorType.CACHEABLE_RESPONSE, "Low", "High"),
        (WebCacheDeceptionIndicatorType.STATIC_EXTENSION, "Info", "High"),
        (WebCacheDeceptionIndicatorType.PATH_VARIATION, "Medium", "Medium"),
        (WebCacheDeceptionIndicatorType.SENSITIVE_CONTENT, "Medium", "Medium"),
        (WebCacheDeceptionIndicatorType.PRIVATE_CONTENT, "Info", "High"),
        (WebCacheDeceptionIndicatorType.CACHE_STATUS, "Info", "High"),
        (WebCacheDeceptionIndicatorType.AGE_HEADER, "Info", "High"),
        (WebCacheDeceptionIndicatorType.VARY_HEADER, "Info", "High"),
        (
            WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH,
            "Medium",
            "Medium",
        ),
    ],
)
def test_metadata(
    indicator_type,
    expected_severity,
    expected_confidence,
):
    finding = analyzer().create_findings(
        make_analysis(indicator_type),
        "https://example.com",
    )[0]

    assert finding.severity == expected_severity
    assert finding.confidence == expected_confidence


def test_cache_header_finding():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.CACHE_HEADER),
        "https://example.com",
    )[0]

    assert finding.title == "Cache-Control behavior detected"
    assert finding.cwe == "CWE-524"
    assert finding.owasp == "A05:2021"


def test_cacheable_response_finding():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.CACHEABLE_RESPONSE),
        "https://example.com",
    )[0]

    assert finding.title == "Potentially cacheable response detected"


def test_static_extension_finding():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.STATIC_EXTENSION),
        "https://example.com",
    )[0]

    assert finding.title == "Static-looking path detected"


def test_path_variation_finding():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.PATH_VARIATION),
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.title == "Potential cache deception path variation detected"


def test_sensitive_content_finding():
    finding = analyzer().create_findings(
        make_analysis(
            WebCacheDeceptionIndicatorType.SENSITIVE_CONTENT,
            "sensitive_markers",
            "account,profile",
        ),
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-524"


def test_private_content_finding():
    finding = analyzer().create_findings(
        make_analysis(
            WebCacheDeceptionIndicatorType.PRIVATE_CONTENT,
            "cache-control",
            "private, no-store",
        ),
        "https://example.com",
    )[0]

    assert finding.title == "Private cache directive detected"


def test_cache_status_finding():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert finding.title == "Cache status detected"


def test_age_finding():
    finding = analyzer().create_findings(
        make_analysis(
            WebCacheDeceptionIndicatorType.AGE_HEADER,
            "Age",
            "120",
        ),
        "https://example.com",
    )[0]

    assert finding.title == "Cached response age detected"


def test_vary_finding():
    finding = analyzer().create_findings(
        make_analysis(
            WebCacheDeceptionIndicatorType.VARY_HEADER,
            "Vary",
            "Accept-Encoding",
        ),
        "https://example.com",
    )[0]

    assert finding.title == "Vary header affects cache behavior"


def test_content_type_mismatch_finding():
    finding = analyzer().create_findings(
        make_analysis(
            WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH,
            "content-type",
            "text/html",
        ),
        "https://example.com",
    )[0]

    assert finding.title == (
        "Static-looking path returned mismatched content type"
    )
    assert finding.cwe == "CWE-436"


def test_all_supported_types_generate_findings():
    for indicator_type in WebCacheDeceptionIndicatorType:
        findings = analyzer().create_findings(
            make_analysis(indicator_type),
            "https://example.com",
        )

        assert len(findings) == 1


def test_multiple_indicators_generate_multiple_findings():
    analysis = WebCacheDeceptionAnalyzer().analyze(
        url="https://example.com/account.css",
        headers={
            "X-Cache": "HIT",
            "Cache-Control": "public, max-age=3600",
            "Age": "120",
            "Vary": "Accept-Encoding",
            "Content-Type": "text/html",
        },
        response_body="private account content",
    )

    findings = analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert len(findings) == analysis.count


def test_endpoint_and_parameter_are_preserved():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.CACHE_STATUS),
        "https://example.com",
        endpoint="/account",
        parameter="id",
    )[0]

    assert finding.endpoint == "/account"
    assert finding.parameter == "id"


def test_target_is_preserved():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.CACHE_STATUS),
        "https://target.example",
    )[0]

    assert finding.target == "https://target.example"


def test_evidence_contains_indicator_details():
    finding = analyzer().create_findings(
        make_analysis(
            WebCacheDeceptionIndicatorType.CACHE_STATUS,
            "X-Cache",
            "HIT",
        ),
        "https://example.com",
    )[0]

    assert "cache_status" in finding.evidence
    assert "X-Cache" in finding.evidence
    assert "HIT" in finding.evidence


def test_description_contains_disclaimer():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert "does not by itself prove" in finding.description
    assert "web cache deception" in finding.description


def test_remediation_present():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert finding.remediation
    assert "cache" in finding.remediation.lower()


def test_status_defaults_to_open():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert finding.status == "open"


def test_created_at_is_present():
    finding = analyzer().create_findings(
        make_analysis(WebCacheDeceptionIndicatorType.CACHE_STATUS),
        "https://example.com",
    )[0]

    assert finding.created_at is not None
