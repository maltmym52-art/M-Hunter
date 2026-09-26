from m_hunter.analyzers.subdomain_takeover import (
    SubdomainTakeoverAnalysis,
    SubdomainTakeoverIndicator,
    SubdomainTakeoverIndicatorType,
)
from m_hunter.analyzers.subdomain_takeover_finding import (
    SubdomainTakeoverFindingAnalyzer,
)


def indicator(
    indicator_type: SubdomainTakeoverIndicatorType,
    value: str = "test",
) -> SubdomainTakeoverIndicator:
    return SubdomainTakeoverIndicator(
        type=indicator_type,
        name=indicator_type.value,
        value=value,
    )


def analysis(*indicators: SubdomainTakeoverIndicator):
    return SubdomainTakeoverAnalysis(
        detected=bool(indicators),
        indicators=list(indicators),
    )


def test_empty_analysis():
    findings = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(),
        target="https://example.com",
    )

    assert findings == []


def test_cname_present_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.CNAME_PRESENT,
                "target.example.com",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-16"


def test_external_cname_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
                "example.github.io",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Medium"


def test_dangling_cname_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.CNAME_DANGLING,
                "old.github.io",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-350"


def test_nxdomain_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.NXDOMAIN,
                "NXDOMAIN",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_dns_error_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.DNS_ERROR,
                "SERVFAIL",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Low"


def test_unresolved_target_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
                "app.example.com",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_service_fingerprint_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
                "github.io",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"


def test_takeover_signature_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
                "no such app",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-350"


def test_host_not_found_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.HOST_NOT_FOUND,
                "host not found",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_resource_not_found_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.RESOURCE_NOT_FOUND,
                "resource not found",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_service_unavailable_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.SERVICE_UNAVAILABLE,
                "service unavailable",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Low"


def test_http_404_metadata():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.HTTP_404,
                "404",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "High"


def test_evidence_contains_value():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
                "no such app",
            )
        ),
        target="https://example.com",
    )[0]

    assert "no such app" in finding.evidence


def test_description_has_disclaimer():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
                "example.github.io",
            )
        ),
        target="https://example.com",
    )[0]

    assert "does not by itself prove" in finding.description


def test_remediation_is_present():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
                "example.github.io",
            )
        ),
        target="https://example.com",
    )[0]

    assert finding.remediation
    assert "DNS" in finding.remediation


def test_target_preserved():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
                "site not found",
            )
        ),
        target="https://target.example",
    )[0]

    assert finding.target == "https://target.example"


def test_endpoint_and_parameter_preserved():
    finding = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.HTTP_404,
                "404",
            )
        ),
        target="https://example.com",
        endpoint="/",
        parameter="host",
    )[0]

    assert finding.endpoint == "/"
    assert finding.parameter == "host"


def test_analyze_alias():
    analyzer = SubdomainTakeoverFindingAnalyzer()

    a = analysis(
        indicator(
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
            "github.io",
        )
    )

    result1 = analyzer.create_findings(
        a,
        target="https://example.com",
    )
    result2 = analyzer.analyze(
        a,
        target="https://example.com",
    )

    assert len(result1) == len(result2)
    assert result1[0].title == result2[0].title


def test_multiple_indicators_create_multiple_findings():
    findings = SubdomainTakeoverFindingAnalyzer().create_findings(
        analysis(
            indicator(
                SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
                "example.github.io",
            ),
            indicator(
                SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
                "github.io",
            ),
            indicator(
                SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
                "site not found",
            ),
        ),
        target="https://example.com",
    )

    assert len(findings) == 3


def test_all_indicator_types_have_metadata():
    analyzer = SubdomainTakeoverFindingAnalyzer()

    for indicator_type in SubdomainTakeoverIndicatorType:
        findings = analyzer.create_findings(
            analysis(
                indicator(
                    indicator_type,
                    indicator_type.value,
                )
            ),
            target="https://example.com",
        )

        assert len(findings) == 1
        assert findings[0].severity
        assert findings[0].confidence
        assert findings[0].cwe
        assert findings[0].owasp
