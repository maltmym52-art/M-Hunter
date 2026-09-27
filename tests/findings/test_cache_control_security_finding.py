from m_hunter.findings.cache_control_security import CacheControlSecurityFinding


def test_public_sensitive_content():
    finding = CacheControlSecurityFinding.build(
        "PUBLIC_SENSITIVE_CONTENT",
        "https://example.com",
        endpoint="/account",
        evidence="public, max-age=3600",
    )

    assert finding.title == "Sensitive Content Is Publicly Cacheable"
    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.target == "https://example.com"
    assert finding.endpoint == "/account"
    assert finding.evidence == "public, max-age=3600"
    assert finding.cwe == "CWE-524"


def test_missing_vary():
    finding = CacheControlSecurityFinding.build(
        "MISSING_VARY",
        "https://example.com",
        endpoint="/profile",
    )

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-525"


def test_conflicting_directives():
    finding = CacheControlSecurityFinding.build(
        "CONFLICTING_CACHE_DIRECTIVES",
        "https://example.com",
        evidence="public, private",
    )

    assert finding.title == "Conflicting Cache-Control Directives"
    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-16"


def test_multiple_cache_control():
    finding = CacheControlSecurityFinding.build(
        "MULTIPLE_CACHE_CONTROL",
        "https://example.com",
        evidence="public, max-age=300",
    )

    assert finding.title == "Multiple Cache-Control Headers"
    assert finding.severity == "Low"
    assert finding.confidence == "Medium"


def test_from_analysis():
    analysis = type(
        "Analysis",
        (),
        {
            "indicators": [
                type(
                    "Indicator",
                    (),
                    {
                        "type": "PUBLIC_SENSITIVE_CONTENT",
                        "value": "public, max-age=3600",
                    },
                )(),
                type(
                    "Indicator",
                    (),
                    {
                        "type": "CACHEABLE_RESPONSE",
                        "value": "max-age=3600",
                    },
                ),
                type(
                    "Indicator",
                    (),
                    {
                        "type": "MISSING_VARY",
                        "value": "",
                    },
                ),
            ]
        },
    )()

    findings = CacheControlSecurityFinding.from_analysis(
        analysis,
        "https://example.com",
        endpoint="/account",
    )

    assert len(findings) == 2
    assert findings[0].title == "Sensitive Content Is Publicly Cacheable"
    assert findings[1].title == "Missing Vary Header on Sensitive Cacheable Response"


def test_from_analysis_ignores_non_security_indicators():
    analysis = type(
        "Analysis",
        (),
        {
            "indicators": [
                type(
                    "Indicator",
                    (),
                    {
                        "type": "CACHE_CONTROL_PRESENT",
                        "value": "public",
                    },
                ),
            ]
        },
    )()

    findings = CacheControlSecurityFinding.from_analysis(
        analysis,
        "https://example.com",
    )

    assert findings == []
