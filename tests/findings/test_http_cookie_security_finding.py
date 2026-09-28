from m_hunter.analyzers.http_cookie_security import (
    HttpCookieSecurityAnalyzer,
)
from m_hunter.findings.http_cookie_security import (
    HttpCookieSecurityFinding,
)


def test_secure_missing():
    finding = HttpCookieSecurityFinding.build(
        "SECURE_MISSING",
        "https://example.com",
        evidence="session",
    )

    assert finding.title == "Cookie Missing Secure Attribute"
    assert finding.severity == "Medium"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-614"


def test_httponly_missing():
    finding = HttpCookieSecurityFinding.build(
        "HTTPONLY_MISSING",
        "https://example.com",
        endpoint="/login",
    )

    assert finding.title == "Cookie Missing HttpOnly Attribute"
    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-1004"


def test_samesite_missing():
    finding = HttpCookieSecurityFinding.build(
        "SAMESITE_MISSING",
        "https://example.com",
    )

    assert finding.title == "Cookie Missing SameSite Attribute"
    assert finding.severity == "Medium"
    assert finding.cwe == "CWE-1275"


def test_samesite_none():
    finding = HttpCookieSecurityFinding.build(
        "SAMESITE_NONE",
        "https://example.com",
        evidence="session",
    )

    assert finding.title == "Cookie Uses SameSite=None"
    assert finding.severity == "Low"


def test_prefix_violation():
    finding = HttpCookieSecurityFinding.build(
        "PREFIX_VIOLATION",
        "https://example.com",
        evidence="__Host-session",
    )

    assert finding.title == "Cookie Prefix Security Requirement Violation"
    assert finding.severity == "Medium"


def test_long_lived_cookie():
    finding = HttpCookieSecurityFinding.build(
        "LONG_LIVED_COOKIE",
        "https://example.com",
        evidence="40000000",
    )

    assert finding.title == "Long-Lived Cookie"
    assert finding.severity == "Low"
    assert finding.cwe == "CWE-613"


def test_duplicate_cookie():
    finding = HttpCookieSecurityFinding.build(
        "DUPLICATE_COOKIE",
        "https://example.com",
        evidence="session",
    )

    assert finding.title == "Duplicate Cookie Name Detected"
    assert finding.severity == "Low"


def test_from_analysis():
    analysis = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        secure=False,
        httponly=False,
        samesite=None,
        domain=".example.com",
        path="/",
        max_age=40000000,
        duplicate_cookie=True,
    )

    findings = HttpCookieSecurityFinding.from_analysis(
        analysis,
        "https://example.com",
        endpoint="/login",
    )

    assert len(findings) == 7

    titles = {finding.title for finding in findings}

    assert "Cookie Missing Secure Attribute" in titles
    assert "Cookie Missing HttpOnly Attribute" in titles
    assert "Cookie Missing SameSite Attribute" in titles
    assert "Broad Cookie Domain Scope" in titles
    assert "Broad Cookie Path Scope" in titles
    assert "Long-Lived Cookie" in titles
    assert "Duplicate Cookie Name Detected" in titles
